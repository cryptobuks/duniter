var async      = require('async');
var util       = require('util');
var logger     = require('./app/lib/logger')('regserver');
var PeerServer = require('./peerserver');

function RegistryServer (dbConf, overrideConf) {

  PeerServer.call(this, dbConf, overrideConf);

  var that = this;
  var queue = [];

  this._read = function (size) {
  };

  this._write = function (obj, enc, done) {
    async.waterfall([
      async.apply(that.initServer.bind(that)),
      function (next){
        if (obj.pubkey) {
          // Pubkey
          async.waterfall([
            function (next){
              var PublicKey = that.conn.model('PublicKey');
              var pubkey = new PublicKey({ raw: obj.pubkey });
              pubkey.construct(function (err) {
                next(err, pubkey);
              });
            },
            function (pubkey, next){
              that.PublicKeyService.submitPubkey(pubkey, next);
            },
            function (pubkey, next){
              that.emit('pubkey', pubkey);
              next();
            },
          ], next);
        } else if (obj.amendment) {
          // Vote
          async.waterfall([
            function (next){
              that.VoteService.submit(obj, next);
            },
            function (am, vote, next){
              that.emit('vote', vote);
              next();
            },
          ], next);
        } else if (obj.recipient) {
          // Transaction
          async.waterfall([
            function (next){
              that.TransactionsService.processTx(obj, next);
            },
            function (tx, next){
              that.emit('transaction', tx);
              next();
            },
          ], next);
        } else if (obj.endpoints) {
          // Peer
          async.waterfall([
            function (next){
              that.PeeringService.submit(obj, obj.keyID, next);
            },
            function (peer, next){
              that.emit('peer', peer);
              next();
            },
          ], next);
        } else if (obj.forward) {
          // Forward
          async.waterfall([
            function (next){
              that.PeeringService.submitForward(obj, next);
            },
            function (fwd, next){
              that.emit('forward', fwd);
              next();
            },
          ], next);
        } else if (obj.status) {
          // Status
          async.waterfall([
            function (next){
              that.PeeringService.submitStatus(obj, next);
            },
            function (status, peer, wasStatus, next){
              that.emit('status', status);
              next();
            },
          ], next);
        } else if (obj.requiredTrusts) {
          // Wallet
          async.waterfall([
            function (next){
              that.WalletService.submit(obj, next);
            },
            function (wallet, next){
              that.emit('wallet', wallet);
              next();
            },
          ], next);
        } else if (obj.registry && obj.registry == "MEMBERSHIP") {
          // Membership
          async.waterfall([
            function (next){
              that.SyncService.submit(obj, next);
            },
            function (ms, next){
              that.emit('membership', ms);
              next();
            },
          ], next);
        } else if (obj.registry && obj.registry == "VOTING") {
          // Voting
          async.waterfall([
            function (next){
              that.SyncService.submitVoting(obj, next);
            },
            function (vt, next){
              that.emit('voting', vt);
              next();
            },
          ], next);
        } else if (obj.algorithm) {
          // CommunityFlow
          async.waterfall([
            function (next){
              that.SyncService.submitCF(obj, next);
            },
            function (cf, next){
              that.emit('communityflow', cf);
              next();
            },
          ], next);
        } else {
          var err = 'Unknown document type';
          that.emit('error', Error(err));
          next(err);
        }
      },
    ], function (err) {
      if (err){
        logger.debug(err);
      }
      done();
    });
  };

  this._initServices = function(conn, done) {
    async.waterfall([
      function (next){
        that.checkConfig(next);
      },
      function (next){
        that.KeyService          = require('./app/service/KeyService').get(conn);
        that.ContractService     = require('./app/service/ContractService').get(conn, that.conf);
        that.PublicKeyService    = require('./app/service/PublicKeyService').get(conn, that.conf, that.KeyService);
        that.PeeringService      = require('./app/service/PeeringService').get(conn, that.conf, that.PublicKeyService, that.ParametersService);
        next();
      },
      function (next){
        that.createSignFunction(that.conf, next);
      },
      function (next){
        that.SyncService         = require('./app/service/SyncService').get(conn, that.conf, that.sign, that.ContractService, that.PeeringService, that.alertDaemon, that.daemonJudgesTimeForVote);
        that.StrategyService     = require('./app/service/StrategyService').get(conn, that.conf, that.ContractService, that.SyncService);
        that.VoteService         = require('./app/service/VoteService').get(conn, that.StrategyService);
        that.TransactionsService = require('./app/service/TransactionsService').get(conn, that.MerkleService, that.PeeringService);
        that.WalletService       = require('./app/service/WalletService').get(conn);
        async.parallel({
          contract: function(callback){
            that.ContractService.load(callback);
          },
          peering: function(callback){
            that.PeeringService.load(callback);
          },
        }, function (err) {
          next(err);
        });
      },
    ], done);
  };

  this.checkConfig = function (done) {
    async.waterfall([
      function (next){
        that.checkPeeringConf(that.conf, next);
      },
      function (next){
        that.checkDaemonConf(that.conf, next);
      }
    ], done);
  };

  this.initServer = function (done) {
    if (!that.peerInited) {
      that.peerInited = true;
      async.waterfall([
        function (next){
          that.connect(next);
        },
        function (next){
          that.initServices(next);
        },
        function (next){
          that.initPeer(that.conn, that.conf, next);
        },
        function (next){
          that.initRegistry(that.conn, that.conf, next);
        },
      ], function (err) {
        done(err);
      });
    } else {
      done();
    }
  };

  this.initRegistry = function (conn, conf, done) {
    async.waterfall([
      function (next){
        // Init Daemon
        that.daemon = require('./app/lib/daemon')(that.conn, that.PeeringService, that.ContractService);
        that.daemon.init(conf, that.PeeringService.cert.fingerprint);
        // Init first amendment
        conn.model('Amendment').current(function (err, am) {
          next(null, am);
        });
      },
      function (currentAM, next) {
        var nextAMNumber = currentAM && currentAM.number + 1 || 0;
        // Create NEXT AM proposal if not existing
        conn.model('Amendment').getTheOneToBeVoted(nextAMNumber, conf.sync.Algorithm, function (err, am) {
          if (err || !am) {
            that.SyncService.createNext(currentAM, next);
            return;
          }
          next();
        });
      },
      function (next){
        // Start autonomous contract daemon
        that.daemon.start();
        next();
      },
    ], done);
  };

  this.alertDaemon = function (delay) {
    that.daemon.nextIn(delay);
  };

  this.daemonJudgesTimeForVote = function (amNext) {
    return that.daemon.judges.timeForVote(amNext);
  };

  this.checkDaemonConf = function (conf, done) {
    var errors = [];
    if (conf.sync.AMDaemon == "ON") {
      if (!conf.sync.AMStart) {
        errors.push('Autovoting enabled but starting date not given');
      }
      if (!conf.sync.AMFreq) {
        errors.push('Autovoting enabled but amendment frequency not given');
      }
      if (!conf.sync.UDFreq) {
        errors.push('Autovoting enabled but dividend frequency not given');
      }
      if (conf.sync.UDFreq % conf.sync.AMFreq != 0) {
        errors.push('UD frequency must be a multiple of Amendment frequency');
      }
      if (!conf.sync.UD0) {
        errors.push('Autovoting enabled but initial dividend not given');
      }
      if (!conf.sync.UDPercent) {
        errors.push('Autovoting enabled but %dividend not given');
      }
      if (!conf.sync.Consensus) {
        errors.push('Autovoting enabled but %required votes not given');
      }
      if (!conf.sync.MSExpires) {
        errors.push('Autovoting enabled but membership validity not given');
      }
      if (!conf.sync.VTExpires) {
        errors.push('Autovoting enabled but voting validity not given');
      }
    }
    done(errors[0]);
  };

  this._listenBMA = function (app) {
    this.listenPKS(app);
    this.listenHDC(app);
    this.listenNET(app);
    this.listenREG(app);
  };

  this.listenREG = function (app) {
    var reg = require('./app/controllers/registry')(that, that.conf);
    app.get(    '/registry/parameters',                             reg.parameters);
    app.post(   '/registry/community/members',                      reg.membershipPost);
    app.get(    '/registry/community/members/:fpr/current',         reg.membershipCurrent);
    app.get(    '/registry/community/members/:fpr/history',         reg.membershipHistory);
    app.post(   '/registry/community/voters',                       reg.votingPost);
    app.get(    '/registry/community/voters/:fpr/current',          reg.votingCurrent);
    app.get(    '/registry/community/voters/:fpr/history',          reg.votingHistory);
    app.get(    '/registry/amendment',                              reg.amendmentCurrent);
    app.get(    '/registry/amendment/:am_number',                   reg.amendmentNext);
    app.get(    '/registry/amendment/:am_number/:algo/members/in',  reg.membersIn);
    app.get(    '/registry/amendment/:am_number/:algo/members/out', reg.membersOut);
    app.get(    '/registry/amendment/:am_number/:algo/voters/in',   reg.votersIn);
    app.get(    '/registry/amendment/:am_number/:algo/voters/out',  reg.votersOut);
    app.get(    '/registry/amendment/:am_number/:algo/flow',        reg.askFlow);
    app.get(    '/registry/amendment/:am_number/:algo/vote',        reg.askVote);
  }
}

util.inherits(RegistryServer, PeerServer);

module.exports = RegistryServer;
