// Source file from duniter: Crypto-currency software to manage libre currency such as Ğ1
// Copyright (C) 2018  Cedric Moreau <cem.moreau@gmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

"use strict";

const co        = require('co');
const should    = require('should');
const _         = require('underscore');
const duniter     = require('../../index');
const bma       = require('../../app/modules/bma').BmaDependency.duniter.methods.bma;
const TestUser  = require('./tools/TestUser').TestUser
const commit    = require('./tools/commit');
const shutDownEngine  = require('./tools/shutDownEngine');

const MEMORY_MODE = true;
const commonConf = {
  ipv4: '127.0.0.1',
  currency: 'bb',
  httpLogs: true,
  forksize: 3,
  sigQty: 1
};

let s1, s2, s3, cat, toc, tic, cat2, toc2, tic2, cat3, toc3, tic3

const now = 1482000000;
const _100_PERCENT = 1.0;
const MAX_DISTANCE_1 = 1;
const MAX_DISTANCE_2 = 2;
const FROM_1_LINK_SENTRIES = 1;
const __OUTDISTANCED__ = true;
const __OK__ = false;

describe("WOTB module", function() {

  describe("Server 1", () => {

    let wotb;

    before(function() {

      return co(function *() {

        s1 = duniter(
          '/bb11',
          MEMORY_MODE,
          _.extend({
            port: '9337',
            pair: {
              pub: 'HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd',
              sec: '51w4fEShBk1jCMauWu4mLpmDVfHksKmWcygpxriqCEZizbtERA6de4STKRkQBpxmMUwsKXRjSzuQ8ECwmqN1u2DP'
            },
            rootoffset: 10,
            sigQty: 1, dt: 1, ud0: 120
          }, commonConf));

        s2 = duniter(
          '/bb41',
          MEMORY_MODE,
          _.extend({
            port: '9338',
            pair: {
              pub: 'HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd',
              sec: '51w4fEShBk1jCMauWu4mLpmDVfHksKmWcygpxriqCEZizbtERA6de4STKRkQBpxmMUwsKXRjSzuQ8ECwmqN1u2DP'
            },
            rootoffset: 10,
            sigQty: 1, dt: 1, ud0: 120,
            msValidity: 400 // Memberships expire after 400 second delay
          }, commonConf));

        s3 = duniter(
          '/bb11',
          MEMORY_MODE,
          _.extend({
            port: '9339',
            pair: {
              pub: 'DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV',
              sec: '468Q1XtTq7h84NorZdWBZFJrGkB18CbmbHr9tkp9snt5GiERP7ySs3wM8myLccbAAGejgMRC9rqnXuW3iAfZACm7'
            },
            rootoffset: 10,
            sigQty: 1, dt: 1, ud0: 120,
            sigValidity: 1400, sigPeriod: 0
          }, commonConf));

        cat = new TestUser('cat', { pub: 'HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd', sec: '51w4fEShBk1jCMauWu4mLpmDVfHksKmWcygpxriqCEZizbtERA6de4STKRkQBpxmMUwsKXRjSzuQ8ECwmqN1u2DP'}, { server: s1 });
        toc = new TestUser('toc', { pub: 'DKpQPUL4ckzXYdnDRvCRKAm1gNvSdmAXnTrJZ7LvM5Qo', sec: '64EYRvdPpTfLGGmaX5nijLXRqWXaVz8r1Z1GtaahXwVSJGQRn7tqkxLb288zwSYzELMEG5ZhXSBYSxsTsz1m9y8F'}, { server: s1 });
        tic = new TestUser('tic', { pub: 'DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV', sec: '468Q1XtTq7h84NorZdWBZFJrGkB18CbmbHr9tkp9snt5GiERP7ySs3wM8myLccbAAGejgMRC9rqnXuW3iAfZACm7'}, { server: s1 });

        cat2 = new TestUser('cat2', { pub: 'HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd', sec: '51w4fEShBk1jCMauWu4mLpmDVfHksKmWcygpxriqCEZizbtERA6de4STKRkQBpxmMUwsKXRjSzuQ8ECwmqN1u2DP'}, { server: s2 });
        toc2 = new TestUser('toc2', { pub: 'DKpQPUL4ckzXYdnDRvCRKAm1gNvSdmAXnTrJZ7LvM5Qo', sec: '64EYRvdPpTfLGGmaX5nijLXRqWXaVz8r1Z1GtaahXwVSJGQRn7tqkxLb288zwSYzELMEG5ZhXSBYSxsTsz1m9y8F'}, { server: s2 });
        tic2 = new TestUser('tic2', { pub: 'DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV', sec: '468Q1XtTq7h84NorZdWBZFJrGkB18CbmbHr9tkp9snt5GiERP7ySs3wM8myLccbAAGejgMRC9rqnXuW3iAfZACm7'}, { server: s2 });

        cat3 = new TestUser('cat3', { pub: 'HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd', sec: '51w4fEShBk1jCMauWu4mLpmDVfHksKmWcygpxriqCEZizbtERA6de4STKRkQBpxmMUwsKXRjSzuQ8ECwmqN1u2DP'}, { server: s3 });
        toc3 = new TestUser('toc3', { pub: 'DKpQPUL4ckzXYdnDRvCRKAm1gNvSdmAXnTrJZ7LvM5Qo', sec: '64EYRvdPpTfLGGmaX5nijLXRqWXaVz8r1Z1GtaahXwVSJGQRn7tqkxLb288zwSYzELMEG5ZhXSBYSxsTsz1m9y8F'}, { server: s3 });
        tic3 = new TestUser('tic3', { pub: 'DNann1Lh55eZMEDXeYt59bzHbA3NJR46DeQYCS2qQdLV', sec: '468Q1XtTq7h84NorZdWBZFJrGkB18CbmbHr9tkp9snt5GiERP7ySs3wM8myLccbAAGejgMRC9rqnXuW3iAfZACm7'}, { server: s3 });

        /**
         * cat <==> toc
         */
        yield s1.initWithDAL().then(bma).then((bmapi) => bmapi.openConnections());
        wotb = s1.dal.wotb;
        yield cat.createIdentity();
        yield toc.createIdentity();
        yield toc.cert(cat);
        yield cat.cert(toc);
        yield cat.join();
        yield toc.join();
        yield commit(s1)({
          time: now + 500
        });
        yield commit(s1)({
          time: now + 500
        });
      });
    });

    after(() => {
      return Promise.all([
        shutDownEngine(s1)
      ])
    })

    it('the wotb_id should be affected to new members', function() {
      return co(function *() {
        let icat = yield s1.dal.getWrittenIdtyByUID("cat");
        let itoc = yield s1.dal.getWrittenIdtyByUID("toc");
        icat.should.have.property('wotb_id').equal(0);
        itoc.should.have.property('wotb_id').equal(1);
        wotb.isEnabled(0).should.equal(true);
        wotb.isEnabled(1).should.equal(true);
        wotb.existsLink(0, 1).should.equal(true);
        wotb.existsLink(1, 0).should.equal(true);
        wotb.existsLink(1, 1).should.equal(false);
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(0, 0).should.equal(false);
        wotb.existsLink(0, 2).should.equal(false);
        wotb.isOutdistanced(0, FROM_1_LINK_SENTRIES, MAX_DISTANCE_1, _100_PERCENT).should.equal(__OK__);
      });
    });

    it('a newcomer should be affected an ID + links', function() {
      return co(function *() {
        /**
         * cat <==> toc --> tic
         */
        yield tic.createIdentity();
        yield toc.cert(tic);
        yield tic.join();
        yield commit(s1)();
        let itic = yield s1.dal.getWrittenIdtyByUID("tic");
        itic.should.have.property('wotb_id').equal(2);
        wotb.isEnabled(2).should.equal(true);
        wotb.existsLink(1, 2).should.equal(true);
        wotb.existsLink(0, 2).should.equal(false);
        wotb.isOutdistanced(0, FROM_1_LINK_SENTRIES, MAX_DISTANCE_1, _100_PERCENT).should.equal(__OK__);
        wotb.isOutdistanced(1, FROM_1_LINK_SENTRIES, MAX_DISTANCE_1, _100_PERCENT).should.equal(__OK__);
        // tic is outdistanced if k = 1! (cat can't reach him)
        wotb.isOutdistanced(2, FROM_1_LINK_SENTRIES, MAX_DISTANCE_1, _100_PERCENT).should.equal(__OUTDISTANCED__);
        // but reachable if k = 2
        wotb.isOutdistanced(2, FROM_1_LINK_SENTRIES, MAX_DISTANCE_2, _100_PERCENT).should.equal(__OK__);
      });
    });
  });

  describe("Server 2", () => {

    let wotb;

    before(function() {

      return co(function *() {
        /**
         * tic <==> cat <==> toc
         */
        yield s2.initWithDAL().then(bma).then((bmapi) => bmapi.openConnections());
        wotb = s2.dal.wotb;
        yield cat2.createIdentity();
        yield toc2.createIdentity();
        yield tic2.createIdentity();
        // toc2 <==> cat2
        yield toc2.cert(cat2);
        yield cat2.cert(toc2);
        // tic2 <==> cat2
        yield tic2.cert(cat2);
        yield cat2.cert(tic2);
        yield cat2.join();
        yield toc2.join();
        yield tic2.join();
        yield commit(s2)({
          time: now
        });
        // Should make MS expire for toc2
        yield commit(s2)({
          time: now + 500
        });
        yield commit(s2)({
          time: now + 600
        });
        yield cat2.join(); // Renew for not to be kicked!
        yield tic2.join(); // Renew for not to be kicked!
        yield commit(s2)({
          time: now + 800
        });
        yield commit(s2)({
          time: now + 800
        });
        // Members excluded
        yield commit(s2)({
          time: now + 800
        });
      });
    });

    after(() => {
      return Promise.all([
        shutDownEngine(s2)
      ])
    })

    it('a leaver should still have links but be disabled', function() {
      return co(function *() {
        wotb.isEnabled(0).should.equal(true);
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(false);
        // tic2 <==> cat2
        wotb.existsLink(0, 1).should.equal(true);
        wotb.existsLink(1, 0).should.equal(true);
        // toc2 <==> cat2
        wotb.existsLink(0, 2).should.equal(true);
        wotb.existsLink(2, 0).should.equal(true);
        // toc2 <==> tic2
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(2, 1).should.equal(false);
      });
    });

    it('a leaver who joins back should be enabled', function() {
      return co(function *() {
        yield toc2.join();
        yield commit(s2)();
        wotb.isEnabled(0).should.equal(true);
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(true);
        // tic2 <==> cat2
        wotb.existsLink(0, 1).should.equal(true);
        wotb.existsLink(1, 0).should.equal(true);
        // toc2 <==> cat2
        wotb.existsLink(0, 2).should.equal(true);
        wotb.existsLink(2, 0).should.equal(true);
        // toc2 <==> tic2
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(2, 1).should.equal(false);
      });
    });
  });

  describe("Server 3", () => {

    let wotb;

    before(function() {

      return co(function *() {
        yield s3.initWithDAL().then(bma).then((bmapi) => bmapi.openConnections());
        wotb = s3.dal.wotb;
        yield cat3.createIdentity();
        yield tic3.createIdentity();
        // cat <==> tic
        yield tic3.cert(cat3);
        yield cat3.cert(tic3);
        yield cat3.join();
        yield tic3.join();
      });
    });

    after(() => {
      return Promise.all([
        shutDownEngine(s3)
      ])
    })

    it('two first commits: the WoT is new and OK', function() {
      return co(function *() {
        yield commit(s3)({ time: now });
        yield commit(s3)({
          time: now + 1200
        });
        /**
         * cat <==> tic
         */
        wotb.isEnabled(0).should.equal(true);
        wotb.isEnabled(1).should.equal(true);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(true);
        wotb.existsLink(1, 0).should.equal(true);
        // tic3 <==> toc3
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(2, 1).should.equal(false);
      });
    });

    it('third & fourth commits: toc should have joined', function() {
      return co(function *() {
        yield commit(s3)({
          time: now + 2400
        });
        // MedianTime is now +500 for next certs
        yield toc3.createIdentity();
        yield toc3.join();
        yield tic3.cert(toc3);
        yield commit(s3)({
          time: now + 4000
        });
        // MedianTime is now +1000 for next certs
        /**
         * cat <==> tic --> toc
         */
        wotb.isEnabled(0).should.equal(true);
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(true);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(true);
        wotb.existsLink(1, 0).should.equal(true);
        // tic3 <==> toc3
        wotb.existsLink(1, 2).should.equal(true);
        wotb.existsLink(2, 1).should.equal(false);
      });
    });

    it('fifth commit: cat still here, but not its certs', function() {
      return co(function *() {
        yield toc3.cert(tic3);
        yield commit(s3)({
          time: now + 4000
        });
        /**
         *   cat     tic <==> toc
         */
        wotb.isEnabled(0).should.equal(true); // But marked as to kick: cannot issue new links
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(true);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(false);
        wotb.existsLink(1, 0).should.equal(false);
        // tic3 <==> toc3
        wotb.existsLink(1, 2).should.equal(true);
        wotb.existsLink(2, 1).should.equal(true);
      });
    });

    it('sixth commit: cat is gone with its certs', function() {
      return co(function *() {
        yield commit(s3)({
          time: now + 2500
        });
        /**
         *         tic <-- toc
         */
        wotb.isEnabled(0).should.equal(false);
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(true);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(false);
        wotb.existsLink(1, 0).should.equal(false);
        // tic3 --> toc3
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(2, 1).should.equal(true);
      });
    });

    it('seventh commit: toc is gone, but not its cert to tic', function() {
      return co(function *() {
        yield tic3.cert(cat3);
        yield cat3.join();
        yield commit(s3)({
          time: now + 5000
        });
        /**
         *  cat <-- tic <-- [toc]
         */
        wotb.isEnabled(0).should.equal(true);
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(false);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(false);
        wotb.existsLink(1, 0).should.equal(true);
        // tic3 --> toc3
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(2, 1).should.equal(true);
      });
    });

    it('revert seventh commit: toc is back, cat is gone', function() {
      return co(function *() {
        yield s3.revert();
        wotb.isEnabled(0).should.equal(false);
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(true);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(false);
        wotb.existsLink(1, 0).should.equal(false);
        // tic3 --> toc3
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(2, 1).should.equal(true);
      });
    });

    it('revert sixth commit: cat is back', function() {
      return co(function *() {
        yield s3.revert();
        wotb.isEnabled(0).should.equal(true); // But marked as to kick: cannot issue new links
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(true);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(false);
        wotb.existsLink(1, 0).should.equal(false);
        // tic3 <==> toc3
        wotb.existsLink(1, 2).should.equal(true);
        wotb.existsLink(2, 1).should.equal(true);
      });
    });

    it('revert fifth commit', function() {
      return co(function *() {
        yield s3.revert();
        wotb.isEnabled(0).should.equal(true);
        wotb.isEnabled(1).should.equal(true);
        wotb.isEnabled(2).should.equal(true);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(true);
        wotb.existsLink(1, 0).should.equal(true);
        // tic3 <==> toc3
        wotb.existsLink(1, 2).should.equal(true);
        wotb.existsLink(2, 1).should.equal(false);
      });
    });

    it('revert third & fourth commits', function() {
      return co(function *() {
        yield s3.revert();
        yield s3.revert();
        wotb.isEnabled(0).should.equal(true);
        wotb.isEnabled(1).should.equal(true);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(true);
        wotb.existsLink(1, 0).should.equal(true);
        // tic3 <==> toc3
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(2, 1).should.equal(false);
      });
    });

    it('revert first & second commits', function() {
      return co(function *() {
        yield s3.revert();
        yield s3.revert();
        wotb.isEnabled(0).should.equal(false);
        wotb.isEnabled(1).should.equal(false);
        wotb.isEnabled(2).should.equal(false);
        // cat3 <==> tic3
        wotb.existsLink(0, 1).should.equal(false);
        wotb.existsLink(1, 0).should.equal(false);
        // tic3 <==> toc3
        wotb.existsLink(1, 2).should.equal(false);
        wotb.existsLink(2, 1).should.equal(false);
      });
    });
  });
});
