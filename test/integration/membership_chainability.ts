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

const toolbox = require('./tools/toolbox')
import {CommonConstants} from "../../app/lib/common-libs/constants"

describe("Membership chainability", function() {

  describe("before July 2017", () => {

    const now = 1482220000
    let s1:any, cat:any

    const conf = {
      msWindow: 20, // Determies msPeriod
      nbCores: 1,
      msValidity: 10000,
      udTime0: now,
      udReevalTime0: now,
      sigQty: 1,
      medianTimeBlocks: 1 // The medianTime always equals previous block's medianTime
    }

    before(async () => {
      const res1 = await toolbox.simpleNodeWith2Users(conf)
      s1 = res1.s1
      cat = res1.cat
      const nowVersion = CommonConstants.BLOCK_NEW_GENERATED_VERSION
      CommonConstants.BLOCK_NEW_GENERATED_VERSION = 10
      await s1.commit({ time: now })
      await s1.commit({ time: now })
      await s1.commit({ time: now, actives: [
        'HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd:oHIjaiAVcmyac13oBirFulXbYqScAAwZIhvLjocqS5oMfF0eLQcvi8S0AIfkaBqhn2CVqxRZgcFBQaYVwLgwCg==:1-07A550E7DC27710610A290E55AA778CE6FA9F776AB777ABF4DB660D7BF0C4117:0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855:cat'
      ]})
      CommonConstants.BLOCK_NEW_GENERATED_VERSION = nowVersion
    })

    before(() => {
      CommonConstants.BLOCK_NEW_GENERATED_VERSION = 11
    })

    it('current should be the 2nd', () => s1.expect('/blockchain/current', (res:any) => {
      res.should.have.property('number').equal(2)
      res.should.have.property('actives').length(1)
    }))

    after(() => {
      CommonConstants.BLOCK_NEW_GENERATED_VERSION = 10
    })

    after(async () => {
      await s1.closeCluster()
    })
  })

  describe("after July 2017", () => {

    const now = 1498860000
    let s1:any, cat:any

    const conf = {
      msWindow: 20,
      nbCores: 1,
      msValidity: 10000,
      udTime0: now,
      udReevalTime0: now,
      sigQty: 1,
      medianTimeBlocks: 1 // The medianTime always equals previous block's medianTime
    }

    before(async () => {
      const res1 = await toolbox.simpleNodeWith2Users(conf)
      s1 = res1.s1
      cat = res1.cat
      await s1.commit({ time: now })
      await s1.commit({ time: now + 20 })
    })

    it('should refuse a block with a too early membership in it', async () => {
      await s1.commitWaitError({
        time: now + 20,
        actives: ['HgTTJLAQ5sqfknMq7yLPZbehtuLSsKj9CxWN7k8QvYJd:d+2p9+qks9XvYZmLMmmwDkyheUuecXaaRtUk2gFi+RDqRG2MOOFzjwBEC8IZzK7gdrzOwPZAMormHZnijPyiCA==:1-B9A509E0CF1B475012846D180EDD98DDC4D10C3B90EA14B1F28ACBA8FEF1FC88:0-E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855:cat']
      }, 'ruleMembershipPeriod')
    })

    it('should not be able to renew immediately', async () => {
      await cat.join()
      await s1.commit({ time: now + 20 })
      await s1.expect('/blockchain/block/2', (res:any) => {
        res.should.have.property('number').equal(2)
        res.should.have.property('joiners').length(0)
      })
    })

    it('should be able to renew after 20 sec', async () => {
      await s1.commit({ time: now + 20 })
      await s1.expect('/blockchain/block/3', (res:any) => {
        res.should.have.property('number').equal(3)
        res.should.have.property('actives').length(1)
      })
    })

    it('current should be the 4th', () => s1.expect('/blockchain/current', (res:any) => {
      res.should.have.property('number').equal(3)
      res.should.have.property('actives').length(1)
    }))

    after(async () => {
      await s1.closeCluster()
    })
  })
})
