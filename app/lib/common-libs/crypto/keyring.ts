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

import {Base58decode, Base58encode} from "./base58"
import {decodeBase64, decodeUTF8, encodeBase64} from "./nacl-util"

const nacl        = require('tweetnacl');
const seedrandom  = require('seedrandom');
const sodium      = require('sodium');

const crypto_sign_BYTES = 64;

export class Key {

  constructor(readonly pub:string, readonly sec:string) {
  }

  /*****************************
  *
  *      GENERAL CRYPTO
  *
  *****************************/

  get publicKey() {
    return this.pub
  }

  get secretKey() {
    return this.sec
  }

  private rawSec() {
    return Base58decode(this.secretKey)
  }

  private rawPub() {
    return Base58decode(this.publicKey)
  }

  json() {
    return {
      pub: this.publicKey,
      sec: this.secretKey
    }
  }

  sign(msg:string) {
    return Promise.resolve(this.signSync(msg))
  }

  signSync(msg:string) {
    const key = new sodium.Key.Sign(encodeBase64(this.rawPub()), encodeBase64(this.rawSec()), 'base64')
    const signer = new sodium.Sign(key)
    const signedMsg = signer.sign(msg, 'utf8').sign;
    const sig = new Uint8Array(crypto_sign_BYTES);
    for (let i = 0; i < sig.length; i++) {
      sig[i] = signedMsg[i];
    }
    return encodeBase64(sig)
  };
}

export function randomKey() {
  const byteseed = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    byteseed[i] = Math.floor(seedrandom()() *  255) + 1
  }
  const keypair = nacl.sign.keyPair.fromSeed(byteseed)
  return new Key(
    Base58encode(new Buffer(keypair.publicKey)),
    Base58encode(new Buffer(keypair.secretKey))
  )
}

export function KeyGen(pub:string, sec:string) {
  return new Key(pub, sec)
}

/**
 * Verify a signature against data & public key.
 * Return true of false as callback argument.
 */
export function verify(rawMsg:string, rawSig:string, rawPub:string) {
  const msg = decodeUTF8(rawMsg);
  const sig = decodeBase64(rawSig);
  const pub = Base58decode(rawPub);
  // Call to verification lib...
  return sig.length === 64 && sodium.Sign.verifyDetached({
    sign: sig,
    publicKey: pub
  }, msg);
}
