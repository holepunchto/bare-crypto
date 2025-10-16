import { TransformOptions } from 'bare-stream'
import Buffer from 'bare-buffer'
import constants from './lib/constants'
import Hash, { type HashAlgorithm } from './lib/hash'
import Hmac from './lib/hmac'
import { Cipheriv, Decipheriv, type CipherAlgorithm, type CipherAlgorithmName } from './lib/cipher'
import { randomBytes, randomFill, randomUUID } from './lib/random'
import pbkdf2 from './lib/pbkdf2'
import { generateKeyPair } from './lib/key'
import { sign, verify } from './lib/signature'
import web from './web'

declare function createHash(
  algorithm: HashAlgorithm | Lowercase<HashAlgorithm> | number,
  opts?: TransformOptions<Hash>
): Hash

declare function createHmac(
  algorithm: HashAlgorithm | Lowercase<HashAlgorithm> | number,
  key: string | Buffer,
  opts?: TransformOptions<Hmac>
): Hmac

declare function createCipheriv(
  algorithm: CipherAlgorithmName | CipherAlgorithm | Lowercase<CipherAlgorithm> | number,
  key: string | Buffer,
  iv: string | Buffer,
  opts?: TransformOptions<Cipheriv>
): Cipheriv

declare function createDecipheriv(
  algorithm: CipherAlgorithmName | CipherAlgorithm | Lowercase<CipherAlgorithm> | number,
  key: string | Buffer,
  iv: string | Buffer,
  opts?: TransformOptions<Cipheriv>
): Decipheriv

declare function randomFillSync<B extends ArrayBuffer | ArrayBufferView>(
  buffer: B,
  offset?: number,
  size?: number
): B

declare function pbkdf2Sync(
  password: string | ArrayBuffer | ArrayBufferView,
  salt: string | ArrayBuffer | ArrayBufferView,
  iterations: number,
  keylen: number,
  digest: HashAlgorithm | Lowercase<HashAlgorithm> | number
): Buffer

export {
  constants,
  Hash,
  createHash,
  Hmac,
  createHmac,
  Cipheriv,
  createCipheriv,
  Decipheriv,
  createDecipheriv,
  randomBytes,
  randomFill,
  randomUUID,
  randomFillSync,
  pbkdf2,
  pbkdf2Sync,
  generateKeyPair,
  sign,
  verify,
  web as webcrpyto
}
