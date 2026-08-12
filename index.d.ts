import { TransformOptions } from 'bare-stream'
import Buffer from 'bare-buffer'
import constants from './lib/constants'
import Hash, { type HashAlgorithm } from './lib/hash'
import Hmac from './lib/hmac'
import { Cipheriv, Decipheriv, type CipherAlgorithm } from './lib/cipher'
import { randomBytes, randomFill, randomUUID } from './lib/random'
import pbkdf2 from './lib/pbkdf2'
import { generateKeyPair } from './lib/key'
import { sign, verify } from './lib/signature'
import { timingSafeEqual } from './lib/timing'
import web from './web'

/**
 * Create a new `Hash` instance with the specified `algorithm`. `algorithm` may be a string (for
 * example `'sha256'`, `'sha-256'`) or a numeric constant from `constants.hash`. The `options` are
 * forwarded to the `Transform` constructor from `bare-stream`
 * (<https://github.com/holepunchto/bare-stream>).
 * @param algorithm - The hash algorithm, as a string (for example `'sha256'`, `'sha-256'`) or a
 * numeric constant from `constants.hash`.
 * @param opts - Options forwarded to the `Transform` constructor from `bare-stream`.
 * @throws {UNKNOWN_HASH} `algorithm` is a string that does not name a supported hash algorithm.
 */
declare function createHash(algorithm: HashAlgorithm | number, opts?: TransformOptions<Hash>): Hash

/**
 * Create a new `Hmac` instance using `algorithm` and `key`. `key` may be a string or
 * `ArrayBufferView`. If `key` is a string, an `encoding` option (defaults to `'utf8'`) controls how
 * it is decoded. The `options` are also forwarded to `Transform`.
 * @param algorithm - The hash algorithm, as a string (for example `'sha256'`, `'sha-256'`) or a
 * numeric constant from `constants.hash`.
 * @param key - The HMAC key; a string is decoded using the `encoding` option (defaults to
 * `'utf8'`).
 * @param opts - Options forwarded to the `Transform` constructor from `bare-stream`.
 * @throws {UNKNOWN_HASH} `algorithm` is a string that does not name a supported hash algorithm.
 */
declare function createHmac(
  algorithm: HashAlgorithm | number,
  key: string | Buffer,
  opts?: TransformOptions<Hmac>
): Hmac

/**
 * Create a new `Cipheriv` instance using `algorithm`, `key`, and `iv` (initialization vector /
 * nonce). `key` and `iv` must match the algorithm's required lengths. For AEAD algorithms (for
 * example `AES128GCM`, `CHACHA20POLY1305`), the `options` may include an `authTagLength` (defaults
 * to `16`).
 * @param algorithm - The cipher algorithm, as a string or a numeric constant from
 * `constants.cipher`.
 * @param key - The encryption key; must match the algorithm's required length.
 * @param iv - The initialization vector / nonce; must match the algorithm's required length.
 * @param opts - Options forwarded to `Transform`; may include `encoding` (defaults to `'utf8'`)
 * and, for AEAD algorithms, `authTagLength` (defaults to `16`; must be `12`, `14`, or `16`).
 * @throws {UNKNOWN_CIPHER} `algorithm` is a string that does not name a supported cipher.
 * @throws {RangeError} `key` or `iv` does not match the algorithm's required length, or (AEAD)
 * `authTagLength` is not `12`, `14`, or `16`.
 */
declare function createCipheriv(
  algorithm: CipherAlgorithm | number,
  key: string | Buffer,
  iv: string | Buffer,
  opts?: TransformOptions<Cipheriv>
): Cipheriv

/**
 * Create a new `Decipheriv` instance using `algorithm`, `key`, and `iv`. Accepts the same `options`
 * as `createCipheriv`.
 * @param algorithm - The cipher algorithm, as a string or a numeric constant from
 * `constants.cipher`.
 * @param key - The decryption key; must match the algorithm's required length.
 * @param iv - The initialization vector / nonce; must match the algorithm's required length.
 * @param opts - Accepts the same options as `createCipheriv`.
 * @throws {UNKNOWN_CIPHER} `algorithm` is a string that does not name a supported cipher.
 * @throws {RangeError} `key` or `iv` does not match the algorithm's required length, or (AEAD)
 * `authTagLength` is not `12`, `14`, or `16`.
 */
declare function createDecipheriv(
  algorithm: CipherAlgorithm | number,
  key: string | Buffer,
  iv: string | Buffer,
  opts?: TransformOptions<Cipheriv>
): Decipheriv

/**
 * @param buffer - The buffer to fill.
 * @param offset - Offset at which filling starts (defaults to `0`).
 * @param size - Amount to fill (defaults to `buffer.byteLength - offset`).
 * @throws {RangeError} `offset`, `size`, or `offset + size` is out of range for `buffer`.
 */
declare function randomFillSync<B extends ArrayBuffer | ArrayBufferView>(
  buffer: B,
  offset?: number,
  size?: number
): B

/**
 * @param password - The password to derive the key from.
 * @param salt - The salt.
 * @param iterations - The number of PBKDF2 iterations; must be between `1` and `2^32 - 1`.
 * @param keylen - The length in bytes of the derived key.
 * @param digest - The hash algorithm, as a string or a numeric constant from `constants.hash`.
 * @throws {RangeError} `iterations` or `keylen` is out of range.
 * @throws {UNKNOWN_HASH} `digest` is a string that does not name a supported hash algorithm.
 */
declare function pbkdf2Sync(
  password: string | ArrayBufferView,
  salt: string | ArrayBufferView,
  iterations: number,
  keylen: number,
  digest: HashAlgorithm | number
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
  timingSafeEqual,
  web as webcrypto
}
