import Buffer from 'bare-buffer'
import { type HashAlgorithm } from './hash'

/**
 * Derive a key from `password` and `salt` using the specified `digest` algorithm and number of `iterations`. Returns a `keylen`-byte `Buffer`. `password` and `salt` may be strings or `ArrayBufferView`s.
 * @param password - The password to derive the key from.
 * @param salt - The salt.
 * @param iterations - The number of PBKDF2 iterations; must be between `1` and `2^32 - 1`.
 * @param keylen - The length in bytes of the derived key.
 * @param digest - The hash algorithm, as a string or a numeric constant from `constants.hash`.
 * @throws {RangeError} `iterations` or `keylen` is out of range.
 * @throws {UNKNOWN_HASH} `digest` is a string that does not name a supported hash algorithm.
 */
declare function pbkdf2(
  password: string | ArrayBuffer | ArrayBufferView,
  salt: string | ArrayBuffer | ArrayBufferView,
  iterations: number,
  keylen: number,
  digest: HashAlgorithm | number
): Buffer

declare function pbkdf2(
  password: string | ArrayBuffer | ArrayBufferView,
  salt: string | ArrayBuffer | ArrayBufferView,
  iterations: number,
  keylen: number,
  digest: HashAlgorithm | number,
  callback: (err: Error | null, buffer: Buffer) => void
): void

export = pbkdf2
