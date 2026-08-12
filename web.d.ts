import Buffer from 'bare-buffer'

import { randomUUID, randomFillSync } from '.'
import CryptoKey from './lib/web/crypto-key'

type HashArg = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512' | { name: HashArg }

interface JWK {
  alg?: string
  crv?: string
  d?: string
  ext?: boolean
  k?: string
  key_ops?: string[]
  kty?: string
  use?: string
  x?: string
}

interface SubtleCrypto {
  generateKey(
    algorithm: { name: 'HMAC'; hash: HashArg; length?: number },
    extractable: boolean,
    usages: ('sign' | 'verify')[]
  ): Promise<CryptoKey<'HMAC'>>
  generateKey(
    algorithm: { name: 'Ed25519' },
    extractable: boolean,
    usages: ('sign' | 'verify')[]
  ): Promise<{ publicKey: CryptoKey<'Ed25519'>; privateKey: CryptoKey<'Ed25519'> }>

  importKey(
    format: 'raw',
    keyData: Buffer | ArrayBuffer,
    algorithm: { name: 'HMAC'; hash: HashArg },
    extractable: boolean,
    usages: ('sign' | 'verify')[]
  ): Promise<CryptoKey<'HMAC'>>
  importKey(
    format: 'jwk',
    keyData: JWK,
    algorithm: { name: 'HMAC'; hash: HashArg },
    extractable: boolean,
    usages: ('sign' | 'verify')[]
  ): Promise<CryptoKey<'HMAC'>>

  importKey(
    format: 'raw' | 'spki',
    keyData: Buffer | ArrayBuffer,
    algorithm: { name: 'Ed25519' } | 'Ed25519',
    extractable: boolean,
    usages: 'verify'[]
  ): Promise<CryptoKey<'Ed25519'>>
  importKey(
    format: 'pkcs8',
    keyData: Buffer | ArrayBuffer,
    algorithm: { name: 'Ed25519' } | 'Ed25519',
    extractable: boolean,
    usages: 'sign'[]
  ): Promise<CryptoKey<'Ed25519'>>
  importKey(
    format: 'jwk',
    keyData: JWK,
    algorithm: { name: 'Ed25519' } | 'Ed25519',
    extractable: boolean,
    usages: ('sign' | 'verify')[]
  ): Promise<CryptoKey<'Ed25519'>>

  importKey(
    format: 'raw',
    keyData: Buffer | ArrayBuffer,
    algorithm: { name: 'PBKDF2' } | 'PBKDF2',
    extractable: false,
    usages: ('deriveKey' | 'deriveBits')[]
  ): Promise<CryptoKey<'PBKDF2'>>

  exportKey(format: 'raw' | 'spki' | 'pkcs8', key: CryptoKey): Promise<ArrayBuffer>
  exportKey(format: 'jwk', key: CryptoKey): Promise<JWK>

  /**
   * Sign `data` using `key`. For Ed25519, `algorithm` is ignored — pass `null`. `data` may be an
   * `ArrayBuffer` or `ArrayBufferView`. Returns a `Buffer` containing the signature.
   * @param algorithm - Ignored for Ed25519 — pass `null`.
   * @param data - The data to sign.
   * @param key - The key to sign with.
   */
  sign(algorithm: 'HMAC' | 'Ed25519', key: CryptoKey, data: Buffer): Promise<ArrayBuffer>

  /**
   * Verify that `signature` is a valid signature over `data` for `key`. Returns `true` or `false`.
   * @param algorithm - Ignored for Ed25519 — pass `null`.
   * @param data - The signed data.
   * @param key - The key to verify against.
   * @param signature - The signature to check.
   */
  verify(
    algorithm: 'HMAC' | 'Ed25519',
    key: CryptoKey,
    signature: ArrayBuffer,
    data: Buffer
  ): Promise<boolean>

  deriveBits(
    algorithm: { name: 'PBKDF2'; hash: HashArg; salt: Buffer; iterations: number } | 'PBKDF2',
    key: CryptoKey,
    length: number
  ): Promise<ArrayBuffer>

  deriveKey(
    algorithm: { name: 'PBKDF2'; hash: HashArg; salt: Buffer; iterations: number },
    baseKey: CryptoKey,
    derivedKeyType: { name: 'HMAC'; hash: HashArg },
    extractable: boolean,
    usages: ('sign' | 'verify')[]
  ): Promise<CryptoKey>

  digest(algorithm: HashArg, data: Buffer): Promise<ArrayBuffer>
}

declare const subtle: SubtleCrypto

interface Crypto {
  readonly subtle: SubtleCrypto

  /**
   * Fill `array` with cryptographically secure random bytes and return the same `array`. Equivalent
   * to `randomFillSync(array)`.
   * @param array - The buffer to fill with cryptographically secure random bytes.
   */
  getRandomValues<B extends ArrayBuffer | ArrayBufferView>(array: B): B

  /** Generate a random RFC 4122 version-4 UUID string. */
  randomUUID(): string
}

export {
  CryptoKey,
  randomFillSync as getRandomValues,
  randomUUID,
  SubtleCrypto,
  subtle,
  Crypto,
  type JWK,
  type HashArg
}
