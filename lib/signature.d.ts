import Buffer from 'bare-buffer'
import { Key as CryptoKey } from './key'

export type SignatureAlgorithm = 'ed25519'

/**
 * Sign `data` using `key`. For Ed25519, `algorithm` is ignored — pass `null`. `data` may be an
 * `ArrayBuffer` or `ArrayBufferView`. Returns a `Buffer` containing the signature.
 * @param algorithm - Ignored for Ed25519 — pass `null`.
 * @param data - The data to sign.
 * @param key - The key to sign with.
 */
export function sign(algorithm: null, data: ArrayBuffer | ArrayBufferView, key: CryptoKey): Buffer

/**
 * Verify that `signature` is a valid signature over `data` for `key`. Returns `true` or `false`.
 * @param algorithm - Ignored for Ed25519 — pass `null`.
 * @param data - The signed data.
 * @param key - The key to verify against.
 * @param signature - The signature to check.
 */
export function verify(
  algorithm: null,
  data: ArrayBuffer | ArrayBufferView,
  key: CryptoKey,
  signature: Buffer
): boolean
