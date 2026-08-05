import Buffer from 'bare-buffer'
import { type SignatureAlgorithm } from './signature'

declare class CryptoKey {
  readonly type: 'public' | 'private' | 'secret'

  readonly destroyed: boolean

  export(): Buffer

  destroy(): void

  [Symbol.dispose](): void
}

/**
 * Generate a new asymmetric key pair. `type` may be a string (for example `'ed25519'`) or a numeric constant from `constants.keyType`.
 * @param type - The key type, as a string (for example `'ed25519'`) or a numeric constant from `constants.keyType`.
 * @throws {UNKNOWN_KEY_TYPE} `type` is a string that does not name a supported key type.
 */
declare function generateKeyPair(type: SignatureAlgorithm | Lowercase<SignatureAlgorithm>): {
  publicKey: CryptoKey
  privateKey: CryptoKey
}

export { CryptoKey as Key, generateKeyPair }
