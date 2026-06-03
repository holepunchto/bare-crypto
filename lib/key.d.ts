import Buffer from 'bare-buffer'
import { type SignatureAlgorithm } from './signature'

declare class CryptoKey {
  readonly type: 'public' | 'private' | 'secret'

  readonly destroyed: boolean

  export(): Buffer

  destroy(): void

  [Symbol.dispose](): void
}

declare function generateKeyPair(type: SignatureAlgorithm | Lowercase<SignatureAlgorithm>): {
  publicKey: CryptoKey
  privateKey: CryptoKey
}

export { CryptoKey as Key, generateKeyPair }
