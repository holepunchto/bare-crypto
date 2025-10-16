import { type SignatureAlgorithm } from './signature'

declare class CryptoKey {}

declare class CryptoEd25519Key extends CryptoKey {
  readonly asymmetricKeyType: 'ed25519'
}

declare class CryptoEd25519PublicKey extends CryptoEd25519Key {
  readonly type: 'public'
}

declare class CryptoEd25519PrivateKey extends CryptoEd25519Key {
  readonly type: 'private'
}

declare function generateKeyPair(type: SignatureAlgorithm | Lowercase<SignatureAlgorithm>): {
  publicKey: CryptoKey
  privateKey: CryptoKey
}

export {
  CryptoKey as Key,
  CryptoEd25519PublicKey as Ed25519PublicKey,
  CryptoEd25519PrivateKey as Ed25519PrivateKey,
  generateKeyPair
}
