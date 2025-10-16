import { type HashAlgorithm } from './hash'
import { type SignatureAlgorithm } from './signature'
import { type CipherAlgorithm } from './cipher'

declare const constants: {
  hash: Record<HashAlgorithm, number>
  signature: Record<SignatureAlgorithm, number>
  cipher: Record<CipherAlgorithm, number>
  keyType: Record<SignatureAlgorithm, number>
}

export = constants
