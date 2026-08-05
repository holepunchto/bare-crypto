import { type HashAlgorithm } from './hash'
import { type SignatureAlgorithm } from './signature'
import { type CipherAlgorithm } from './cipher'

/** The supported algorithm constants: `hash` (hash algorithms), `cipher` (symmetric cipher algorithms), `signature` (signature algorithms), and `keyType` (asymmetric key types). */
declare const constants: {
  hash: Record<HashAlgorithm, number>
  signature: Record<SignatureAlgorithm, number>
  cipher: Record<CipherAlgorithm, number>
  keyType: Record<SignatureAlgorithm, number>
}

export = constants
