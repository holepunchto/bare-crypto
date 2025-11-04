import Buffer from 'bare-buffer'
import { Key as CryptoKey } from './key'

export type SignatureAlgorithm = 'ed25519'

export function sign(algorithm: null, data: ArrayBuffer | ArrayBufferView, key: CryptoKey): Buffer

export function verify(
  algorithm: null,
  data: ArrayBuffer | ArrayBufferView,
  key: CryptoKey,
  signature: Buffer
): boolean
