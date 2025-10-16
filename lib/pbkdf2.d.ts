import Buffer from 'bare-buffer'
import { type HashAlgorithm } from './hash'

declare function pbkdf2(
  password: string | ArrayBuffer | ArrayBufferView,
  salt: string | ArrayBuffer | ArrayBufferView,
  iterations: number,
  keylen: number,
  digest: HashAlgorithm | Lowercase<HashAlgorithm> | number
): Buffer

declare function pbkdf2(
  password: string | ArrayBuffer | ArrayBufferView,
  salt: string | ArrayBuffer | ArrayBufferView,
  iterations: number,
  keylen: number,
  digest: HashAlgorithm | Lowercase<HashAlgorithm> | number,
  callback: (err: Error | null, buffer: Buffer) => void
): void

export = pbkdf2
