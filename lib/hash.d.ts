import { Transform, TransformOptions } from 'bare-stream'
import Buffer, { BufferEncoding } from 'bare-buffer'

type HashAlgorithm = 'md5' | 'sha-1' | 'sha-256' | 'sha-512' | 'blake2b-256' | 'ripemd-160'

declare class CryptoHash extends Transform {
  constructor(algorithm: HashAlgorithm | number, opts?: TransformOptions<CryptoHash>)

  update(data: string, encoding?: BufferEncoding): this
  update(data: Buffer, encoding?: 'buffer'): this

  digest(encoding: BufferEncoding): string
  digest(): Buffer
}

declare namespace CryptoHash {
  export { type HashAlgorithm }
}

export = CryptoHash
