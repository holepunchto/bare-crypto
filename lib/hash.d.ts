import { Transform, TransformOptions } from 'bare-stream'
import Buffer, { BufferEncoding } from 'bare-buffer'

type HashAlgorithm = 'md5' | 'sha1' | 'sha256' | 'sha512' | 'blake2b256'

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
