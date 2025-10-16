import { Transform, TransformOptions } from 'bare-stream'
import Buffer, { BufferEncoding } from 'bare-buffer'

type HashAlgorithm = 'MD5' | 'SHA1' | 'SHA256' | 'SHA512' | 'BLAKE2B256'

declare class CryptoHash extends Transform {
  constructor(
    algorithm: HashAlgorithm | Lowercase<HashAlgorithm> | number,
    opts?: TransformOptions<CryptoHash>
  )

  update(data: string, encoding?: BufferEncoding): this
  update(data: Buffer, encoding?: 'buffer'): this

  digest(encoding: BufferEncoding): string
  digest(): Buffer
}

declare namespace CryptoHash {
  export { type HashAlgorithm }
}

export = CryptoHash
