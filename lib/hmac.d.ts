import { Transform, TransformOptions } from 'bare-stream'
import Buffer, { BufferEncoding } from 'bare-buffer'
import { type HashAlgorithm } from './hash'

declare class CryptoHmac extends Transform {
  constructor(
    algorithm: HashAlgorithm | Lowercase<HashAlgorithm> | number,
    key: string | Buffer,
    opts?: TransformOptions<CryptoHmac>
  )

  update(data: string, encoding?: BufferEncoding): this
  update(data: Buffer, encoding?: 'buffer'): this

  digest(encoding: BufferEncoding): string
  digest(): Buffer
}

export = CryptoHmac
