import { Transform, TransformOptions } from 'bare-stream'
import Buffer, { BufferEncoding } from 'bare-buffer'

export type CipherAlgorithm =
  | 'aes-128-cbc'
  | 'aes-128-ctr'
  | 'aes-128-ecb'
  | 'aes-128-gcm'
  | 'aes-128-ofb'
  | 'aes-256-cbc'
  | 'aes-256-ctr'
  | 'aes-256-ecb'
  | 'aes-256-gcm'
  | 'aes-256-ofb'
  | 'chacha20-poly1305'
  | 'xchacha20-poly1305'

export class Cipheriv extends Transform {
  constructor(
    algorithm: CipherAlgorithm | number,
    key: string | Buffer,
    iv: string | Buffer,
    opts?: TransformOptions<Cipheriv>
  )

  update(
    data: string | Buffer,
    inputEncoding?: BufferEncoding,
    outputEncoding?: BufferEncoding
  ): string | Buffer

  final(outputEncoding?: BufferEncoding): string | Buffer

  setAutoPadding(pad: unknown): this

  setAAD(buffer: string | Buffer, opts?: { encoding?: BufferEncoding }): this

  getAuthTag(): Buffer
}

export class Decipheriv extends Transform {
  constructor(
    algorithm: CipherAlgorithm | number,
    key: string | Buffer,
    iv: string | Buffer,
    opts?: TransformOptions<Cipheriv>
  )

  update(
    data: string | Buffer,
    inputEncoding?: BufferEncoding,
    outputEncoding?: BufferEncoding
  ): string | Buffer

  final(outputEncoding?: BufferEncoding): string | Buffer

  setAutoPadding(pad: boolean): this

  setAAD(buffer: string | Buffer, opts?: { encoding?: BufferEncoding }): this

  setAuthTag(authTag: string | Buffer, encoding?: BufferEncoding): this
}
