import { Transform, TransformOptions } from 'bare-stream'
import { Buffer, BufferEncoding } from 'bare-buffer'

type Algorithm = 'MD5' | 'SHA1' | 'SHA256' | 'SHA512' | 'BLAKE2B256'

export const constants: { hash: Record<Algorithm, number> }

declare class CryptoError extends Error {
  static UNSUPPORTED_DIGEST_METHOD(msg: string): CryptoError
}

export class Hash extends Transform {
  constructor(
    algorithm: Algorithm | Lowercase<Algorithm> | number,
    opts?: TransformOptions
  )

  update(data: string | Buffer | DataView, encoding?: BufferEncoding): this

  digest(encoding?: BufferEncoding): string | Buffer
}

export function createHash(
  algorithm: Algorithm | Lowercase<Algorithm> | number,
  opts?: TransformOptions
): Hash

export function randomBytes(
  size: number,
  callback: (error: null, buffer: Buffer) => void
): void

export function randomBytes(size: number): Buffer

export function randomFill<B extends ArrayBuffer | Buffer | DataView>(
  buffer: B,
  offset?: number,
  size?: number
): B

export function randomFill<B extends ArrayBuffer | Buffer | DataView>(
  buffer: B,
  offset: number,
  size: number,
  callback: (err: null, buffer: B) => void
): void

export function randomFill<B extends ArrayBuffer | Buffer | DataView>(
  buffer: B,
  offset: number,
  callback: (err: null, buffer: B) => void
): void

export function randomFill<B extends ArrayBuffer | Buffer | DataView>(
  buffer: B,
  callback: (err: null, buffer: B) => void
): void

export { CryptoError as errors, randomFill as randomFillSync }
