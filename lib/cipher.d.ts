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
  /**
   * @param algorithm - The cipher algorithm, as a string or a numeric constant from `constants.cipher`.
   * @param key - The encryption key; must match the algorithm's required length.
   * @param iv - The initialization vector / nonce; must match the algorithm's required length.
   * @param opts - Options forwarded to `Transform`; may include `encoding` (defaults to `'utf8'`) and, for AEAD algorithms, `authTagLength` (defaults to `16`; must be `12`, `14`, or `16`).
   * @throws {UNKNOWN_CIPHER} `algorithm` is a string that does not name a supported cipher.
   * @throws {RangeError} `key` or `iv` does not match the algorithm's required length, or (AEAD) `authTagLength` is not `12`, `14`, or `16`.
   */
  constructor(
    algorithm: CipherAlgorithm | number,
    key: string | Buffer,
    iv: string | Buffer,
    opts?: TransformOptions<Cipheriv>
  )

  /**
   * Encrypt a chunk. Returns a `Buffer`, or a string if `outputEncoding` is provided. For AEAD ciphers, encrypted output is delivered all at once from `final()`.
   * @param data - The chunk to encrypt.
   * @param inputEncoding - The encoding of `data` when it is a string.
   * @param outputEncoding - If provided, the encrypted result is returned as a string in this encoding.
   */
  update(
    data: string | Buffer,
    inputEncoding?: BufferEncoding,
    outputEncoding?: BufferEncoding
  ): string | Buffer

  /**
   * Finalize encryption. For AEAD ciphers, the auth tag becomes available via `getAuthTag()` after this call.
   * @param outputEncoding - If provided, the final output is returned as a string in this encoding.
   */
  final(outputEncoding?: BufferEncoding): string | Buffer

  /**
   * Enable or disable automatic padding. Block ciphers only.
   * @param pad - `true` to enable automatic padding, `false` to disable it.
   */
  setAutoPadding(pad: unknown): this

  /**
   * Provide additional authenticated data. AEAD ciphers only. The `options` may include an `encoding` for string inputs.
   * @param buffer - The additional authenticated data.
   * @param opts - May include an `encoding` for string `buffer` inputs.
   */
  setAAD(buffer: string | Buffer, opts?: { encoding?: BufferEncoding }): this

  /** Return the auth tag produced by `final()`. AEAD ciphers only. */
  getAuthTag(): Buffer
}

export class Decipheriv extends Transform {
  /**
   * @param algorithm - The cipher algorithm, as a string or a numeric constant from `constants.cipher`.
   * @param key - The decryption key; must match the algorithm's required length.
   * @param iv - The initialization vector / nonce; must match the algorithm's required length.
   * @param opts - Accepts the same options as `createCipheriv`.
   * @throws {UNKNOWN_CIPHER} `algorithm` is a string that does not name a supported cipher.
   * @throws {RangeError} `key` or `iv` does not match the algorithm's required length, or (AEAD) `authTagLength` is not `12`, `14`, or `16`.
   */
  constructor(
    algorithm: CipherAlgorithm | number,
    key: string | Buffer,
    iv: string | Buffer,
    opts?: TransformOptions<Cipheriv>
  )

  /**
   * Decrypt a chunk. Same semantics as `cipher.update()`.
   * @param data - The chunk to decrypt.
   * @param inputEncoding - The encoding of `data` when it is a string.
   * @param outputEncoding - If provided, the decrypted result is returned as a string in this encoding.
   */
  update(
    data: string | Buffer,
    inputEncoding?: BufferEncoding,
    outputEncoding?: BufferEncoding
  ): string | Buffer

  /**
   * Finalize decryption. For AEAD ciphers, `setAuthTag()` must be called before `final()`.
   * @param outputEncoding - If provided, the final output is returned as a string in this encoding.
   */
  final(outputEncoding?: BufferEncoding): string | Buffer

  setAutoPadding(pad: boolean): this

  setAAD(buffer: string | Buffer, opts?: { encoding?: BufferEncoding }): this

  /**
   * Set the expected auth tag prior to calling `final()`. AEAD ciphers only.
   * @param authTag - The expected authentication tag.
   * @param encoding - The encoding of `authTag` when it is a string.
   */
  setAuthTag(authTag: string | Buffer, encoding?: BufferEncoding): this
}
