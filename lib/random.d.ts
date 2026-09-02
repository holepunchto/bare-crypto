import Buffer from 'bare-buffer'

/**
 * Generate `size` cryptographically secure random bytes.
 * @param size - The number of random bytes to generate.
 */
export function randomBytes(size: number): Buffer

export function randomBytes(
  size: number,
  callback: (err: Error | null, buffer: Buffer) => void
): void

/**
 * Fill `buffer` with cryptographically secure random bytes, optionally restricted to `[offset,
 * offset + size)`. `offset` defaults to `0` and `size` to `buffer.byteLength - offset`. Returns the
 * same `buffer`.
 * @param buffer - The buffer to fill.
 * @param offset - Offset at which filling starts (defaults to `0`).
 * @param size - Amount to fill (defaults to `buffer.byteLength - offset`).
 * @throws {RangeError} `offset`, `size`, or `offset + size` is out of range for `buffer`.
 */
export function randomFill<B extends ArrayBuffer | ArrayBufferView>(
  buffer: B,
  offset?: number,
  size?: number
): B

export function randomFill<B extends ArrayBuffer | ArrayBufferView>(
  buffer: B,
  callback: (err: Error | null, buffer: B) => void
): void

export function randomFill<B extends ArrayBuffer | ArrayBufferView>(
  buffer: B,
  offset: number,
  callback: (err: Error | null, buffer: B) => void
): void

export function randomFill<B extends ArrayBuffer | ArrayBufferView>(
  buffer: B,
  offset: number,
  size: number,
  callback: (err: Error | null, buffer: B) => void
): void

/** Generate a random RFC 4122 version-4 UUID string. */
export function randomUUID(): string
