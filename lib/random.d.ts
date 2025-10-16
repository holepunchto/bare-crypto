import Buffer from 'bare-buffer'

export function randomBytes(size: number): Buffer

export function randomBytes(
  size: number,
  callback: (err: Error | null, buffer: Buffer) => void
): void

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

export function randomUUID(): string
