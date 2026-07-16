declare class CryptoKey<A extends 'HMAC' | 'Ed25519' | 'PBKDF2' | string = string> {
  readonly type: 'public' | 'secret'
  readonly extractable: boolean
  readonly algorithm: A extends 'HMAC'
    ? { name: A; length: number; hash: { name: 'SHA-256' } }
    : { name: A }
  readonly usages: ('sign' | 'verify')[]
  readonly destroyed: boolean

  destroy(): void

  [Symbol.dispose](): void
}

export = CryptoKey
