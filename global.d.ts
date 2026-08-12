export * as crypto from './web'

type Crypto = typeof crypto

declare global {
  /**
   * Installed as a global by importing `bare-crypto/global`, along with `Crypto`, `CryptoKey`, and
   * `SubtleCrypto`.
   */
  const crypto: Crypto
}
