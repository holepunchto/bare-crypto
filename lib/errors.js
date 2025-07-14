module.exports = class CryptoError extends Error {
  constructor(msg, code, fn = CryptoError) {
    super(`${code}: ${msg}`)
    this.code = code

    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, fn)
    }
  }

  get name() {
    return 'CryptoError'
  }

  static UNSUPPORTED_DIGEST_METHOD(msg) {
    return new CryptoError(
      msg,
      'UNSUPPORTED_DIGEST_METHOD',
      CryptoError.UNSUPPORTED_DIGEST_METHOD
    )
  }

  static UNSUPPORTED_ALGORITHM(msg) {
    return new CryptoError(
      msg,
      'UNSUPPORTED_ALGORITHM',
      CryptoError.UNSUPPORTED_DIGEST_METHOD
    )
  }

  static UNSUPPORTED_FORMAT(msg) {
    return new CryptoError(
      msg,
      'UNSUPPORTED_FORMAT',
      CryptoError.UNSUPPORTED_DIGEST_METHOD
    )
  }

  static INVALID_ACCESS(msg) {
    return new CryptoError(
      msg,
      'INVALID_ACCESS',
      CryptoError.UNSUPPORTED_DIGEST_METHOD
    )
  }
}
