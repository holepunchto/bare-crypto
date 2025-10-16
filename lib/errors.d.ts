declare class CryptoError extends Error {
  static UNKNOWN_HASH(msg: string): CryptoError
  static UNKNOWN_CIPHER(msg: string): CryptoError
  static UNKNOWN_KEY_TYPE(msg: string): CryptoError
  static INVALID_ACCESS(msg: string): CryptoError
  static INVALID_DATA(msg: string): CryptoError
  static OPERATION_ERROR(msg: string): CryptoError
  static NOT_SUPPORTED(msg: string): CryptoError
}

export = CryptoError
