const crypto = require('.')
const errors = require('./lib/errors')

// https://w3c.github.io/webcrypto/#Crypto-method-getRandomValues
exports.getRandomValues = function getRandomValues(array) {
  return crypto.randomFillSync(array)
}

// https://w3c.github.io/webcrypto/#subtlecrypto-interface
exports.SubtleCrypto = class SubtleCrypto {
  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-generateKey
  // https://w3c.github.io/webcrypto/#hmac-operations-generate-key
  async generateKey(algorithm, extractable) {
    let { name, length } = algorithm
    const { hash } = algorithm

    name = name.toUpperCase()

    if (name !== 'HMAC') {
      throw errors.UNSUPPORTED_ALGORITHM(`Unsupported algorithm name '${name}'`)
    }

    if (length === undefined) {
      if (hash === 'SHA-1' || hash === 'SHA-256') length = 512
      if (hash === 'SHA-512') length = 1024
    }

    const key = crypto
      .createHmac(hash.replace('-', ''), crypto.randomBytes(length))
      .digest()

    return new exports.CryptoKey(
      key,
      { name, length, hash: { name: hash } },
      extractable
    )
  }

  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-importKey
  // https://w3c.github.io/webcrypto/#hmac-operations-import-key
  async importKey(format, keyData, algorithm, extractable) {
    if (format !== 'raw') {
      throw errors.UNSUPPORTED_FORMAT(`Unsupported format '${format}'`)
    }

    let { name } = algorithm

    name = name.toUpperCase()

    if (name !== 'HMAC') {
      throw errors.UNSUPPORTED_ALGORITHM(`Unsupported algorithm name '${name}'`)
    }

    const length = keyData.byteLength * 8

    if (length === 0) {
      throw errors.UNSUPPORTED_FORMAT('Key length cannot be zero')
    }

    const { hash } = algorithm

    return new exports.CryptoKey(
      keyData,
      { name, length, hash: { name: hash } },
      extractable
    )
  }

  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-exportKey
  // https://w3c.github.io/webcrypto/#hmac-operations-export-key
  async exportKey(format, key) {
    const { name, extractable } = key.algorithm

    if (name !== 'HMAC') {
      throw errors.UNSUPPORTED_ALGORITHM(`Unsupported algorithm name '${name}'`)
    }

    if (extractable === false) {
      throw errors.INVALID_ACCESS('Provided key is not extractable')
    }

    if (format !== 'raw') {
      throw errors.UNSUPPORTED_FORMAT(`Unsupported format '${format}'`)
    }

    return key._key.buffer
  }
}

// https://w3c.github.io/webcrypto/#cryptokey-interface
exports.CryptoKey = class CryptoKey {
  constructor(key, algorithm, extractable) {
    this._key = key // must be a non-enumerable property
    this.type = 'secret'
    this.algorithm = algorithm
    this.extractable = extractable
  }
}

exports.subtle = new exports.SubtleCrypto()
