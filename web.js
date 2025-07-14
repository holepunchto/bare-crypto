const crypto = require('.')
const errors = require('./lib/errors')

// https://w3c.github.io/webcrypto/#Crypto-method-getRandomValues
exports.getRandomValues = function getRandomValues(array) {
  return crypto.randomFillSync(array)
}

// https://w3c.github.io/webcrypto/#subtlecrypto-interface
exports.SubtleCrypto = class SubtleCrypto {
  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-generateKey
  async generateKey(algorithm) {
    let { name, length } = algorithm
    const { hash } = algorithm

    name = name.toUpperCase()

    if (name !== 'HMAC') {
      throw errors.UNSUPPORTED_DIGEST_METHOD(
        `Unsupported algorithm name '${name}'`
      )
    }

    // https://w3c.github.io/webcrypto/#hmac-operations-generate-key
    if (length === undefined) {
      if (hash === 'SHA-1' || hash === 'SHA-256') length = 512
      if (hash === 'SHA-512') length = 1024
    }

    return new exports.CryptoKey('secret', {
      name,
      length,
      hash: { name: hash }
    })
  }
}

// https://w3c.github.io/webcrypto/#cryptokey-interface
exports.CryptoKey = class CryptoKey {
  constructor(type, algorithm) {
    this.type = type
    this.algorithm = algorithm
  }
}

exports.subtle = new exports.SubtleCrypto()
