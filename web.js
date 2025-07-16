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
  async generateKey(algorithm, extractable, usages) {
    let { name, length } = algorithm
    const { hash } = algorithm

    name = name.toUpperCase()

    if (name !== 'HMAC') {
      throw errors.UNSUPPORTED_ALGORITHM(`Unsupported algorithm name '${name}'`)
    }

    if (usages.length === 0) {
      throw new SyntaxError('Usages argument cannot be empty')
    }

    for (const usage of usages) {
      if (!['sign', 'verify'].includes(usage)) {
        throw new SyntaxError(`Invalid usage ${usage}`)
      }
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
      extractable,
      usages
    )
  }

  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-importKey
  async importKey(format, keyData, algorithm, extractable, usages) {
    if (format !== 'raw') {
      throw errors.UNSUPPORTED_FORMAT(`Unsupported format '${format}'`)
    }

    let name = algorithm.name || algorithm

    name = name.toUpperCase()

    if (!['HMAC', 'PBKDF2'].includes(name)) {
      throw errors.UNSUPPORTED_ALGORITHM(`Unsupported algorithm name '${name}'`)
    }

    keyData = Buffer.from(keyData) // clone

    if (usages.length === 0) {
      throw new SyntaxError('keyUsages cannot be empty')
    }

    // https://w3c.github.io/webcrypto/#hmac-operations-import-key
    if (name === 'HMAC') {
      for (const usage of usages) {
        if (!['sign', 'verify'].includes(usage)) {
          throw new SyntaxError(`Invalid usage ${usage}`)
        }
      }

      const length = keyData.byteLength * 8

      if (length === 0) {
        throw errors.UNSUPPORTED_FORMAT('Key length cannot be zero')
      }

      const { hash } = algorithm

      return new exports.CryptoKey(
        keyData,
        { name, length, hash: { name: hash } },
        extractable,
        usages
      )
    }
    // https://w3c.github.io/webcrypto/#pbkdf2-operations-import-key
    else {
      for (const usage of usages) {
        if (!['deriveKey', 'deriveBits'].includes(usage)) {
          throw new SyntaxError(`Invalid usage ${usage}`)
        }
      }

      if (extractable !== false) {
        throw new SyntaxError('Extractable must be false')
      }

      return new exports.CryptoKey(keyData, { name }, extractable, usages)
    }
  }

  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-exportKey
  // https://w3c.github.io/webcrypto/#hmac-operations-export-key
  async exportKey(format, key) {
    const { algorithm, extractable } = key

    if (!['HMAC', 'PBKDF2'].includes(algorithm.name)) {
      throw errors.UNSUPPORTED_ALGORITHM(
        `Unsupported algorithm name '${algorithm.name}'`
      )
    }

    if (extractable === false) {
      throw errors.INVALID_ACCESS('Provided key is not extractable')
    }

    if (format !== 'raw') {
      throw errors.UNSUPPORTED_FORMAT(`Unsupported format '${format}'`)
    }

    return key._key
  }

  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-sign
  // https://w3c.github.io/webcrypto/#hmac-operations-sign
  async sign(algorithm, key, data) {
    if (typeof algorithm === 'string') algorithm = { name: algorithm }

    if (algorithm.name.toUpperCase() !== 'HMAC') {
      throw errors.UNSUPPORTED_ALGORITHM(
        `Unsupported algorithm name '${algorithm.name}'`
      )
    }

    if (algorithm.name.toUpperCase() !== key.algorithm.name) {
      throw errors.INVALID_ACCESS('Divergent algorithms')
    }

    if (!key.usages.includes('sign')) {
      throw errors.INVALID_ACCESS('Unable to use this key to sign')
    }

    const hash = key.algorithm.hash.name.replace('-', '')

    data = Buffer.from(data) // clone

    return crypto.createHmac(hash, key._key).update(data).digest()
  }

  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-verify
  // https://w3c.github.io/webcrypto/#hmac-operations-verify
  async verify(algorithm, key, signature, data) {
    if (typeof algorithm === 'string') algorithm = { name: algorithm }

    if (algorithm.name.toUpperCase() !== 'HMAC') {
      throw errors.UNSUPPORTED_ALGORITHM(
        `Unsupported algorithm name '${algorithm.name}'`
      )
    }

    if (algorithm.name.toUpperCase() !== key.algorithm.name) {
      throw errors.INVALID_ACCESS('Divergent algorithms')
    }

    if (!key.usages.includes('verify')) {
      throw errors.INVALID_ACCESS('Unable to use this key to verify')
    }

    signature = Buffer.from(signature) // clone
    data = Buffer.from(data)

    return signature.equals(await this.sign(algorithm, key, data))
  }
}

// https://w3c.github.io/webcrypto/#cryptokey-interface
exports.CryptoKey = class CryptoKey {
  constructor(key, algorithm, extractable, usages) {
    this._key = key

    this.type = 'secret'
    this.algorithm = algorithm
    this.extractable = extractable
    this.usages = usages
  }
}

exports.subtle = new exports.SubtleCrypto()
