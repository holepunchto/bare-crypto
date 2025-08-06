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
      if (usage !== 'sign' && usage !== 'verify') {
        throw new SyntaxError(`Invalid usage ${usage}`)
      }
    }

    if (!length) length = getKeyLength(algorithm)

    const key = crypto
      .createHmac(fromWebCryptoBareCrypto(hash), crypto.randomBytes(length))
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

    if (name !== 'HMAC' && name !== 'PBKDF2') {
      throw errors.UNSUPPORTED_ALGORITHM(`Unsupported algorithm name '${name}'`)
    }

    keyData = Buffer.from(keyData)

    if (usages.length === 0) {
      throw new SyntaxError('keyUsages cannot be empty')
    }

    // https://w3c.github.io/webcrypto/#hmac-operations-import-key
    if (name === 'HMAC') {
      for (const usage of usages) {
        if (usage !== 'sign' && usage !== 'verify') {
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
        if (usage !== 'deriveKey' && usage !== 'deriveBits') {
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

    if (algorithm.name !== 'HMAC' && algorithm.name !== 'PBKDF2') {
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
      throw errors.INVALID_ACCESS('Unable to use the provided key to sign')
    }

    const hash = fromWebCryptoBareCrypto(key.algorithm.hash.name)

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
      throw errors.INVALID_ACCESS('Unable to use the provided key to verify')
    }

    key = structuredClone(key)
    key.usages = ['sign']

    return signature.equals(await this.sign(algorithm, key, data))
  }

  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-deriveBits
  // https://w3c.github.io/webcrypto/#pbkdf2-operations-derive-bits
  async deriveBits(algorithm, key, length = null) {
    if (algorithm.name.toUpperCase() !== 'PBKDF2') {
      throw errors.UNSUPPORTED_ALGORITHM(
        `Unsupported algorithm name '${algorithm.name}'`
      )
    }

    if (algorithm.name.toUpperCase() !== key.algorithm.name.toUpperCase()) {
      throw errors.INVALID_ACCESS('Divergent algorithms')
    }

    if (!key.usages.includes('deriveBits')) {
      throw errors.INVALID_ACCESS(
        'Unable to use the provided key to derive bits'
      )
    }

    if (length === null || length % 8) {
      throw errors.OPERATION_ERROR('Length must be multiple of 8')
    }

    const buf = crypto.pbkdf2(
      key._key,
      algorithm.salt,
      algorithm.iterations,
      length / 8,
      fromWebCryptoBareCrypto(algorithm.hash)
    )

    return buf.buffer
  }

  // https://w3c.github.io/webcrypto/#SubtleCrypto-method-deriveKey
  async deriveKey(algorithm, key, derivedKeyAlgorithm, extractable, keyUsages) {
    if (!key.usages.includes('deriveKey')) {
      throw errors.INVALID_ACCESS(
        'Unable to use the provided key to derive key'
      )
    }

    key = structuredClone(key)
    key.usages = ['deriveBits']

    const derivedKey = await this.deriveBits(
      algorithm,
      key,
      getKeyLength(derivedKeyAlgorithm)
    )

    return this.importKey(
      'raw',
      derivedKey,
      derivedKeyAlgorithm,
      extractable,
      keyUsages
    )
  }
}

exports.subtle = new exports.SubtleCrypto()

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

function getKeyLength({ name, hash, length }) {
  name = name.toUpperCase()

  if (name === 'HMAC') {
    // https://w3c.github.io/webcrypto/#hmac-operations-get-key-length
    if (length === undefined) {
      if (hash === 'SHA-1' || hash === 'SHA-256') return 512
      if (hash === 'SHA-512') return 1024

      throw errors.OPERATION_ERROR(`Invalid hash ${hash}`)
    } else if (length > 0) {
      return length
    } else {
      throw errors.OPERATION_ERROR(`Invalid length ${length}`)
    }
  } else if (name === 'PBKDF2') {
    // https://w3c.github.io/webcrypto/#pbkdf2-operations-get-key-length
    return null
  } else {
    throw errors.UNSUPPORTED_ALGORITHM(`Unsupported algorithm name '${name}'`)
  }
}

function fromWebCryptoBareCrypto(name) {
  if (name === 'SHA-1') return 'SHA1'
  if (name === 'SHA-256') return 'SHA256'
  if (name === 'SHA-512') return 'SHA512'

  return name
}
