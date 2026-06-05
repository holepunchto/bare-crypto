const crypto = require('../../..')
const errors = require('../../errors')
const { SecretKey } = require('../../key')
const CryptoKey = require('../crypto-key')

// https://w3c.github.io/webcrypto/#hmac

// https://w3c.github.io/webcrypto/#hmac-operations-sign
exports.sign = function sign(algorithm, key, data) {
  const material = key._handle.export()

  const digest = crypto.createHmac(key.algorithm.hash.name, material).update(data).digest()

  return digest.buffer.slice(0, digest.byteLength)
}

// https://w3c.github.io/webcrypto/#hmac-operations-verify
exports.verify = function verify(algorithm, key, signature, data) {
  const material = key._handle.export()

  const digest = crypto.createHmac(key.algorithm.hash.name, material).update(data).digest()

  if (ArrayBuffer.isView(signature)) {
    signature = Buffer.coerce(signature)
  } else {
    signature = Buffer.from(signature)
  }

  if (signature.byteLength !== digest.byteLength) return false

  return crypto.timingSafeEqual(signature, digest)
}

// https://w3c.github.io/webcrypto/#hmac-operations-generate-key
exports.generateKey = function generateKey(algorithm, extractable, usages) {
  for (const usage of usages) {
    if (usage !== 'sign' && usage !== 'verify') {
      throw new SyntaxError(`Usage '${usage}' cannot be used for the HMAC generateKey() operation`)
    }
  }

  const length = exports.getKeyLength(algorithm)

  let hash = algorithm.hash

  if (typeof hash === 'string') hash = { name: hash }

  const key = crypto.randomBytes(length / 8)

  const handle = new SecretKey(key)

  key.fill(0)

  return new CryptoKey(
    'secret',
    extractable,
    {
      name: 'HMAC',
      length,
      hash: {
        name: hash.name.toUpperCase()
      }
    },
    usages,
    handle
  )
}

// https://w3c.github.io/webcrypto/#hmac-operations-import-key
exports.importKey = function importKey(format, keyData, algorithm, extractable, usages) {
  for (const usage of usages) {
    if (usage !== 'sign' && usage !== 'verify') {
      throw new SyntaxError(`Invalid usage ${usage}`)
    }
  }

  let hash = algorithm.hash

  if (typeof hash === 'string') hash = { name: hash }

  let data
  let owned = false

  switch (format) {
    case 'raw':
      data = keyData
      break
    case 'jwk': {
      const jwk = keyData

      if (jwk.kty !== 'oct') {
        throw errors.INVALID_DATA('JWK key must be an octet sequence')
      }

      data = Buffer.from(jwk.k, 'base64url')
      owned = true

      switch (hash.name.toLowerCase()) {
        case 'sha-1':
          if (jwk.alg === 'HS1') break
          else throw errors.INVALID_DATA('Invalid JWK key algorithm')
        case 'sha-256':
          if (jwk.alg === 'HS256') break
          else throw errors.INVALID_DATA('Invalid JWK key algorithm')
        case 'sha-384':
          if (jwk.alg === 'HS384') break
          else throw errors.INVALID_DATA('Invalid JWK key algorithm')
        case 'sha-512':
          if (jwk.alg === 'HS512') break
          else throw errors.INVALID_DATA('Invalid JWK key algorithm')
      }

      if (usages.length && 'use' in jwk && jwk.use !== 'sign') {
        throw errors.INVALID_DATA('JWK cannot be used for signing')
      }

      if ('ext' in jwk && jwk.ext !== extractable && extractable) {
        throw errors.INVALID_DATA('JWK is not extractable')
      }
      break
    }
    default:
      throw errors.NOT_SUPPORTED(
        `Format '${format}' cannot be used for the HMAC importKey() operation`
      )
  }

  const length = data.byteLength * 8

  if (length === 0) {
    throw errors.INVALID_DATA('Key cannot be empty')
  }

  const handle = new SecretKey(data)

  if (owned) data.fill(0)

  return new CryptoKey(
    'secret',
    extractable,
    {
      name: 'HMAC',
      length,
      hash: {
        name: hash.name.toUpperCase()
      }
    },
    usages,
    handle
  )
}

// https://w3c.github.io/webcrypto/#hmac-operations-export-key
exports.exportKey = function exportKey(format, key) {
  const data = key._handle.export()

  switch (format) {
    case 'raw':
      return data.buffer.slice(0, data.byteLength)
    case 'jwk': {
      const jwk = {
        kty: 'oct',
        k: data.toString('base64url'),
        alg: null,
        key_ops: key.usages,
        ext: key.extractable
      }

      switch (key.algorithm.hash.name) {
        case 'SHA-1':
          jwk.alg = 'HS1'
          break
        case 'SHA-256':
          jwk.alg = 'HS256'
          break
        case 'SHA-384':
          jwk.alg = 'HS384'
          break
        case 'SHA-512':
          jwk.alg = 'HS512'
          break
      }

      return jwk
    }
    default:
      throw errors.NOT_SUPPORTED(
        `Format '${format}' cannot be used for the HMAC exportKey() operation`
      )
  }
}

// https://w3c.github.io/webcrypto/#hmac-operations-get-key-length
exports.getKeyLength = function getKeyLength(algorithm) {
  const { length } = algorithm

  let { hash } = algorithm

  if (hash !== null && typeof hash === 'object') hash = hash.name

  if (length === undefined) {
    if (hash === 'SHA-1' || hash === 'SHA-256') return 512
    if (hash === 'SHA-384' || hash === 'SHA-512') return 1024

    throw errors.OPERATION_ERROR(`Invalid hash '${hash}'`)
  }

  if (length === 0) {
    throw errors.OPERATION_ERROR(`Invalid length ${length}`)
  }

  return length
}
