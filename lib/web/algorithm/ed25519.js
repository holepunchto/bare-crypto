const crypto = require('../../..')
const errors = require('../../errors')
const CryptoKey = require('../crypto-key')

// https://w3c.github.io/webcrypto/#ed25519

// https://w3c.github.io/webcrypto/#ed25519-operations-sign
exports.sign = function sign(algorithm, key, data) {
  if (key.type !== 'private') {
    throw errors.INVALID_ACCESS('Must pass private key for ED25519 signing')
  }

  const signature = crypto.sign(null, data, key._handle)

  const result = new ArrayBuffer(signature.byteLength)
  Buffer.from(result).set(signature)
  return result
}

// https://w3c.github.io/webcrypto/#ed25519-operations-verify
exports.verify = function verify(algorithm, key, signature, data) {
  if (key.type !== 'public') {
    throw errors.INVALID_ACCESS('Must pass public key for ED25519 verification')
  }

  return crypto.verify(null, data, key._handle, signature)
}

// https://w3c.github.io/webcrypto/#ed25519-operations-generate-key
exports.generateKey = function generateKey(algorithm, extractable, usages) {
  for (const usage of usages) {
    if (usage !== 'sign' && usage !== 'verify') {
      throw new SyntaxError(
        `Usage '${usage}' cannot be used for the ED25519 generateKey() operation`
      )
    }
  }

  const keys = crypto.generateKeyPair('ed25519')

  algorithm = { name: 'Ed25519' }

  return {
    publicKey: new CryptoKey(
      'public',
      true,
      algorithm,
      ['verify'],
      keys.publicKey
    ),
    privateKey: new CryptoKey(
      'private',
      extractable,
      algorithm,
      ['sign'],
      keys.privateKey
    )
  }
}
