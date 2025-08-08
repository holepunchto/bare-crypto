const binding = require('../binding')
const constants = require('./constants')

const {
  keyType: { ED25519 }
} = constants

class CryptoKey {
  constructor(keyType) {
    this._keyType = keyType
  }
}

exports.Key = CryptoKey

class CryptoED25519Key extends CryptoKey {
  constructor(key) {
    super(ED25519)

    this._key = key
  }

  get asymmetricKeyType() {
    return 'ed25519'
  }
}

class CryptoED25519PublicKey extends CryptoED25519Key {
  get type() {
    return 'public'
  }
}

class CryptoED25519PrivateKey extends CryptoED25519Key {
  get type() {
    return 'private'
  }
}

exports.generateKeyPair = function generateKeyPair(type, opts = {}) {
  type = constants.toKeyType(type)

  switch (type) {
    case ED25519: {
      const { publicKey, privateKey } = binding.ed25519GenerateKeypair()

      return {
        publicKey: new CryptoED25519PublicKey(publicKey),
        privateKey: new CryptoED25519PrivateKey(privateKey)
      }
    }
  }
}
