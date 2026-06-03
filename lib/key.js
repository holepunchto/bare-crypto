const binding = require('../binding')
const constants = require('./constants')

const {
  keyType: { ED25519 }
} = constants

class CryptoKey {
  constructor(keyType) {
    this._keyType = keyType
  }

  get type() {
    throw new Error('Not implemented')
  }

  get destroyed() {
    return false
  }

  export() {
    throw new Error('Not implemented')
  }

  destroy() {}

  [Symbol.dispose]() {
    this.destroy()
  }
}

exports.Key = CryptoKey

class CryptoEd25519Key extends CryptoKey {
  constructor(key = null) {
    super(ED25519)

    this._destroyed = false

    if (key === null) {
      binding.keyInit(this, new ArrayBuffer(0), 0, 0)
    } else if (ArrayBuffer.isView(key)) {
      binding.keyInit(this, key.buffer, key.byteOffset, key.byteLength)
    } else {
      binding.keyInit(this, key, 0, key.byteLength)
    }
  }

  get asymmetricKeyType() {
    return 'ed25519'
  }

  get destroyed() {
    return this._destroyed
  }

  export() {
    if (this._destroyed) {
      throw new Error('Key has been destroyed')
    }

    return Buffer.from(binding.keyExport(this))
  }

  destroy() {
    if (this._destroyed) return

    binding.keyDestroy(this)

    this._destroyed = true
  }
}

class CryptoEd25519PublicKey extends CryptoEd25519Key {
  get type() {
    return 'public'
  }
}

exports.Ed25519PublicKey = CryptoEd25519PublicKey

class CryptoEd25519PrivateKey extends CryptoEd25519Key {
  get type() {
    return 'private'
  }
}

exports.Ed25519PrivateKey = CryptoEd25519PrivateKey

class CryptoSecretKey extends CryptoKey {
  constructor(key) {
    super()

    this._destroyed = false

    if (ArrayBuffer.isView(key)) {
      binding.keyInit(this, key.buffer, key.byteOffset, key.byteLength)
    } else {
      binding.keyInit(this, key, 0, key.byteLength)
    }
  }

  get type() {
    return 'secret'
  }

  get destroyed() {
    return this._destroyed
  }

  export() {
    if (this._destroyed) {
      throw new Error('Key has been destroyed')
    }

    return Buffer.from(binding.keyExport(this))
  }

  destroy() {
    if (this._destroyed) return

    binding.keyDestroy(this)

    this._destroyed = true
  }
}

exports.SecretKey = CryptoSecretKey

exports.generateKeyPair = function generateKeyPair(type) {
  type = constants.toKeyType(type)

  switch (type) {
    case ED25519: {
      const publicKey = new CryptoEd25519PublicKey()
      const privateKey = new CryptoEd25519PrivateKey()

      binding.ed25519GenerateKeypair(publicKey, privateKey)

      return { publicKey, privateKey }
    }
  }
}
