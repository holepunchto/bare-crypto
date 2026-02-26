const { Transform } = require('bare-stream')
const binding = require('../binding')
const constants = require('./constants')

const {
  hash: { RIPEMD160 }
} = constants

class CryptoDigest {
  constructor(algorithm) {
    this._handle = binding.digestInit(algorithm)
  }

  update(data) {
    if (this._handle === null) {
      throw new Error('Digest has already been finalized')
    }

    binding.digestUpdate(this._handle, data.buffer, data.byteOffset, data.byteLength)
  }

  final() {
    if (this._handle === null) {
      throw new Error('Digest has already been finalized')
    }

    const result = Buffer.from(binding.digestFinal(this._handle))
    this._handle = null
    return result
  }
}

class CryptoRIPEMD160Digest {
  constructor() {
    this._handle = binding.ripemd160Init()
  }

  update(data) {
    if (this._handle === null) {
      throw new Error('Digest has already been finalized')
    }

    binding.ripemd160Update(this._handle, data.buffer, data.byteOffset, data.byteLength)
  }

  final() {
    if (this._handle === null) {
      throw new Error('Digest has already been finalized')
    }

    const result = Buffer.from(binding.ripemd160Final(this._handle))
    this._handle = null
    return result
  }
}

module.exports = class CryptoHash extends Transform {
  constructor(algorithm, opts = {}) {
    super(opts)

    algorithm = constants.toHash(algorithm)

    switch (algorithm) {
      case RIPEMD160:
        this._digest = new CryptoRIPEMD160Digest()
        break

      default:
        this._digest = new CryptoDigest(algorithm)
        break
    }
  }

  update(data, encoding = 'utf8') {
    if (typeof data === 'string') data = Buffer.from(data, encoding)

    this._digest.update(data)

    return this
  }

  digest(encoding) {
    const digest = this._digest.final()

    return encoding && encoding !== 'buffer' ? digest.toString(encoding) : digest
  }

  _transform(data, encoding, cb) {
    this.update(data)

    cb(null)
  }

  _flush(cb) {
    this.push(this.digest())

    cb(null)
  }
}
