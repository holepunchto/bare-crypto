const { Transform } = require('bare-stream')
const binding = require('./binding')
const constants = exports.constants = require('./lib/constants')
const errors = exports.errors = require('./lib/errors')

const Hash = exports.Hash = class CryptoHash extends Transform {
  constructor (algorithm, opts = {}) {
    super(opts)

    if (typeof algorithm === 'string') {
      if (algorithm in constants.hash) algorithm = constants.hash[algorithm]
      else {
        algorithm = algorithm.toUpperCase()

        if (algorithm in constants.hash) algorithm = constants.hash[algorithm]
        else {
          throw errors.UNSUPPORTED_DIGEST_METHOD(`Unsupported digest method '${algorithm}'`)
        }
      }
    }

    this._handle = binding.hashInit(algorithm)
  }

  update (data, encoding = 'utf8') {
    if (typeof data === 'string') data = Buffer.from(data, encoding)

    binding.hashUpdate(this._handle, data)

    return this
  }

  digest (encoding) {
    const digest = Buffer.from(binding.hashFinal(this._handle))

    return encoding ? digest.toString(encoding) : digest
  }

  _transform (data, encoding, cb) {
    this.update(data)

    cb(null)
  }

  _flush (cb) {
    this.push(this.digest())

    cb(null)
  }
}

exports.createHash = function createHash (algorithm, opts) {
  return new Hash(algorithm, opts)
}

exports.randomBytes = function randomBytes (size, cb) {
  const buffer = Buffer.allocUnsafe(size)
  randomFill(buffer)
  if (cb) queueMicrotask(() => cb(null, buffer))
  else return buffer
}

const randomFill = exports.randomFill = function randomFill (buffer, offset, size, cb) {
  if (typeof offset === 'function') {
    cb = offset
    offset = undefined
  } else if (typeof size === 'function') {
    cb = size
    size = undefined
  }

  const elementSize = buffer.BYTES_PER_ELEMENT || 1

  if (offset === undefined) offset = 0
  else offset *= elementSize

  if (size === undefined) size = buffer.byteLength - offset
  else size *= elementSize

  if (offset < 0 || offset > buffer.byteLength) throw new RangeError('offset is out of range')
  if (size < 0 || size > buffer.byteLength) throw new RangeError('size is out of range')
  if (offset + size > buffer.byteLength) throw new RangeError('offset + size is out of range')

  if (ArrayBuffer.isView(buffer)) {
    offset += buffer.byteOffset
    buffer = buffer.buffer
  }

  binding.randomFill(buffer, offset, size)

  if (cb) queueMicrotask(() => cb(null, buffer))
  else return buffer
}

// For Node.js compatibility
exports.randomFillSync = function randomFillSync (buffer, offset, size) {
  return randomFill(buffer, offset, size)
}
