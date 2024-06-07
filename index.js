const { Transform } = require('bare-stream')
const binding = require('./binding')
const constants = exports.constants = require('./lib/constants')
const errors = exports.errors = require('./lib/errors')

const Hash = exports.Hash = class CryptoHash extends Transform {
  constructor (algorithm, opts = {}) {
    super({ ...opts, mapWritable })

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
    binding.hashUpdate(this._handle, typeof data === 'string' ? Buffer.from(data, encoding) : data)

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

exports.randomBytes = function randomBytes (size) {
  return randomFillSync(Buffer.alloc(size))
}

const randomFillSync = exports.randomFillSync = function randomFillSync (buf, offset, size) {
  const isView = ArrayBuffer.isView(buf)
  const elementSize = buf.BYTES_PER_ELEMENT || 1

  if (offset === undefined) offset = 0
  else offset *= elementSize

  if (size === undefined) size = buf.byteLength - offset
  else size *= elementSize

  if (offset < 0 || offset > buf.byteLength) throw new RangeError('offset is out of range')
  if (size < 0 || size > buf.byteLength) throw new RangeError('size is out of range')
  if (offset + size > buf.byteLength) throw new RangeError('offset + size is out of range')

  if (isView) offset += buf.byteOffset

  binding.randomBytes(isView ? buf.buffer : buf, offset, size)

  return buf
}

function mapWritable (data) {
  return typeof data === 'string' ? Buffer.from(data) : data
}
