const { Transform } = require('bare-stream')
const binding = require('./binding')
const constants = (exports.constants = require('./lib/constants'))

exports.Hash = class CryptoHash extends Transform {
  constructor(algorithm, opts = {}) {
    super(opts)

    this._handle = binding.hashInit(constants.toHash(algorithm))
  }

  update(data, encoding = 'utf8') {
    if (typeof data === 'string') data = Buffer.from(data, encoding)

    binding.hashUpdate(
      this._handle,
      data.buffer,
      data.byteOffset,
      data.byteLength
    )

    return this
  }

  digest(encoding) {
    const digest = Buffer.from(binding.hashFinal(this._handle))

    return encoding && encoding !== 'buffer'
      ? digest.toString(encoding)
      : digest
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

exports.createHash = function createHash(algorithm, opts) {
  return new exports.Hash(algorithm, opts)
}

exports.Hmac = class CryptoHmac extends Transform {
  constructor(algorithm, key, opts = {}) {
    super(opts)

    const { encoding = 'utf8' } = opts

    if (typeof key === 'string') key = Buffer.from(key, encoding)

    this._handle = binding.hmacInit(
      constants.toHash(algorithm),
      key.buffer,
      key.byteOffset,
      key.byteLength
    )
  }

  update(data, encoding = 'utf8') {
    if (typeof data === 'string') data = Buffer.from(data, encoding)

    binding.hmacUpdate(
      this._handle,
      data.buffer,
      data.byteOffset,
      data.byteLength
    )

    return this
  }

  digest(encoding) {
    const digest = Buffer.from(binding.hmacFinal(this._handle))

    return encoding && encoding !== 'buffer'
      ? digest.toString(encoding)
      : digest
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

exports.createHmac = function createHmac(algorithm, key, opts) {
  return new exports.Hmac(algorithm, key, opts)
}

class CryptoCipher {
  constructor(algorithm, key, iv, encrypt, opts = {}) {
    const { encoding = 'utf8' } = opts

    if (typeof key === 'string') key = Buffer.from(key, encoding)
    if (typeof iv === 'string') iv = Buffer.from(iv, encoding)

    algorithm = constants.toCipher(algorithm)

    if (key.byteLength !== binding.cipherKeyLength(algorithm)) {
      throw new RangeError('Invalid key length')
    }

    if (iv.byteLength !== binding.cipherIVLength(algorithm)) {
      throw new RangeError('Invalid iv length')
    }

    this._blockSize = binding.cipherBlockSize(algorithm)

    this._handle = binding.cipherInit(
      algorithm,
      key.buffer,
      key.byteOffset,
      key.byteLength,
      iv.buffer,
      iv.byteOffset,
      iv.byteLength,
      encrypt
    )
  }

  update(data, inputEncoding = 'utf8', outputEncoding) {
    if (typeof data === 'string') data = Buffer.from(data, inputEncoding)

    const out = new ArrayBuffer(this._blockSize)

    const written = binding.cipherUpdate(
      this._handle,
      data.buffer,
      data.byteOffset,
      data.byteLength,
      out
    )

    const result = Buffer.from(out, 0, written)

    return outputEncoding ? result.toString(outputEncoding) : result
  }

  final(outputEncoding) {
    const out = new ArrayBuffer(this._blockSize)

    const written = binding.cipherFinal(this._handle, out)

    const result = Buffer.from(out, 0, written)

    return outputEncoding ? result.toString(outputEncoding) : result
  }

  setPadding(pad) {
    binding.cipherSetPadding(pad)
  }
}

exports.Cipheriv = class CryptoCipheriv extends Transform {
  constructor(algorithm, key, iv, opts = {}) {
    super(opts)

    this._cipher = new CryptoCipher(algorithm, key, iv, true, opts)
  }

  update(data, inputEncoding, outputEncoding) {
    return this._cipher.update(data, inputEncoding, outputEncoding)
  }

  final(outputEncoding) {
    return this._cipher.final(outputEncoding)
  }

  setAutoPadding(pad) {
    this._cipher.setPadding(pad)

    return this
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

exports.createCipheriv = function createCipheriv(algorithm, key, iv, opts) {
  return new exports.Cipheriv(algorithm, key, iv, opts)
}

exports.Decipheriv = class CryptoDeipheriv extends Transform {
  constructor(algorithm, key, iv, opts = {}) {
    super(opts)

    this._cipher = new CryptoCipher(algorithm, key, iv, false, opts)
  }

  update(data, inputEncoding, outputEncoding) {
    return this._cipher.update(data, inputEncoding, outputEncoding)
  }

  final(outputEncoding) {
    return this._cipher.final(outputEncoding)
  }

  setAutoPadding(pad) {
    this._cipher.setPadding(pad)

    return this
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

exports.createDecipheriv = function createDecipheriv(algorithm, key, iv, opts) {
  return new exports.Decipheriv(algorithm, key, iv, opts)
}

exports.randomBytes = function randomBytes(size, cb) {
  const buffer = Buffer.allocUnsafe(size)
  exports.randomFill(buffer)
  if (cb) queueMicrotask(() => cb(null, buffer))
  else return buffer
}

exports.randomFill = function randomFill(buffer, offset, size, cb) {
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

  if (offset < 0 || offset > buffer.byteLength) {
    throw new RangeError('offset is out of range')
  }

  if (size < 0 || size > buffer.byteLength) {
    throw new RangeError('size is out of range')
  }

  if (offset + size > buffer.byteLength) {
    throw new RangeError('offset + size is out of range')
  }

  let arraybuffer

  if (ArrayBuffer.isView(buffer)) {
    offset += buffer.byteOffset
    arraybuffer = buffer.buffer
  } else {
    arraybuffer = buffer
  }

  binding.randomFill(arraybuffer, offset, size)

  if (cb) queueMicrotask(() => cb(null, buffer))
  else return buffer
}

// For Node.js compatibility
exports.randomFillSync = function randomFillSync(buffer, offset, size) {
  return exports.randomFill(buffer, offset, size)
}

exports.pbkdf2 = function pbkdf2(
  password,
  salt,
  iterations,
  keylen,
  digest,
  cb
) {
  if (iterations <= 0) {
    throw new RangeError('iterations is out of range')
  }

  if (typeof password === 'string') password = Buffer.from(password)
  if (typeof salt === 'string') salt = Buffer.from(salt)

  const buffer = Buffer.from(
    binding.pbkdf2(
      password.buffer,
      password.byteOffset,
      password.byteLength,
      salt.buffer,
      salt.byteOffset,
      salt.byteLength,
      iterations,
      constants.toHash(digest),
      keylen
    )
  )

  if (cb) queueMicrotask(() => cb(null, buffer))
  else return buffer
}

// For Node.js compatibility
exports.pbkdf2Sync = function pbkdf2Sync(
  password,
  salt,
  iterations,
  keylen,
  digest
) {
  return exports.pbkdf2(password, salt, iterations, keylen, digest)
}

// For Node.js compatibility
exports.webcrypto = require('./web')
