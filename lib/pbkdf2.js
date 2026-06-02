const assert = require('bare-assert')
const binding = require('../binding')
const constants = require('./constants')

module.exports = function pbkdf2(password, salt, iterations, keylen, digest, cb) {
  assert(typeof iterations === 'number' && !isNaN(iterations))

  if (iterations < 1 || iterations > 0xffffffff) {
    throw new RangeError('Invalid iterations')
  }

  assert(typeof keylen === 'number' && !isNaN(keylen))

  if (keylen < 1 || keylen > 0x7fffffff) {
    throw new RangeError('Invalid key length')
  }

  if (typeof password === 'string') password = Buffer.from(password)
  if (typeof salt === 'string') salt = Buffer.from(salt)

  assert(ArrayBuffer.isView(password))
  assert(ArrayBuffer.isView(salt))

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
