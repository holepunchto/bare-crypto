const constants = require('./lib/constants')
const Hash = require('./lib/hash')
const Hmac = require('./lib/hmac')
const { Cipheriv, Decipheriv } = require('./lib/cipher')
const { randomBytes, randomFill } = require('./lib/random')
const pbkdf2 = require('./lib/pbkdf2')

exports.constants = constants

exports.Hash = Hash

exports.createHash = function createHash(algorithm, opts) {
  return new Hash(algorithm, opts)
}

exports.Hmac = Hmac

exports.createHmac = function createHmac(algorithm, key, opts) {
  return new Hmac(algorithm, key, opts)
}

exports.Cipheriv = Cipheriv

exports.createCipheriv = function createCipheriv(algorithm, key, iv, opts) {
  return new Cipheriv(algorithm, key, iv, opts)
}

exports.Decipheriv = Decipheriv

exports.createDecipheriv = function createDecipheriv(algorithm, key, iv, opts) {
  return new Decipheriv(algorithm, key, iv, opts)
}

exports.randomBytes = randomBytes

exports.randomFill = randomFill

// For Node.js compatibility
exports.randomFillSync = function randomFillSync(buffer, offset, size) {
  return exports.randomFill(buffer, offset, size)
}

exports.pbkdf2 = pbkdf2

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
