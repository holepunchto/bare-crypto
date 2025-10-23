const crypto = require('../../..')

// https://w3c.github.io/webcrypto/#sha

// https://w3c.github.io/webcrypto/#sha-operations-digest
exports.digest = function digest(name, data) {
  const digest = crypto.createHash(name).update(data).digest()

  return digest.buffer.slice(0, digest.byteLength)
}
