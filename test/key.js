const test = require('brittle')
const crypto = require('..')

test('generateKeyPair, ed25519', (t) => {
  const { publicKey, privateKey } = crypto.generateKeyPair('ed25519')
})
