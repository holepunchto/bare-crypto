const test = require('brittle')
const crypto = require('..')

test('generateKeyPair, ed25519', (t) => {
  const { publicKey, privateKey } = crypto.generateKeyPair('ed25519')

  t.is(publicKey.type, 'public')
  t.is(privateKey.type, 'private')
})

test('type guards', (t) => {
  t.exception(() => crypto.generateKeyPair(NaN), /AssertionError/)
})
