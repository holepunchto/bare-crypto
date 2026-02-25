const test = require('brittle')
const crypto = require('..')

test('sign + verify, ed25519', (t) => {
  const { publicKey, privateKey } = crypto.generateKeyPair('ed25519')

  const signature = crypto.sign(null, Buffer.from('message'), privateKey)

  t.is(crypto.verify(null, Buffer.from('message'), publicKey, signature), true)

  t.is(crypto.verify(null, Buffer.from('other message'), publicKey, signature), false)
})

test('signature, type guards', (t) => {
  t.plan(5)

  const { publicKey, privateKey } = crypto.generateKeyPair('ed25519')

  const signature = crypto.sign(null, Buffer.from('foo'), privateKey)

  t.exception(() => crypto.sign(null, NaN, privateKey), /AssertionError/)

  t.exception(() => crypto.sign(null, Buffer.from('foo'), NaN), /AssertionError/)

  t.exception(() => crypto.verify(null, NaN, publicKey, signature), /AssertionError/)

  t.exception(() => crypto.verify(null, Buffer.from(''), NaN, signature), /AssertionError/)

  t.exception(() => crypto.verify(null, Buffer.from('foo'), publicKey, NaN), /AssertionError/)
})
