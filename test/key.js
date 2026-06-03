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

test('ed25519, destroy zeroes private key', (t) => {
  const { privateKey } = crypto.generateKeyPair('ed25519')

  t.ok(privateKey.export().some((b) => b !== 0))

  privateKey.destroy()

  t.is(privateKey.destroyed, true)
  t.exception(() => privateKey.export(), /Key has been destroyed/)
})

test('ed25519, destroy is idempotent', (t) => {
  const { privateKey } = crypto.generateKeyPair('ed25519')

  privateKey.destroy()
  privateKey.destroy()

  t.is(privateKey.destroyed, true)
})

test('ed25519, signing with destroyed key throws', (t) => {
  const { privateKey } = crypto.generateKeyPair('ed25519')

  privateKey.destroy()

  t.exception(
    () => crypto.sign(null, Buffer.from('hello'), privateKey),
    /Key has been destroyed/
  )
})

test('ed25519, verifying with destroyed key throws', (t) => {
  const { publicKey, privateKey } = crypto.generateKeyPair('ed25519')

  const data = Buffer.from('hello')
  const signature = crypto.sign(null, data, privateKey)

  publicKey.destroy()

  t.exception(
    () => crypto.verify(null, data, publicKey, signature),
    /Key has been destroyed/
  )
})

test('ed25519, using disposes key', (t) => {
  let key

  {
    using privateKey = crypto.generateKeyPair('ed25519').privateKey

    key = privateKey
    t.ok(key.export().some((b) => b !== 0))
  }

  t.is(key.destroyed, true)
})
