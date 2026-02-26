const test = require('brittle')
const crypto = require('..')

test('sign + verify, ed25519', (t) => {
  const { publicKey, privateKey } = crypto.generateKeyPair('ed25519')

  const signature = crypto.sign(null, Buffer.from('message'), privateKey)

  t.is(crypto.verify(null, Buffer.from('message'), publicKey, signature), true)

  t.is(crypto.verify(null, Buffer.from('other message'), publicKey, signature), false)
})

test('verify ed25519, empty signature should not crash', (t) => {
  const { publicKey } = crypto.generateKeyPair('ed25519')

  t.is(crypto.verify(null, Buffer.from('message'), publicKey, Buffer.alloc(0)), false)
})

test('verify ed25519, signature shorter than 64 bytes should not crash', (t) => {
  const { publicKey } = crypto.generateKeyPair('ed25519')

  t.is(crypto.verify(null, Buffer.from('message'), publicKey, Buffer.alloc(32)), false)
})

test('verify ed25519, signature longer than 64 bytes should not crash', (t) => {
  const { publicKey } = crypto.generateKeyPair('ed25519')

  t.is(crypto.verify(null, Buffer.from('message'), publicKey, Buffer.alloc(96)), false)
})
