const test = require('brittle')
const crypto = require('..')

test('sign + verify, ed25519', (t) => {
  const { publicKey, privateKey } = crypto.generateKeyPair('ed25519')

  const signature = crypto.sign(null, Buffer.from('message'), privateKey)

  t.is(crypto.verify(null, Buffer.from('message'), publicKey, signature), true)

  t.is(crypto.verify(null, Buffer.from('other message'), publicKey, signature), false)
})
