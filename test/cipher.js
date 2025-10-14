const test = require('brittle')
const crypto = require('..')

test('cipheriv aes-256-cbc', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const iv = Buffer.alloc(16, 'vector')

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)

  t.alike(cipher.update('hello world'), Buffer.alloc(0))
  t.alike(
    cipher.final(),
    Buffer.from([
      0xcf, 0xd3, 0x88, 0x0b, 0x6b, 0x4c, 0xa4, 0xd2, 0x9f, 0x1d, 0x76, 0xed, 0xa0, 0x0d, 0x91, 0x13
    ])
  )
})

test('cipheriv aes-256-gcm', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

  t.alike(cipher.update('hello world'), Buffer.alloc(0))
  t.alike(
    cipher.final(),
    Buffer.from([0xf7, 0x5a, 0x18, 0xd3, 0xd5, 0x5a, 0xb6, 0xeb, 0x84, 0x10, 0x12])
  )
  t.alike(
    cipher.getAuthTag(),
    Buffer.from([
      0x32, 0xfd, 0x47, 0xd6, 0xd3, 0x10, 0x5a, 0x40, 0x33, 0x16, 0x6d, 0xfa, 0xec, 0x8f, 0xe8, 0xd5
    ])
  )
})

test('cipheriv aes-256-gcm, additional data', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

  cipher.setAAD('additional data')

  t.alike(cipher.update('hello world'), Buffer.alloc(0))
  t.alike(
    cipher.final(),
    Buffer.from([0xf7, 0x5a, 0x18, 0xd3, 0xd5, 0x5a, 0xb6, 0xeb, 0x84, 0x10, 0x12])
  )
  t.alike(
    cipher.getAuthTag(),
    Buffer.from([
      0xcb, 0xa9, 0x2a, 0x39, 0x7f, 0x98, 0x51, 0x64, 0x33, 0x41, 0x6a, 0x91, 0x0f, 0xc4, 0x1f, 0x16
    ])
  )
})

test('cipheriv aes-256-gcm, larger nonce', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(16, 'vector')

  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

  t.alike(cipher.update('hello world'), Buffer.alloc(0))
  t.alike(
    cipher.final(),
    Buffer.from([0x0d, 0xac, 0x88, 0x8a, 0x76, 0x58, 0xc6, 0x76, 0x12, 0x9b, 0x6a])
  )
  t.alike(
    cipher.getAuthTag(),
    Buffer.from([
      0xfb, 0x3f, 0x45, 0xfe, 0xe8, 0x03, 0xfd, 0x51, 0xb1, 0xf2, 0xa7, 0x96, 0x0a, 0x06, 0xaa, 0x9a
    ])
  )
})

test('decipheriv aes-256-cbc', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const iv = Buffer.alloc(16, 'vector')

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)

  t.alike(
    decipher.update(
      Buffer.from([
        0xcf, 0xd3, 0x88, 0x0b, 0x6b, 0x4c, 0xa4, 0xd2, 0x9f, 0x1d, 0x76, 0xed, 0xa0, 0x0d, 0x91,
        0x13
      ])
    ),
    Buffer.alloc(0)
  )
  t.alike(decipher.final(), Buffer.from('hello world'))
})

test('decipheriv aes-256-gcm', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)

  decipher.setAuthTag(
    Buffer.from([
      0x32, 0xfd, 0x47, 0xd6, 0xd3, 0x10, 0x5a, 0x40, 0x33, 0x16, 0x6d, 0xfa, 0xec, 0x8f, 0xe8, 0xd5
    ])
  )

  t.alike(
    decipher.update(
      Buffer.from([0xf7, 0x5a, 0x18, 0xd3, 0xd5, 0x5a, 0xb6, 0xeb, 0x84, 0x10, 0x12])
    ),
    Buffer.alloc(0)
  )
  t.alike(decipher.final(), Buffer.from('hello world'))
})

test('decipheriv aes-256-gcm, additional data', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)

  decipher.setAAD('additional data')

  decipher.setAuthTag(
    Buffer.from([
      0xcb, 0xa9, 0x2a, 0x39, 0x7f, 0x98, 0x51, 0x64, 0x33, 0x41, 0x6a, 0x91, 0x0f, 0xc4, 0x1f, 0x16
    ])
  )

  t.alike(
    decipher.update(
      Buffer.from([0xf7, 0x5a, 0x18, 0xd3, 0xd5, 0x5a, 0xb6, 0xeb, 0x84, 0x10, 0x12])
    ),
    Buffer.alloc(0)
  )
  t.alike(decipher.final(), Buffer.from('hello world'))
})
