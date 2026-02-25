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

test('cipheriv aes-256-cbc, large input', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const iv = Buffer.alloc(16, 'vector')

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)

  t.alike(
    cipher.update('hello world'.repeat(10)),
    Buffer.from([
      0xd1, 0x0, 0x51, 0xcf, 0x1d, 0x39, 0x31, 0x2, 0xaf, 0xd8, 0x8d, 0x80, 0x84, 0x20, 0xfa, 0x62,
      0xfe, 0x9b, 0x3f, 0xc3, 0x4a, 0x43, 0xa8, 0x93, 0xaf, 0x78, 0x35, 0x2e, 0xd4, 0xbf, 0xdf,
      0xbc, 0xea, 0xe9, 0x6, 0x98, 0x82, 0x2e, 0x2f, 0x3d, 0x98, 0x75, 0x96, 0x8d, 0x55, 0x6f, 0x5c,
      0x26, 0xd6, 0x6, 0xee, 0xa2, 0x34, 0x1b, 0xeb, 0x49, 0x4c, 0x56, 0xe, 0x7e, 0x7e, 0x17, 0xec,
      0x22, 0xfc, 0x40, 0x29, 0x5d, 0xc, 0x67, 0x1e, 0x50, 0xbd, 0xb4, 0x6d, 0x5a, 0x8a, 0xfd, 0x1a,
      0x6c, 0x9f, 0x1a, 0x1d, 0xa0, 0x16, 0x33, 0xef, 0xf4, 0x9a, 0xe2, 0xac, 0x22, 0x9a, 0x51,
      0xbf, 0x90
    ])
  )
  t.alike(
    cipher.final(),
    Buffer.from([
      0x20, 0xaa, 0x29, 0xb0, 0x40, 0x7c, 0xbb, 0x0d, 0xfe, 0xca, 0xc6, 0x6c, 0xf6, 0x73, 0x48, 0x9e
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

test('cipheriv aes-256-gcm, double final should not crash', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

  cipher.update('hello world')
  cipher.final()

  t.exception(() => cipher.final(), 'calling final() twice should throw, not crash')
})

test('decipheriv aes-256-gcm, double final should not crash', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)
  cipher.update('hello world')
  const ciphertext = cipher.final()
  const authTag = cipher.getAuthTag()

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAuthTag(authTag)
  decipher.update(ciphertext)
  decipher.final()

  t.exception(() => decipher.final(), 'calling final() twice should throw, not crash')
})

test('cipheriv aes-256-cbc, double final should not crash', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const iv = Buffer.alloc(16, 'vector')

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  cipher.update('hello world')
  cipher.final()

  t.exception(() => cipher.final(), 'calling final() twice should throw, not crash')
})

test('decipheriv aes-256-cbc, double final should not crash', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const iv = Buffer.alloc(16, 'vector')

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  cipher.update('hello world')
  const ciphertext = cipher.final()

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
  decipher.update(ciphertext)
  decipher.final()

  t.exception(() => decipher.final(), 'calling final() twice should throw, not crash')
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

test('cipher, type guards', (t) => {
  t.plan(9)

  t.exception.all(() => crypto.createCipheriv(NaN), /TypeError/)
  t.exception.all(() => crypto.createDecipheriv(NaN), /TypeError/)

  t.exception(() => crypto.createCipheriv('aes-256-cbc', NaN, NaN), /AssertionError/)
  t.exception(() => crypto.createCipheriv('aes-256-gcm', NaN, NaN), /AssertionError/)

  t.exception(() => crypto.createDecipheriv('aes-256-gcm', NaN, NaN), /AssertionError/)

  t.exception(
    () => crypto.createCipheriv('aes-256-cbc', Buffer.alloc(32), Buffer.alloc(16)).update(NaN),
    /AssertionError/
  )

  t.exception(
    () => crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(16)).update(NaN),
    /AssertionError/
  )

  t.exception(
    () => crypto.createCipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(16)).setAAD(NaN),
    /AssertionError/
  )

  t.exception(
    () =>
      crypto.createDecipheriv('aes-256-gcm', Buffer.alloc(32), Buffer.alloc(16)).setAuthTag(NaN),
    /AssertionError/
  )
})
