const test = require('brittle')
const crypto = require('.')

test('hash sha1', (t) => {
  t.is(
    crypto.createHash('sha1')
      .update('foo bar')
      .digest('hex'),
    '3773dea65156909838fa6c22825cafe090ff8030'
  )
})

test('random bytes', (t) => {
  t.is(crypto.randomBytes(0).byteLength, 0)
  t.is(crypto.randomBytes(2).byteLength, 2)
  t.is(crypto.randomBytes(4).byteLength, 4)
})

test('randomFillSync', (t) => {
  const len = 40
  const half = len / 2

  const buf = Buffer.alloc(len)

  crypto.randomFillSync(buf)

  const firstHalf = Buffer.alloc(half)
  buf.copy(firstHalf)

  const lastHalf = Buffer.alloc(half)
  buf.copy(lastHalf, 0, half)

  // randomize only the last half
  crypto.randomFillSync(buf, half)

  t.is(buf.compare(firstHalf, 0, half, 0, half), 0, 'first half is equal')
  t.not(buf.compare(lastHalf, 0, half, half), 0, 'last half is different')
})
