const test = require('brittle')
const crypto = require('..')

test('hash sha1', (t) => {
  t.is(
    crypto.createHash('sha1').update('foo bar').digest('hex'),
    '3773dea65156909838fa6c22825cafe090ff8030'
  )
})

test('hash ripemd160', (t) => {
  t.is(
    crypto.createHash('ripemd160').update('foo bar').digest('hex'),
    'daba326b8e276af34297f879f6234bcef2528efa'
  )
})

test('hash double digest should not crash', (t) => {
  const hash = crypto.createHash('sha256')
  hash.update('hello')
  hash.digest()

  t.exception(() => hash.digest(), 'calling digest() twice should throw, not crash')
})

test('hash, type guards', (t) => {
  t.plan(3)

  t.exception(() => crypto.createHash(NaN), /AssertionError/)

  t.exception(() => crypto.createHash('sha1').update(NaN), /AssertionError/)
  t.exception(() => crypto.createHash('ripemd160').update(NaN), /AssertionError/)
})
