const test = require('brittle')
const crypto = require('..')

test('hmac sha1', (t) => {
  t.is(
    crypto.createHmac('sha1', 'secret key').update('foo bar').digest('hex'),
    '53497cb818cd33297778b3437cf20890eab27ae2'
  )
})

test('hmac update after digest should not crash', (t) => {
  const hmac = crypto.createHmac('sha256', 'secret key')
  hmac.update('hello')
  hmac.digest()

  t.exception(
    () => hmac.update('more data'),
    'calling update() after digest() should throw, not crash'
  )
})

test('hmac double digest should not crash', (t) => {
  const hmac = crypto.createHmac('sha256', 'secret key')
  hmac.update('hello')
  hmac.digest()

  t.exception(() => hmac.digest(), 'calling digest() twice should throw, not crash')
})
