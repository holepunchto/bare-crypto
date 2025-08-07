const test = require('brittle')
const crypto = require('..')

test('hmac sha1', (t) => {
  t.is(
    crypto.createHmac('sha1', 'secret key').update('foo bar').digest('hex'),
    '53497cb818cd33297778b3437cf20890eab27ae2'
  )
})
