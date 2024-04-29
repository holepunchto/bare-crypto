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
