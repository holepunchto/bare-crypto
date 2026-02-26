const test = require('brittle')
const crypto = require('..')

test('pbkdf2', (t) => {
  t.is(
    crypto.pbkdf2('secret', 'salt', 100000, 64, 'sha512').toString('hex'),
    '3745e482c6e0ade35da10139e797157f4a5da669dad7d5da88ef87e47471cc47ed941c7ad618e827304f083f8707f12b7cfdd5f489b782f10cc269e3c08d59ae'
  )
})

test('pbkdf2, type guards', (t) => {
  t.plan(5)

  t.exception(() => crypto.pbkdf2(NaN, 'salt', 100000, 64, 'sha512'), /AssertionError/)

  t.exception(() => crypto.pbkdf2('secret', NaN, 100000, 64, 'sha512'), /AssertionError/)

  t.exception(() => crypto.pbkdf2('secret', 'salt', NaN, 64, 'sha512'), /AssertionError/)

  t.exception(() => crypto.pbkdf2('secret', 'salt', 100000, NaN, 'sha512'), /AssertionError/)

  t.exception(() => crypto.pbkdf2('secret', 'salt', 100000, 64, NaN), /AssertionError/)
})
