const test = require('brittle')
const crypto = require('..')

test('timing safe equal, equal buffers', (t) => {
  const a = Buffer.from([1, 2, 3, 4])
  const b = Buffer.from([1, 2, 3, 4])

  t.is(crypto.timingSafeEqual(a, b), true)
})

test('timing safe equal, unequal buffers', (t) => {
  const a = Buffer.from([1, 2, 3, 4])
  const b = Buffer.from([1, 2, 3, 5])

  t.is(crypto.timingSafeEqual(a, b), false)
})

test('timing safe equal, empty buffers', (t) => {
  t.is(crypto.timingSafeEqual(Buffer.alloc(0), Buffer.alloc(0)), true)
})

test('timing safe equal, length mismatch throws', (t) => {
  const a = Buffer.from([1, 2, 3])
  const b = Buffer.from([1, 2, 3, 4])

  t.exception.all(() => crypto.timingSafeEqual(a, b))
})

test('timing safe equal, arraybuffer', (t) => {
  const a = new Uint8Array([1, 2, 3, 4]).buffer
  const b = new Uint8Array([1, 2, 3, 4]).buffer

  t.is(crypto.timingSafeEqual(a, b), true)
})

test('timing safe equal, subarray honors byte offset', (t) => {
  const a = Buffer.from([0, 0, 1, 2, 3, 4]).subarray(2)
  const b = Buffer.from([9, 9, 9, 1, 2, 3, 4]).subarray(3)

  t.is(crypto.timingSafeEqual(a, b), true)
})

test('timing safe equal, mixed view types', (t) => {
  const ab = new Uint8Array([1, 2, 3, 4]).buffer
  const view = new DataView(ab)
  const u8 = new Uint8Array([1, 2, 3, 4])

  t.is(crypto.timingSafeEqual(view, u8), true)
})

test('timing safe equal, type guards', (t) => {
  t.exception(() => crypto.timingSafeEqual('abcd', Buffer.from('abcd')), /AssertionError/)

  t.exception(() => crypto.timingSafeEqual(Buffer.from('abcd'), 'abcd'), /AssertionError/)
})
