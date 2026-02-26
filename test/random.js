const test = require('brittle')
const crypto = require('..')

test('random bytes', (t) => {
  t.is(crypto.randomBytes(0).byteLength, 0)
  t.is(crypto.randomBytes(2).byteLength, 2)
  t.is(crypto.randomBytes(4).byteLength, 4)
})

test('random fill', (t) => {
  const b = Buffer.alloc(4)

  crypto.randomFill(b, 1, 2)

  t.comment(b)

  t.is(b[0], 0)
  t.is(b[3], 0)
})

test('random fill, subarray', (t) => {
  const b = Buffer.alloc(8)

  crypto.randomFill(b.subarray(2, 6), 1, 2)

  t.comment(b)

  t.is(b[0], 0)
  t.is(b[1], 0)
  t.is(b[2], 0)
  t.is(b[5], 0)
  t.is(b[6], 0)
  t.is(b[7], 0)
})

test('random fill, negative offset', (t) => {
  const b = Buffer.alloc(4)

  t.exception.all(() => crypto.randomFill(b.subarray(1, 3), -1, 2))
})

test('random fill, negative size', (t) => {
  const b = Buffer.alloc(4)

  t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 0, -2))
})

test('random fill, size out of bounds', (t) => {
  const b = Buffer.alloc(4)

  t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 0, 3))
})

test('random fill, offset + size out of bounds', (t) => {
  const b = Buffer.alloc(4)

  t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 1, 2))
})

test('random fill, arraybuffer', (t) => {
  const b = new ArrayBuffer(4)

  crypto.randomFill(b, 1, 2)

  t.comment(b)

  const v = Buffer.from(b)

  t.is(v[0], 0)
  t.is(v[3], 0)
})

test('random fill, arraybuffer, negative offset', (t) => {
  const b = new ArrayBuffer(2)

  t.exception.all(() => crypto.randomFill(b, -1, 2))
})

test('random fill, arraybuffer, negative size', (t) => {
  const b = new ArrayBuffer(2)

  t.exception.all(() => crypto.randomFill(b, 0, -2))
})

test('random fill, arraybuffer, size out of bounds', (t) => {
  const b = new ArrayBuffer(2)

  t.exception.all(() => crypto.randomFill(b, 0, 3))
})

test('random fill, arraybuffer, offset + size out of bounds', (t) => {
  const b = new ArrayBuffer(2)

  t.exception.all(() => crypto.randomFill(b, 1, 2))
})

test('random fill, uint16array', (t) => {
  const b = new Uint16Array(4)

  crypto.randomFill(b, 1, 2)

  t.comment(b)

  t.is(b[0], 0)
  t.is(b[3], 0)
})

test('random fill, uint16array, subarray', (t) => {
  const b = new Uint16Array(8)

  crypto.randomFill(b.subarray(2, 6), 1, 2)

  t.comment(b)

  t.is(b[0], 0)
  t.is(b[1], 0)
  t.is(b[2], 0)
  t.is(b[5], 0)
  t.is(b[6], 0)
  t.is(b[7], 0)
})

test('random fill, uint16array, size out of bounds', (t) => {
  const b = new Uint16Array(4)

  t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 0, 3))
})

test('random fill, uint16array, offset + size out of bounds', (t) => {
  const b = new Uint16Array(4)

  t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 1, 2))
})

test('random fill, uint32array, default size', (t) => {
  const b = new Uint32Array(4)

  crypto.randomFill(b, 2)

  t.comment(b)

  t.is(b[0], 0)
  t.is(b[1], 0)
})

test('random fill, uint32array, subarray', (t) => {
  const b = new Uint32Array(8)

  crypto.randomFill(b.subarray(2, 6), 1, 2)

  t.comment(b)

  t.is(b[0], 0)
  t.is(b[1], 0)
  t.is(b[2], 0)
  t.is(b[5], 0)
  t.is(b[6], 0)
  t.is(b[7], 0)
})

test('random fill, uint32array, size out of bounds', (t) => {
  const b = new Uint32Array(4)

  t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 0, 3))
})

test('random fill, uint32array, offset + size out of bounds', (t) => {
  const b = new Uint32Array(4)

  t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 1, 2))
})

test('random fill, dataview', (t) => {
  const b = new DataView(new ArrayBuffer(4))

  crypto.randomFill(b, 1, 2)

  t.comment(b)

  t.is(b.getUint8(0), 0)
  t.is(b.getUint8(3), 0)
})

test('random fill, dataview, subarray', (t) => {
  const b = new ArrayBuffer(8)

  crypto.randomFill(new DataView(b, 2, 4), 1, 2)

  t.comment(b)

  const v = Buffer.from(b)

  t.is(v[0], 0)
  t.is(v[1], 0)
  t.is(v[2], 0)
  t.is(v[5], 0)
  t.is(v[6], 0)
  t.is(v[7], 0)
})

test('random uuid', (t) => {
  t.comment(crypto.randomUUID())
})

test('random, type guards', (t) => {
  t.exception(() => crypto.randomBytes(NaN), /AssertionError/)

  t.exception(() => crypto.randomFill(NaN, 1, 2), /AssertionError/)
  t.exception(() => crypto.randomFill(Buffer.alloc(1), NaN, 2), /AssertionError/)
  t.exception(() => crypto.randomFill(Buffer.alloc(1), 1, NaN), /AssertionError/)
})
