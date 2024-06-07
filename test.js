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

test('random fill', (t) => {
  t.test('buffer', (t) => {
    const b = Buffer.alloc(4)

    crypto.randomFillSync(b, 1, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[3], 0)
  })

  t.test('buffer, subarray', (t) => {
    const b = Buffer.alloc(8)

    crypto.randomFillSync(b.subarray(2, 6), 1, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[1], 0)
    t.is(b[2], 0)
    t.is(b[5], 0)
    t.is(b[6], 0)
    t.is(b[7], 0)
  })

  t.test('buffer, negative offset', (t) => {
    const b = Buffer.alloc(4)

    t.exception.all(() => crypto.randomFillSync(b.subarray(1, 3), -1, 2))
  })

  t.test('buffer, negative size', (t) => {
    const b = Buffer.alloc(4)

    t.exception.all(() => crypto.randomFillSync(b.subarray(1, 3), 0, -2))
  })

  t.test('buffer, size out of bounds', (t) => {
    const b = Buffer.alloc(4)

    t.exception.all(() => crypto.randomFillSync(b.subarray(1, 3), 0, 3))
  })

  t.test('buffer, offset + size out of bounds', (t) => {
    const b = Buffer.alloc(4)

    t.exception.all(() => crypto.randomFillSync(b.subarray(1, 3), 1, 2))
  })

  t.test('arraybuffer', (t) => {
    const b = new ArrayBuffer(4)

    crypto.randomFillSync(b, 1, 2)

    t.comment(b)

    const v = Buffer.from(b)

    t.is(v[0], 0)
    t.is(v[3], 0)
  })

  t.test('arraybuffer, negative offset', (t) => {
    const b = new ArrayBuffer(2)

    t.exception.all(() => crypto.randomFillSync(b, -1, 2))
  })

  t.test('arraybuffer, negative size', (t) => {
    const b = new ArrayBuffer(2)

    t.exception.all(() => crypto.randomFillSync(b, 0, -2))
  })

  t.test('arraybuffer, size out of bounds', (t) => {
    const b = new ArrayBuffer(2)

    t.exception.all(() => crypto.randomFillSync(b, 0, 3))
  })

  t.test('arraybuffer, offset + size out of bounds', (t) => {
    const b = new ArrayBuffer(2)

    t.exception.all(() => crypto.randomFillSync(b, 1, 2))
  })

  t.test('uint16array', (t) => {
    const b = new Uint16Array(4)

    crypto.randomFillSync(b, 1, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[3], 0)
  })

  t.test('uint16array, subarray', (t) => {
    const b = new Uint16Array(8)

    crypto.randomFillSync(b.subarray(2, 6), 1, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[1], 0)
    t.is(b[2], 0)
    t.is(b[5], 0)
    t.is(b[6], 0)
    t.is(b[7], 0)
  })

  t.test('uint16array, size out of bounds', (t) => {
    const b = new Uint16Array(4)

    t.exception.all(() => crypto.randomFillSync(b.subarray(1, 3), 0, 3))
  })

  t.test('uint16array, offset + size out of bounds', (t) => {
    const b = new Uint16Array(4)

    t.exception.all(() => crypto.randomFillSync(b.subarray(1, 3), 1, 2))
  })

  t.test('uint32array, default size', (t) => {
    const b = new Uint32Array(4)

    crypto.randomFillSync(b, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[1], 0)
  })

  t.test('uint32array, subarray', (t) => {
    const b = new Uint32Array(8)

    crypto.randomFillSync(b.subarray(2, 6), 1, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[1], 0)
    t.is(b[2], 0)
    t.is(b[5], 0)
    t.is(b[6], 0)
    t.is(b[7], 0)
  })

  t.test('uint32array, size out of bounds', (t) => {
    const b = new Uint32Array(4)

    t.exception.all(() => crypto.randomFillSync(b.subarray(1, 3), 0, 3))
  })

  t.test('uint32array, offset + size out of bounds', (t) => {
    const b = new Uint32Array(4)

    t.exception.all(() => crypto.randomFillSync(b.subarray(1, 3), 1, 2))
  })

  t.test('dataview', (t) => {
    const b = new DataView(new ArrayBuffer(4))

    crypto.randomFillSync(b, 1, 2)

    t.comment(b)

    t.is(b.getUint8(0), 0)
    t.is(b.getUint8(3), 0)
  })

  t.test('dataview, subarray', (t) => {
    const b = new ArrayBuffer(8)

    crypto.randomFillSync(new DataView(b, 2, 4), 1, 2)

    t.comment(b)

    const v = Buffer.from(b)

    t.is(v[0], 0)
    t.is(v[1], 0)
    t.is(v[2], 0)
    t.is(v[5], 0)
    t.is(v[6], 0)
    t.is(v[7], 0)
  })
})
