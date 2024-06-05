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
  t.plan(8)

  const len = 10
  const half = len / 2

  const testCase = (buf, type) => {
    crypto.randomFillSync(buf)

    const _arraybuffer = ArrayBuffer.isView(buf) ? buf.buffer : buf

    const firstHalf = Buffer.from(_arraybuffer.slice(0, half))
    const lastHalf = Buffer.from(_arraybuffer.slice(half))

    crypto.randomFillSync(buf, half) // randomize only the last half

    const _buffer = Buffer.from(_arraybuffer)

    t.is(_buffer.compare(firstHalf, 0, half, 0, half), 0, 'first half is equal - ' + type)
    t.not(_buffer.compare(lastHalf, 0, half, half), 0, 'last half is different - ' + type)
  }

  const buffer = Buffer.alloc(len)
  const arrayBuffer = new ArrayBuffer(len)
  const typedArray = new Uint8Array(len)
  const dataView = new DataView(new ArrayBuffer(len))

  testCase(buffer, 'Buffer')
  testCase(typedArray, 'TypedArray')
  testCase(dataView, 'DataView')
  testCase(arrayBuffer, 'ArrayBuffer')
})
