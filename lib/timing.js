const assert = require('bare-assert')
const binding = require('../binding')

exports.timingSafeEqual = function timingSafeEqual(a, b) {
  assert(a instanceof ArrayBuffer || ArrayBuffer.isView(a))
  assert(b instanceof ArrayBuffer || ArrayBuffer.isView(b))

  let aBuffer, aOffset
  if (ArrayBuffer.isView(a)) {
    aBuffer = a.buffer
    aOffset = a.byteOffset
  } else {
    aBuffer = a
    aOffset = 0
  }

  let bBuffer, bOffset
  if (ArrayBuffer.isView(b)) {
    bBuffer = b.buffer
    bOffset = b.byteOffset
  } else {
    bBuffer = b
    bOffset = 0
  }

  return binding.timingSafeEqual(aBuffer, aOffset, a.byteLength, bBuffer, bOffset, b.byteLength)
}
