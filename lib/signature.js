const assert = require('bare-assert')
const binding = require('../binding')
const { Key } = require('./key')
const constants = require('./constants')

const {
  keyType: { ED25519 }
} = constants

exports.sign = function sign(algorithm, data, key) {
  assert(Buffer.isBuffer(data) || data instanceof ArrayBuffer || ArrayBuffer.isView(data))

  if (ArrayBuffer.isView(data)) {
    data = Buffer.coerce(data)
  } else {
    data = Buffer.from(data)
  }

  assert(key instanceof Key)

  switch (key._keyType) {
    case ED25519:
      return Buffer.from(
        binding.ed25519Sign(data.buffer, data.byteOffset, data.byteLength, key._key)
      )
  }
}

exports.verify = function verify(algorithm, data, key, signature) {
  assert(Buffer.isBuffer(data) || data instanceof ArrayBuffer || ArrayBuffer.isView(data))

  if (ArrayBuffer.isView(data)) {
    data = Buffer.coerce(data)
  } else {
    data = Buffer.from(data)
  }

  assert(
    Buffer.isBuffer(signature) || signature instanceof ArrayBuffer || ArrayBuffer.isView(signature)
  )

  if (ArrayBuffer.isView(signature)) {
    signature = Buffer.coerce(signature)
  } else {
    signature = Buffer.from(signature)
  }

  assert(key instanceof Key)

  switch (key._keyType) {
    case ED25519:
      return binding.ed25519Verify(
        data.buffer,
        data.byteOffset,
        data.byteLength,
        signature.buffer,
        signature.byteOffset,
        key._key
      )
  }
}
