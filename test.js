const test = require('brittle')
const crypto = require('.')

test('hash sha1', (t) => {
  t.is(
    crypto.createHash('sha1').update('foo bar').digest('hex'),
    '3773dea65156909838fa6c22825cafe090ff8030'
  )
})

test('hmac sha1', (t) => {
  t.is(
    crypto.createHmac('sha1', 'secret key').update('foo bar').digest('hex'),
    '53497cb818cd33297778b3437cf20890eab27ae2'
  )
})

test('cipheriv aes-256-cbc', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const iv = Buffer.alloc(16, 'vector')

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)

  t.alike(cipher.update('hello world'), Buffer.alloc(0))
  t.alike(
    cipher.final(),
    Buffer.from([
      0xcf, 0xd3, 0x88, 0x0b, 0x6b, 0x4c, 0xa4, 0xd2, 0x9f, 0x1d, 0x76, 0xed,
      0xa0, 0x0d, 0x91, 0x13
    ])
  )
})

test('cipheriv aes-256-gcm', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

  t.alike(cipher.update('hello world'), Buffer.alloc(0))
  t.alike(
    cipher.final(),
    Buffer.from([
      0xf7, 0x5a, 0x18, 0xd3, 0xd5, 0x5a, 0xb6, 0xeb, 0x84, 0x10, 0x12
    ])
  )
  t.alike(
    cipher.getAuthTag(),
    Buffer.from([
      0x32, 0xfd, 0x47, 0xd6, 0xd3, 0x10, 0x5a, 0x40, 0x33, 0x16, 0x6d, 0xfa,
      0xec, 0x8f, 0xe8, 0xd5
    ])
  )
})

test('cipheriv aes-256-gcm, additional data', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

  cipher.setAAD('additional data')

  t.alike(cipher.update('hello world'), Buffer.alloc(0))
  t.alike(
    cipher.final(),
    Buffer.from([
      0xf7, 0x5a, 0x18, 0xd3, 0xd5, 0x5a, 0xb6, 0xeb, 0x84, 0x10, 0x12
    ])
  )
  t.alike(
    cipher.getAuthTag(),
    Buffer.from([
      0xcb, 0xa9, 0x2a, 0x39, 0x7f, 0x98, 0x51, 0x64, 0x33, 0x41, 0x6a, 0x91,
      0x0f, 0xc4, 0x1f, 0x16
    ])
  )
})

test('cipheriv aes-256-gcm, larger nonce', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(16, 'vector')

  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce)

  t.alike(cipher.update('hello world'), Buffer.alloc(0))
  t.alike(
    cipher.final(),
    Buffer.from([
      0x0d, 0xac, 0x88, 0x8a, 0x76, 0x58, 0xc6, 0x76, 0x12, 0x9b, 0x6a
    ])
  )
  t.alike(
    cipher.getAuthTag(),
    Buffer.from([
      0xfb, 0x3f, 0x45, 0xfe, 0xe8, 0x03, 0xfd, 0x51, 0xb1, 0xf2, 0xa7, 0x96,
      0x0a, 0x06, 0xaa, 0x9a
    ])
  )
})

test('decipheriv aes-256-cbc', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const iv = Buffer.alloc(16, 'vector')

  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv)

  t.alike(
    decipher.update(
      Buffer.from([
        0xcf, 0xd3, 0x88, 0x0b, 0x6b, 0x4c, 0xa4, 0xd2, 0x9f, 0x1d, 0x76, 0xed,
        0xa0, 0x0d, 0x91, 0x13
      ])
    ),
    Buffer.alloc(0)
  )
  t.alike(decipher.final(), Buffer.from('hello world'))
})

test('decipheriv aes-256-gcm', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)

  decipher.setAuthTag(
    Buffer.from([
      0x32, 0xfd, 0x47, 0xd6, 0xd3, 0x10, 0x5a, 0x40, 0x33, 0x16, 0x6d, 0xfa,
      0xec, 0x8f, 0xe8, 0xd5
    ])
  )

  t.alike(
    decipher.update(
      Buffer.from([
        0xf7, 0x5a, 0x18, 0xd3, 0xd5, 0x5a, 0xb6, 0xeb, 0x84, 0x10, 0x12
      ])
    ),
    Buffer.alloc(0)
  )
  t.alike(decipher.final(), Buffer.from('hello world'))
})

test('decipheriv aes-256-gcm, additional data', (t) => {
  const key = Buffer.alloc(32, 'secret key')
  const nonce = Buffer.alloc(12, 'vector')

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce)

  decipher.setAAD('additional data')

  decipher.setAuthTag(
    Buffer.from([
      0xcb, 0xa9, 0x2a, 0x39, 0x7f, 0x98, 0x51, 0x64, 0x33, 0x41, 0x6a, 0x91,
      0x0f, 0xc4, 0x1f, 0x16
    ])
  )

  t.alike(
    decipher.update(
      Buffer.from([
        0xf7, 0x5a, 0x18, 0xd3, 0xd5, 0x5a, 0xb6, 0xeb, 0x84, 0x10, 0x12
      ])
    ),
    Buffer.alloc(0)
  )
  t.alike(decipher.final(), Buffer.from('hello world'))
})

test('random bytes', (t) => {
  t.is(crypto.randomBytes(0).byteLength, 0)
  t.is(crypto.randomBytes(2).byteLength, 2)
  t.is(crypto.randomBytes(4).byteLength, 4)
})

test('random fill', (t) => {
  t.test('buffer', (t) => {
    const b = Buffer.alloc(4)

    crypto.randomFill(b, 1, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[3], 0)
  })

  t.test('buffer, subarray', (t) => {
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

  t.test('buffer, negative offset', (t) => {
    const b = Buffer.alloc(4)

    t.exception.all(() => crypto.randomFill(b.subarray(1, 3), -1, 2))
  })

  t.test('buffer, negative size', (t) => {
    const b = Buffer.alloc(4)

    t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 0, -2))
  })

  t.test('buffer, size out of bounds', (t) => {
    const b = Buffer.alloc(4)

    t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 0, 3))
  })

  t.test('buffer, offset + size out of bounds', (t) => {
    const b = Buffer.alloc(4)

    t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 1, 2))
  })

  t.test('arraybuffer', (t) => {
    const b = new ArrayBuffer(4)

    crypto.randomFill(b, 1, 2)

    t.comment(b)

    const v = Buffer.from(b)

    t.is(v[0], 0)
    t.is(v[3], 0)
  })

  t.test('arraybuffer, negative offset', (t) => {
    const b = new ArrayBuffer(2)

    t.exception.all(() => crypto.randomFill(b, -1, 2))
  })

  t.test('arraybuffer, negative size', (t) => {
    const b = new ArrayBuffer(2)

    t.exception.all(() => crypto.randomFill(b, 0, -2))
  })

  t.test('arraybuffer, size out of bounds', (t) => {
    const b = new ArrayBuffer(2)

    t.exception.all(() => crypto.randomFill(b, 0, 3))
  })

  t.test('arraybuffer, offset + size out of bounds', (t) => {
    const b = new ArrayBuffer(2)

    t.exception.all(() => crypto.randomFill(b, 1, 2))
  })

  t.test('uint16array', (t) => {
    const b = new Uint16Array(4)

    crypto.randomFill(b, 1, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[3], 0)
  })

  t.test('uint16array, subarray', (t) => {
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

  t.test('uint16array, size out of bounds', (t) => {
    const b = new Uint16Array(4)

    t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 0, 3))
  })

  t.test('uint16array, offset + size out of bounds', (t) => {
    const b = new Uint16Array(4)

    t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 1, 2))
  })

  t.test('uint32array, default size', (t) => {
    const b = new Uint32Array(4)

    crypto.randomFill(b, 2)

    t.comment(b)

    t.is(b[0], 0)
    t.is(b[1], 0)
  })

  t.test('uint32array, subarray', (t) => {
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

  t.test('uint32array, size out of bounds', (t) => {
    const b = new Uint32Array(4)

    t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 0, 3))
  })

  t.test('uint32array, offset + size out of bounds', (t) => {
    const b = new Uint32Array(4)

    t.exception.all(() => crypto.randomFill(b.subarray(1, 3), 1, 2))
  })

  t.test('dataview', (t) => {
    const b = new DataView(new ArrayBuffer(4))

    crypto.randomFill(b, 1, 2)

    t.comment(b)

    t.is(b.getUint8(0), 0)
    t.is(b.getUint8(3), 0)
  })

  t.test('dataview, subarray', (t) => {
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
})

test('pbkdf2', (t) => {
  t.is(
    crypto.pbkdf2('secret', 'salt', 100000, 64, 'sha512').toString('hex'),
    '3745e482c6e0ade35da10139e797157f4a5da669dad7d5da88ef87e47471cc47ed941c7ad618e827304f083f8707f12b7cfdd5f489b782f10cc269e3c08d59ae'
  )
})

test('generateKey', async (t) => {
  const key = await crypto.webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  t.test('generateKey', (t) => {
    t.is(key.type, 'secret')
    t.is(key.extractable, true)
    t.alike(key.algorithm, {
      name: 'HMAC',
      length: 256,
      hash: { name: 'SHA-256' }
    })
    t.alike(key.usages, ['sign'])
  })
})

test('HMAC - importKey + exportKey', async (t) => {
  const key = await crypto.webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  const exportedKey = await crypto.webcrypto.subtle.exportKey('raw', key)

  t.is(exportedKey.byteLength, 32)

  const importedKey = await crypto.webcrypto.subtle.importKey(
    'raw',
    exportedKey,
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['sign']
  )

  t.is(importedKey.type, 'secret')
  t.is(importedKey.extractable, true)
  t.alike(importedKey.algorithm, {
    name: 'HMAC',
    length: 256,
    hash: { name: 'SHA-256' }
  })
  t.alike(importedKey.usages, ['sign'])
})

test('PBKDF2 - importKey + exportKey', async (t) => {
  const key = await crypto.webcrypto.subtle.importKey(
    'raw',
    Buffer.from('secret'),
    'PBKDF2',
    false,
    ['deriveKey', 'deriveBits']
  )

  t.is(key.type, 'secret')
  t.is(key.extractable, false)
  t.alike(key.algorithm, { name: 'PBKDF2' })
  t.alike(key.usages, ['deriveKey', 'deriveBits'])

  await t.exception(
    async () => crypto.webcrypto.subtle.exportKey('raw', key),
    /INVALID_ACCESS/
  )
})

test('sign + verify', async (t) => {
  const key = await crypto.webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign', 'verify']
  )

  const data = Buffer.from('hello world')

  const signature = await crypto.webcrypto.subtle.sign('HMAC', key, data)

  t.is(signature.byteLength, 32)

  let verified = await crypto.webcrypto.subtle.verify(
    'HMAC',
    key,
    signature,
    data
  )

  t.is(verified, true)
})

test('verify - different keys', async (t) => {
  const signerKey = await crypto.webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  const verifierKey = await crypto.webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['verify']
  )

  const data = Buffer.from('hello world')

  const signature = await crypto.webcrypto.subtle.sign('HMAC', signerKey, data)

  const verified = await crypto.webcrypto.subtle.verify(
    'HMAC',
    verifierKey,
    signature,
    data
  )

  t.alike(verifierKey.usages, ['verify'])

  t.is(verified, false)
})

test('deriveBits', async (t) => {
  const key = await crypto.webcrypto.subtle.importKey(
    'raw',
    Buffer.from('secret'),
    'PBKDF2',
    false,
    ['deriveBits']
  )

  const algorithm = {
    name: 'PBKDF2',
    hash: 'SHA-512',
    salt: Buffer.from('salt'),
    iterations: 1000
  }

  const bits = await crypto.webcrypto.subtle.deriveBits(algorithm, key, 256)

  t.is(
    Buffer.from(bits).toString('hex'),
    'f76f72381b75f0deb1c339334a8c8974366cadbc6bf46460f978363de8d210db'
  )
})

test('deriveKey', async (t) => {
  const key = await crypto.webcrypto.subtle.importKey(
    'raw',
    Buffer.from('secret'),
    'PBKDF2',
    false,
    ['deriveKey']
  )

  const algorithm = {
    name: 'PBKDF2',
    hash: 'SHA-512',
    salt: Buffer.from('salt'),
    iterations: 1000
  }

  const derivedKey = await crypto.webcrypto.subtle.deriveKey(
    algorithm,
    key,
    { name: 'HMAC', hash: 'SHA-512' },
    true,
    ['sign']
  )

  t.alike(key.usages, ['deriveKey'])

  t.is(derivedKey.type, 'secret')
  t.is(derivedKey.extractable, true)
  t.alike(derivedKey.algorithm, {
    name: 'HMAC',
    length: 1024,
    hash: { name: 'SHA-512' }
  })
  t.alike(derivedKey.usages, ['sign'])
})
