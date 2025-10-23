const test = require('brittle')
const { webcrypto } = require('..')

test('subtle, generateKey hmac', async (t) => {
  const key = await webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  t.is(key.type, 'secret')
  t.is(key.extractable, true)
  t.alike(key.algorithm, {
    name: 'HMAC',
    length: 256,
    hash: { name: 'SHA-256' }
  })
  t.alike(key.usages, ['sign'])
})

test('subtle, generateKey ed25519', async (t) => {
  const key = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])

  const { privateKey, publicKey } = key

  t.test('privateKey', (t) => {
    t.is(privateKey.type, 'private')
    t.is(privateKey.extractable, false)
    t.alike(privateKey.algorithm, { name: 'Ed25519' })
    t.alike(privateKey.usages, ['sign'])
  })

  t.test('publicKey', (t) => {
    t.is(publicKey.type, 'public')
    t.is(publicKey.extractable, true)
    t.alike(publicKey.algorithm, { name: 'Ed25519' })
    t.alike(publicKey.usages, ['verify'])
  })
})

test('subtle, importKey hmac + exportKey raw', async (t) => {
  const key = await webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  const exportedKey = await webcrypto.subtle.exportKey('raw', key)

  t.is(exportedKey.byteLength, 32)

  const importedKey = await webcrypto.subtle.importKey(
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

test('subtle, importKey ed25519 + exportKey raw', async (t) => {
  const key = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])

  const exportedKey = await webcrypto.subtle.exportKey('raw', key.publicKey)

  t.is(exportedKey.byteLength, 32)

  const importedKey = await webcrypto.subtle.importKey(
    'raw',
    exportedKey,
    { name: 'Ed25519' },
    false,
    ['verify']
  )

  t.is(importedKey.type, 'public')
  t.is(importedKey.extractable, false)
  t.alike(importedKey.algorithm, { name: 'Ed25519' })
  t.alike(importedKey.usages, ['verify'])
})

test('subtle, importKey hmac + exportKey jwk', async (t) => {
  const key = await webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['verify']
  )

  const exportedJwk = await webcrypto.subtle.exportKey('jwk', key)

  t.test('exported jwk', (t) => {
    t.is(exportedJwk.kty, 'oct')
    t.is(exportedJwk.alg, 'HS256')
    t.ok(exportedJwk.k)
    t.alike(exportedJwk.key_ops, ['verify'])
    t.is(exportedJwk.ext, true)
  })

  const importedKey = await webcrypto.subtle.importKey(
    'jwk',
    exportedJwk,
    { name: 'HMAC', hash: 'SHA-256' },
    true,
    ['verify']
  )

  t.test('imported key from jwk', (t) => {
    t.is(importedKey.type, 'secret')
    t.is(importedKey.extractable, true)
    t.alike(importedKey.algorithm, {
      name: 'HMAC',
      length: 256,
      hash: { name: 'SHA-256' }
    })
    t.alike(importedKey.usages, ['verify'])
  })
})

test('subtle, importKey ed25519 + exportKey jwk, public key', async (t) => {
  const key = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])

  const exportedJwk = await webcrypto.subtle.exportKey('jwk', key.publicKey)

  t.test('exported jwk', (t) => {
    t.is(exportedJwk.kty, 'OKP')
    t.is(exportedJwk.alg, 'Ed25519')
    t.is(exportedJwk.crv, 'Ed25519')
    t.ok(exportedJwk.x)
    t.alike(exportedJwk.key_ops, ['verify'])
    t.is(exportedJwk.ext, true)
  })

  const importedKey = await webcrypto.subtle.importKey(
    'jwk',
    exportedJwk,
    { name: 'Ed25519' },
    true,
    ['verify']
  )

  t.test('imported key from jwk', (t) => {
    t.is(importedKey.type, 'public')
    t.is(importedKey.extractable, true)
    t.alike(importedKey.algorithm, { name: 'Ed25519' })
    t.alike(importedKey.usages, ['verify'])
  })
})

test('subtle, importKey ed25519 + exportKey jwk, private key', async (t) => {
  const key = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])

  const exportedJwk = await webcrypto.subtle.exportKey('jwk', key.privateKey)

  t.test('exported jwk', (t) => {
    t.is(exportedJwk.kty, 'OKP')
    t.is(exportedJwk.alg, 'Ed25519')
    t.is(exportedJwk.crv, 'Ed25519')
    t.ok(exportedJwk.x)
    t.alike(exportedJwk.key_ops, ['sign'])
    t.is(exportedJwk.ext, true)
  })

  const importedKey = await webcrypto.subtle.importKey(
    'jwk',
    exportedJwk,
    { name: 'Ed25519' },
    true,
    ['sign']
  )

  t.test('imported key from jwk', (t) => {
    t.is(importedKey.type, 'private')
    t.is(importedKey.extractable, true)
    t.alike(importedKey.algorithm, { name: 'Ed25519' })
    t.alike(importedKey.usages, ['sign'])
  })
})

test('subtle, importKey ed25519 + exportKey spki', async (t) => {
  const key = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign'])

  const encodedData = await webcrypto.subtle.exportKey('spki', key.publicKey)

  t.is(encodedData.byteLength, 44)

  const importedKey = await webcrypto.subtle.importKey(
    'spki',
    encodedData,
    { name: 'Ed25519' },
    true,
    ['verify']
  )

  t.test('imported key from spki encoded data', (t) => {
    t.is(importedKey.type, 'public')
    t.is(importedKey.extractable, true)
    t.alike(importedKey.algorithm, { name: 'Ed25519' })
    t.alike(importedKey.usages, ['verify'])
  })
})

test('subtle, importKey ed25519 + exportKey pkcs8', async (t) => {
  const key = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign'])

  const encodedData = await webcrypto.subtle.exportKey('pkcs8', key.privateKey)

  t.is(encodedData.byteLength, 48)

  const importedKey = await webcrypto.subtle.importKey(
    'pkcs8',
    encodedData,
    { name: 'Ed25519' },
    true,
    ['sign']
  )

  t.test('imported key from pkcs8 encoded data', (t) => {
    t.is(importedKey.type, 'private')
    t.is(importedKey.extractable, true)
    t.alike(importedKey.algorithm, { name: 'Ed25519' })
    t.alike(importedKey.usages, ['sign'])
  })
})

test('subtle, importKey pbkdf2 + exportKey raw', async (t) => {
  const key = await webcrypto.subtle.importKey('raw', Buffer.from('secret'), 'PBKDF2', false, [
    'deriveKey',
    'deriveBits'
  ])

  t.is(key.type, 'secret')
  t.is(key.extractable, false)
  t.alike(key.algorithm, { name: 'PBKDF2' })
  t.alike(key.usages, ['deriveKey', 'deriveBits'])

  await t.exception(async () => webcrypto.subtle.exportKey('raw', key), /INVALID_ACCESS/)
})

test('subtle, sign + verify hmac', async (t) => {
  const key = await webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign', 'verify']
  )

  const data = Buffer.from('hello world')

  const signature = await webcrypto.subtle.sign('HMAC', key, data)

  t.is(signature.byteLength, 32)

  const verified = await webcrypto.subtle.verify('HMAC', key, signature, data)

  t.is(verified, true)
})

test('subtle, sign + verify ed25519', async (t) => {
  const key = await webcrypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])

  const data = Buffer.from('hello world')

  const signature = await webcrypto.subtle.sign('Ed25519', key.privateKey, data)

  t.is(signature.byteLength, 64)

  const verified = await webcrypto.subtle.verify('Ed25519', key.publicKey, signature, data)

  t.is(verified, true)
})

test('subtle, verify hmac, different keys', async (t) => {
  const signerKey = await webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  )

  const verifierKey = await webcrypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['verify']
  )

  const data = Buffer.from('hello world')

  const signature = await webcrypto.subtle.sign('HMAC', signerKey, data)

  const verified = await webcrypto.subtle.verify('HMAC', verifierKey, signature, data)

  t.is(verified, false)
})

test('subtle, deriveBits pbkdf2', async (t) => {
  const key = await webcrypto.subtle.importKey('raw', Buffer.from('secret'), 'PBKDF2', false, [
    'deriveBits'
  ])

  const algorithm = {
    name: 'PBKDF2',
    hash: 'SHA-512',
    salt: Buffer.from('salt'),
    iterations: 1000
  }

  const bits = await webcrypto.subtle.deriveBits(algorithm, key, 256)

  t.is(
    Buffer.from(bits).toString('hex'),
    'f76f72381b75f0deb1c339334a8c8974366cadbc6bf46460f978363de8d210db'
  )
})

test('subtle, deriveKey pbkdf2', async (t) => {
  const key = await webcrypto.subtle.importKey('raw', Buffer.from('secret'), 'PBKDF2', false, [
    'deriveKey'
  ])

  const algorithm = {
    name: 'PBKDF2',
    hash: 'SHA-512',
    salt: Buffer.from('salt'),
    iterations: 1000
  }

  const derivedKey = await webcrypto.subtle.deriveKey(
    algorithm,
    key,
    { name: 'HMAC', hash: 'SHA-512' },
    true,
    ['sign']
  )

  t.is(derivedKey.type, 'secret')
  t.is(derivedKey.extractable, true)
  t.alike(derivedKey.algorithm, {
    name: 'HMAC',
    length: 1024,
    hash: { name: 'SHA-512' }
  })
  t.alike(derivedKey.usages, ['sign'])
})

test('subtle, digest sha256', async (t) => {
  const digest = await webcrypto.subtle.digest('SHA-256', Buffer.from('hello world'))

  t.alike(
    Buffer.from(digest).toString('hex'),
    'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
  )
})
