# bare-crypto

Cryptographic primitives for JavaScript.

```
npm i bare-crypto
```

## Usage

```js
const crypto = require('bare-crypto')

const hash = crypto.createHash('sha256')

hash.update('Hello, world!')

const digest = hash.digest('hex')

console.log(digest)
```

## API

#### `const hash = createHash(algorithm[, options])`

Create a new `Hash` instance with the specified `algorithm`. `algorithm` may be a string (e.g. `'sha256'`, `'sha-256'`) or a numeric constant from `constants.hash`. The `options` are forwarded to the `Transform` constructor from `bare-stream` (<https://github.com/holepunchto/bare-stream>).

### `class Hash`

Stream-based hash. Extends `Transform`.

#### `hash.update(data[, encoding])`

Push `data` into the hash. If `data` is a string, it is decoded using `encoding` (defaults to `'utf8'`). Returns the same `hash` for chaining. Throws once `digest()` has been called.

#### `const digest = hash.digest([encoding])`

Finalize the hash and return the digest. If `encoding` is provided (and is not `'buffer'`), the digest is returned as a string in that encoding; otherwise as a `Buffer`. Further calls to `update()` or `digest()` throw.

#### `const hmac = createHmac(algorithm, key[, options])`

Create a new `Hmac` instance using `algorithm` and `key`. `key` may be a string or `ArrayBufferView`. If `key` is a string, an `encoding` option (defaults to `'utf8'`) controls how it is decoded. The `options` are also forwarded to `Transform`.

### `class Hmac`

Stream-based HMAC. Extends `Transform`.

#### `hmac.update(data[, encoding])`

Push `data` into the HMAC. Same semantics as `hash.update()`.

#### `const digest = hmac.digest([encoding])`

Finalize the HMAC. Same semantics as `hash.digest()`.

#### `const cipher = createCipheriv(algorithm, key, iv[, options])`

Create a new `Cipheriv` instance using `algorithm`, `key`, and `iv` (initialization vector / nonce). `key` and `iv` must match the algorithm's required lengths. For AEAD algorithms (e.g. `AES128GCM`, `CHACHA20POLY1305`), the `options` may include an `authTagLength` (defaults to `16`).

Options include:

```js
options = {
  encoding: 'utf8',
  authTagLength: 16
}
```

`authTagLength` must be one of `12`, `14`, or `16`. The `options` are also forwarded to `Transform`.

### `class Cipheriv`

Stream-based encryption. Extends `Transform`.

#### `const result = cipher.update(data[, inputEncoding[, outputEncoding]])`

Encrypt a chunk. Returns a `Buffer`, or a string if `outputEncoding` is provided. For AEAD ciphers, encrypted output is delivered all at once from `final()`.

#### `const result = cipher.final([outputEncoding])`

Finalize encryption. For AEAD ciphers, the auth tag becomes available via `getAuthTag()` after this call.

#### `cipher.setAutoPadding(pad)`

Enable or disable automatic padding. Block ciphers only.

#### `cipher.setAAD(buffer[, options])`

Provide additional authenticated data. AEAD ciphers only. The `options` may include an `encoding` for string inputs.

#### `const tag = cipher.getAuthTag()`

Return the auth tag produced by `final()`. AEAD ciphers only.

#### `const decipher = createDecipheriv(algorithm, key, iv[, options])`

Create a new `Decipheriv` instance using `algorithm`, `key`, and `iv`. Accepts the same `options` as `createCipheriv`.

### `class Decipheriv`

Stream-based decryption. Extends `Transform`.

#### `const result = decipher.update(data[, inputEncoding[, outputEncoding]])`

Decrypt a chunk. Same semantics as `cipher.update()`.

#### `const result = decipher.final([outputEncoding])`

Finalize decryption. For AEAD ciphers, `setAuthTag()` must be called before `final()`.

#### `decipher.setAutoPadding(pad)`

Enable or disable automatic padding. Block ciphers only.

#### `decipher.setAAD(buffer[, options])`

Provide additional authenticated data. AEAD ciphers only.

#### `decipher.setAuthTag(authTag[, encoding])`

Set the expected auth tag prior to calling `final()`. AEAD ciphers only.

#### `const buffer = randomBytes(size)`

Generate `size` cryptographically secure random bytes.

#### `randomBytes(size, callback)`

Async variant. The callback signature is `callback(err, buffer)`.

#### `buffer = randomFill(buffer[, offset[, size]])`

Fill `buffer` with cryptographically secure random bytes, optionally restricted to `[offset, offset + size)`. `offset` defaults to `0` and `size` to `buffer.byteLength - offset`. Returns the same `buffer`.

#### `randomFill(buffer[, offset[, size]], callback)`

Async variant. The callback signature is `callback(err, buffer)`.

#### `buffer = randomFillSync(buffer[, offset[, size]])`

For Node.js compatibility; equivalent to `randomFill` without a callback.

#### `const uuid = randomUUID()`

Generate a random RFC 4122 version-4 UUID string.

#### `const buffer = pbkdf2(password, salt, iterations, keylen, digest)`

Derive a key from `password` and `salt` using the specified `digest` algorithm and number of `iterations`. Returns a `keylen`-byte `Buffer`. `password` and `salt` may be strings or `ArrayBufferView`s.

#### `pbkdf2(password, salt, iterations, keylen, digest, callback)`

Async variant. The callback signature is `callback(err, buffer)`.

#### `const buffer = pbkdf2Sync(password, salt, iterations, keylen, digest)`

For Node.js compatibility; equivalent to `pbkdf2` without a callback.

#### `const { publicKey, privateKey } = generateKeyPair(type)`

Generate a new asymmetric key pair. `type` may be a string (e.g. `'ed25519'`) or a numeric constant from `constants.keyType`.

#### `const signature = sign(algorithm, data, key)`

Sign `data` using `key`. For Ed25519, `algorithm` is ignored — pass `null`. `data` may be an `ArrayBuffer` or `ArrayBufferView`. Returns a `Buffer` containing the signature.

#### `const valid = verify(algorithm, data, key, signature)`

Verify that `signature` is a valid signature over `data` for `key`. Returns `true` or `false`.

#### `const equal = timingSafeEqual(a, b)`

Compare two `ArrayBuffer`s or `ArrayBufferView`s in constant time. Returns `true` if `a` and `b` contain the same bytes, otherwise `false`. Throws a `RangeError` if `a` and `b` differ in byte length. Use this whenever comparing MACs, signatures, capability tokens, or other secret-equality checks.

#### `webcrypto`

A namespace implementing a subset of the W3C Web Crypto API (<https://w3c.github.io/webcrypto>). Exposes `Crypto`, `SubtleCrypto`, `CryptoKey`, `getRandomValues`, `randomUUID`, and `subtle` (a pre-constructed `SubtleCrypto` instance). Supports HMAC, Ed25519, PBKDF2, and SHA-1 / SHA-256 / SHA-384 / SHA-512.

Importing `bare-crypto/global` installs `crypto`, `Crypto`, `CryptoKey`, and `SubtleCrypto` as globals.

#### `constants.hash`

The supported hash algorithms.

| Constant     | Description                                                                                                                                                                           |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MD5`        | A widely-used 128-bit hash function, now considered insecure due to vulnerabilities to collision attacks. Still fast but not recommended for security-sensitive purposes.             |
| `SHA1`       | A 160-bit hash function, stronger than MD5 but also broken by collision attacks. Deprecated for most cryptographic uses due to security vulnerabilities.                              |
| `SHA256`     | Part of the SHA-2 family, this 256-bit hash function is widely used and considered secure for most applications. Slower than MD5 and SHA1 but much more secure.                       |
| `SHA384`     | A truncated variant of SHA-512 producing a 384-bit digest. Shares SHA-512's internal state and performance characteristics but yields a shorter hash.                                 |
| `SHA512`     | Another member of the SHA-2 family, this 512-bit hash function offers greater security than SHA256 but is slower and produces larger hashes. Suitable for high-security environments. |
| `BLAKE2B256` | A fast, secure alternative to SHA-2 designed for efficiency, producing a 256-bit hash. It is optimized for performance while maintaining strong cryptographic security.               |
| `RIPEMD160`  | A 160-bit hash designed in the 1990s as an alternative to SHA-1. Still used by Bitcoin and similar systems; not recommended for new designs.                                          |

#### `constants.cipher`

The supported symmetric cipher algorithms.

| Constant            | Description                                                                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `AES128ECB`         | AES with a 128-bit key in ECB (Electronic Codebook) mode. Fast but insecure due to deterministic encryption of identical plaintext blocks. Not recommended.  |
| `AES128CBC`         | AES with a 128-bit key in CBC (Cipher Block Chaining) mode. Provides better security than ECB by chaining blocks, but requires an IV and is slower.          |
| `AES128CTR`         | AES with a 128-bit key in CTR (Counter) mode. A secure and parallelizable mode that turns a block cipher into a stream cipher. Requires a nonce/IV.          |
| `AES128OFB`         | AES with a 128-bit key in OFB (Output Feedback) mode. Converts AES into a stream cipher; less common than CTR and more sensitive to IV reuse.                |
| `AES256ECB`         | AES with a 256-bit key in ECB mode. Inherits the weaknesses of ECB; not suitable for encrypting more than a block at a time securely.                        |
| `AES256CBC`         | AES with a 256-bit key in CBC mode. Commonly used and reasonably secure with proper IV and padding management.                                               |
| `AES256CTR`         | AES with a 256-bit key in CTR mode. Offers high performance and strong security if nonces are never reused.                                                  |
| `AES256OFB`         | AES with a 256-bit key in OFB mode. Like CTR, it turns AES into a stream cipher but with different feedback mechanics; less commonly used.                   |
| `AES128GCM`         | AES with a 128-bit key in GCM (Galois/Counter Mode). Provides authenticated encryption with associated data (AEAD). Fast and secure with proper nonce usage. |
| `AES256GCM`         | AES with a 256-bit key in GCM mode. Offers strong authenticated encryption; commonly used in TLS and secure messaging.                                       |
| `CHACHA20POLY1305`  | A modern AEAD cipher combining the ChaCha20 stream cipher and Poly1305 MAC. Fast and secure, especially efficient on devices without AES hardware support.   |
| `XCHACHA20POLY1305` | An extended variant of ChaCha20-Poly1305 that supports longer nonces (192-bit). Improves nonce reuse resistance and is easier to use safely.                 |

#### `constants.signature`

The supported signature algorithms.

| Constant  | Description                                                                                                              |
| --------- | ------------------------------------------------------------------------------------------------------------------------ |
| `ED25519` | Edwards-curve digital signature scheme over Curve25519. Fast, deterministic, and produces fixed-size 64-byte signatures. |

#### `constants.keyType`

The supported asymmetric key types.

| Constant  | Description          |
| --------- | -------------------- |
| `ED25519` | An Ed25519 key pair. |

## License

Apache-2.0
