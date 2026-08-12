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

See the [full API reference](https://docs.pears.com/reference/bare/modules/bare-crypto).

## License

Apache-2.0
