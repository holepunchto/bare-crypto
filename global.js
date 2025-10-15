const crypto = require('./web')

global.crypto = crypto
global.Crypto = crypto.Crypto
global.CryptoKey = crypto.CryptoKey
global.SubtleCrypto = crypto.SubtleCrypto
