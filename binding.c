#include <assert.h>
#include <bare.h>
#include <js.h>
#include <openssl/digest.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stddef.h>

enum {
  bare_crypto_md5 = 1,
  bare_crypto_sha1 = 2,
  bare_crypto_sha256 = 3,
  bare_crypto_sha512 = 4,
  bare_crypto_blake2b256 = 5,
};

typedef struct {
  EVP_MD_CTX context;
} bare_crypto_hash_t;

static inline const EVP_MD *
bare_crypto__to_algorithm(js_env_t *env, int type) {
  int err;

  switch (type) {
#define V(algorithm) \
  case bare_crypto_##algorithm: \
    return EVP_##algorithm();

    V(md5)
    V(sha1)
    V(sha256)
    V(sha512)
    V(blake2b256)
#undef V

  default:
    err = js_throw_error(env, NULL, "Unknown digest algorithm");
    assert(err == 0);

    return NULL;
  }
}

static js_value_t *
bare_crypto_hash_init(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  uint32_t type;
  err = js_get_value_uint32(env, argv[0], &type);
  assert(err == 0);

  js_value_t *handle;

  bare_crypto_hash_t *hash;
  err = js_create_arraybuffer(env, sizeof(bare_crypto_hash_t), (void **) &hash, &handle);
  assert(err == 0);

  const EVP_MD *algorithm = bare_crypto__to_algorithm(env, type);

  if (algorithm == NULL) return NULL;

  EVP_MD_CTX_init(&hash->context);

  err = EVP_DigestInit(&hash->context, algorithm);
  assert(err == 1);

  return handle;
}

static js_value_t *
bare_crypto_hash_update(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 4;
  js_value_t *argv[4];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 4);

  bare_crypto_hash_t *hash;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &hash, NULL);
  assert(err == 0);

  void *data;
  err = js_get_arraybuffer_info(env, argv[1], &data, NULL);
  assert(err == 0);

  int64_t offset;
  err = js_get_value_int64(env, argv[2], &offset);
  assert(err == 0);

  int64_t len;
  err = js_get_value_int64(env, argv[3], &len);
  assert(err == 0);

  err = EVP_DigestUpdate(&hash->context, &data[offset], len);
  assert(err == 1);

  return NULL;
}

static js_value_t *
bare_crypto_hash_final(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 1;
  js_value_t *argv[1];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 1);

  bare_crypto_hash_t *hash;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &hash, NULL);
  assert(err == 0);

  js_value_t *result;

  size_t len = EVP_MD_CTX_size(&hash->context);

  uint8_t *digest;
  err = js_create_arraybuffer(env, len, (void **) &digest, &result);
  assert(err == 0);

  err = EVP_DigestFinal(&hash->context, digest, NULL);
  assert(err == 1);

  return result;
}

static js_value_t *
bare_crypto_random_fill(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 3;
  js_value_t *argv[3];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 3);

  uint8_t *data;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &data, NULL);
  assert(err == 0);

  uint32_t offset;
  err = js_get_value_uint32(env, argv[1], &offset);
  assert(err == 0);

  uint32_t len;
  err = js_get_value_uint32(env, argv[2], &len);
  assert(err == 0);

  err = RAND_bytes(&data[offset], len);
  assert(err == 1);

  return NULL;
}

static js_value_t *
bare_crypto_pbkdf2(js_env_t *env, js_callback_info_t *info) {
  int err;

  size_t argc = 9;
  js_value_t *argv[9];

  err = js_get_callback_info(env, info, &argc, argv, NULL, NULL);
  assert(err == 0);

  assert(argc == 9);

  char *password;
  err = js_get_arraybuffer_info(env, argv[0], (void **) &password, NULL);
  assert(err == 0);

  int64_t password_offset;
  err = js_get_value_int64(env, argv[1], &password_offset);
  assert(err == 0);

  int64_t password_len;
  err = js_get_value_int64(env, argv[2], &password_len);
  assert(err == 0);

  uint8_t *salt;
  err = js_get_arraybuffer_info(env, argv[3], (void **) &salt, NULL);
  assert(err == 0);

  int64_t salt_offset;
  err = js_get_value_int64(env, argv[4], &salt_offset);
  assert(err == 0);

  int64_t salt_len;
  err = js_get_value_int64(env, argv[5], &salt_len);
  assert(err == 0);

  uint32_t iterations;
  err = js_get_value_uint32(env, argv[6], &iterations);
  assert(err == 0);

  uint32_t type;
  err = js_get_value_uint32(env, argv[7], &type);
  assert(err == 0);

  int64_t key_len;
  err = js_get_value_int64(env, argv[8], &key_len);
  assert(err == 0);

  js_value_t *handle;

  uint8_t *out;
  err = js_create_arraybuffer(env, key_len, (void **) &out, &handle);
  assert(err == 0);

  const EVP_MD *algorithm = bare_crypto__to_algorithm(env, type);

  if (algorithm == NULL) return NULL;

  err = PKCS5_PBKDF2_HMAC(&password[password_offset], password_len, &salt[salt_offset], salt_len, iterations, algorithm, key_len, out);
  assert(err == 1);

  return handle;
}

static js_value_t *
bare_crypto_exports(js_env_t *env, js_value_t *exports) {
  int err;

#define V(name, fn) \
  { \
    js_value_t *val; \
    err = js_create_function(env, name, -1, fn, NULL, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, exports, name, val); \
    assert(err == 0); \
  }

  V("hashInit", bare_crypto_hash_init)
  V("hashUpdate", bare_crypto_hash_update)
  V("hashFinal", bare_crypto_hash_final)

  V("randomFill", bare_crypto_random_fill)

  V("pbkdf2", bare_crypto_pbkdf2);
#undef V

#define V(name, n) \
  { \
    js_value_t *val; \
    err = js_create_uint32(env, n, &val); \
    assert(err == 0); \
    err = js_set_named_property(env, exports, name, val); \
    assert(err == 0); \
  }

  V("MD5", bare_crypto_md5)
  V("SHA1", bare_crypto_sha1)
  V("SHA256", bare_crypto_sha256)
  V("SHA512", bare_crypto_sha512)
  V("BLAKE2B256", bare_crypto_blake2b256)
#undef V

  return exports;
}

BARE_MODULE(bare_crypto, bare_crypto_exports)
