/**
 * Compare two `ArrayBuffer`s or `ArrayBufferView`s in constant time. Returns `true` if `a` and `b` contain the same bytes, otherwise `false`. Throws a `RangeError` if `a` and `b` differ in byte length. Use this whenever comparing MACs, signatures, capability tokens, or other secret-equality checks.
 * @param a - The first buffer to compare.
 * @param b - The second buffer to compare.
 * @throws {RangeError} `a` and `b` differ in byte length.
 */
declare function timingSafeEqual(
  a: ArrayBuffer | ArrayBufferView,
  b: ArrayBuffer | ArrayBufferView
): boolean

export { timingSafeEqual }
