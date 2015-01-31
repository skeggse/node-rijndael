var Rijndael = require('..');

/**
 * Pad the string with the character such that the string length is a multiple
 * of the provided length.
 *
 * @param {string} string The input string.
 * @param {string} chr The character to pad with.
 * @param {number} length The base length to pad to.
 * @return {string} The padded string.
 */
function rpad(string, chr, length) {
  var extra = string.length % length;
  if (extra === 0)
    return string;

  var pad_length = length - extra;
  // doesn't need to be optimized because pad_length will never be large
  while (--pad_length >= 0) {
    string += chr;
  }
  return string;
}

/**
 * Remove all characters specified by the chr parameter from the end of the
 * string.
 *
 * @param {string} string The string to trim.
 * @param {string} chr The character to trim from the end of the string.
 * @return {string} The trimmed string.
 */
function rtrim(string, chr) {
  for (var i = string.length - 1; i >= 0; i--)
    if (string[i] !== chr)
      return string.slice(0, i + 1);

  return '';
}

/**
 * Encrypt the given plaintext with the base64 encoded key and initialization
 * vector.
 *
 * Null-pads the input plaintext. This means that if your input plaintext ends
 * with null characters, they will be lost in encryption.
 *
 * @param {string} plaintext The plain text for encryption.
 * @param {string} input_key Base64 encoded encryption key.
 * @param {string} input_iv Base64 encoded initialization vector.
 * @return {string} The base64 encoded cipher text.
 */
function encrypt(plaintext, input_key, input_iv) {
  var rijndael = new Rijndael(input_key, {
    mode: Rijndael.MCRYPT_RIJNDAEL_256,
    encoding: 'base64',
    iv: input_iv
  });

  var padded = rpad(plaintext, '\0', Rijndael.blockSize);

  return rijndael.encrypt(padded, 'binary', 'base64');
}

/**
 * Decrypt the given ciphertext with the base64 encoded key and initialization
 * vector.
 *
 * Reverses any null-padding on the original plaintext.
 *
 * @param {string} ciphertext The base64 encoded ciphered text to decode.
 * @param {string} input_key Base64 encoded encryption key.
 * @param {string} input_iv Base64 encoded initialization vector.
 * @param {string} The decrypted plain text.
 */
function decrypt(ciphertext, input_key, input_iv) {
  var rijndael = new Rijndael(input_key, {
    mode: Rijndael.MCRYPT_RIJNDAEL_256,
    encoding: 'base64',
    iv: input_iv
  });

  return rtrim(rijndael.decrypt(ciphertext, 'base64', 'binary'), '\0');
}

exports.decrypt = decrypt;
exports.encrypt = encrypt;
