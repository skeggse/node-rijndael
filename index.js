var lib = require('./build/Release/rijndael');

/**
 * A bound Rijndael object with an option for block cipher mode.
 *
 * @param {!Buffer|string} key The encryption key.
 * @param {?options=} options The options hash.
 * @constructor
 */
var Rijndael = function(key, options) {
  if (!(this instanceof Rijndael))
    return new Rijndael(key);

  options = options || {};
  options.mode || (options.mode = 'ecb');
  options.encoding || (options.encoding = 'binary');

  if (!Buffer.isBuffer(key))
    key = new Buffer(key, options.encoding);

  if (typeof options.iv === 'string')
    options.iv = new Buffer(options.iv, options.encoding);

  if (options.iv && !Buffer.isBuffer(options.iv))
    throw new TypeError('iv must be a buffer or a string');

  if (key.length !== 32)
    throw new Error('key length does not match algorithm parameters');

  if (typeof options.mode !== 'string')
    throw new TypeError('block mode must be a string');

  if (options.mode !== 'ecb' && !options.iv)
    console.warn('attempt to use empty iv, not recommended');

  options.mode = options.mode.toLowerCase();

  this._key = key;
  this._iv = options.iv;
  this._options = options;
};

/**
 * Encrypt the provided plaintext with the bound key using the bound block
 * cipher mode.
 *
 * @param {!Buffer|string} plaintext The plaintext to encrypt.
 * @param {string=} input_encoding The plaintext encoding.
 * @param {string=} output_encoding The output ciphertext encoding.
 * @return {!Buffer|string} The encrypted ciphertext.
 * @public
 */
Rijndael.prototype.encrypt = function(plaintext, input_encoding, output_encoding) {
  var ciphertext;
  if (!Buffer.isBuffer(plaintext))
    plaintext = new Buffer(plaintext, input_encoding);
  ciphertext = lib.rijndael(plaintext, this._key, true, this._options.mode, this._iv || null);
  if (output_encoding)
    return ciphertext.toString(output_encoding);
  return ciphertext;
};

/**
 * Decrypt the provided ciphertext with the bound key using the bound block
 * cipher mode.
 *
 * @param {!Buffer|string} ciphertext The ciphertext to encrypt.
 * @param {string=} input_encoding The ciphertext encoding.
 * @param {string=} output_encoding The output plaintext encoding.
 * @return {!Buffer|string} The decrypted plaintext.
 * @public
 */
Rijndael.prototype.decrypt = function(ciphertext, input_encoding, output_encoding) {
  var plaintext;
  if (!Buffer.isBuffer(ciphertext))
    ciphertext = new Buffer(ciphertext, input_encoding);
  plaintext = lib.rijndael(ciphertext, this._key, false, this._options.mode, this._iv || null);
  if (output_encoding)
    return plaintext.toString(output_encoding);
  return plaintext;
};

// block cipher modes
Rijndael.MCRYPT_MODE_ECB = Rijndael.MODE_ECB = 'ecb';
Rijndael.MCRYPT_MODE_CBC = Rijndael.MODE_CBC = 'cbc';
Rijndael.MCRYPT_MODE_CFB = Rijndael.MODE_CFB = 'cfb';
Rijndael.MCRYPT_MODE_OFB = Rijndael.MODE_OFB = 'ofb';
Rijndael.MCRYPT_MODE_NOFB = Rijndael.MODE_NOFB = 'nofb';
Rijndael.MCRYPT_MODE_STREAM = Rijndael.MODE_STREAM = 'stream';

Rijndael.version = "0.1.0";

module.exports = Rijndael;
