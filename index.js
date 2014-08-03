var lib = require('./build/Release/rijndael');

var allowedEncoding = ['ascii', 'base64', 'binary', 'hex'];
var validModes = ['ecb', 'cbc', 'cfb', 'ofb', 'nofb', 'stream'];

/**
 * Pad the key out to 16, 24 or 32 bytes, making sure it's a buffer.
 *
 * @param {!Buffer|string} key The encryption key.
 * @param {string}
 */
function padkey(key, encoding) {
  var isString = typeof key === 'string';
  var l = isString ? Buffer.byteLength(key, encoding) : key.length;
  if (l > 32) {
    throw new Error('key length does not match algorithm parameters');
  }
  var jump = (((l - 1) >> 3) + 1) << 3, scale = !(jump & 0x30 && jump & 0x2f);
  if (scale || l & 0x7) {
    var buf = new Buffer(scale ? 16 : jump);
    if (isString) {
      buf.write(key, 0, l, encoding);
    } else {
      key.copy(buf);
    }
    buf.fill(0, l);
    return buf;
  }
  return isString ? new Buffer(key, encoding) : key;
}


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

  if (typeof options === 'string') {
    options = {encoding: options};
  } else {
    options || (options = {});
  }

  options.mode || (options.mode = 'ecb');
  options.encoding || (options.encoding = 'binary');

  if (allowedEncoding.indexOf(options.encoding) === -1)
    throw new TypeError(options.encoding + ' is not a permitted encoding');

  key = padkey(key, options.encoding);

  if (typeof options.iv === 'string')
    options.iv = new Buffer(options.iv, options.encoding);

  if (options.iv && !Buffer.isBuffer(options.iv))
    throw new TypeError('iv must be a buffer or a string');

  if (typeof options.mode !== 'string')
    throw new TypeError('block mode must be a string');

  options.mode = options.mode.toLowerCase();

  if (validModes.indexOf(options.mode) === -1)
    throw new TypeError(options.mode + ' is not a valid block mode');

  if (options.mode !== 'ecb' && !options.iv)
    console.warn('attempt to use empty iv, not recommended');

  this._key = key;
  this._iv = options.iv || null;
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
  if (typeof plaintext === 'string')
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
  if (typeof ciphertext === 'string')
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

Rijndael.version = "0.2.0";

module.exports = Rijndael;
