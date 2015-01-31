<?php
/**
 * Encrypt the given plaintext with the base64 encoded key and initialization
 * vector.
 *
 * Uses PHP's automatic null-padding. This means that if your input plaintext
 * ends with null characters, they will be lost in encryption.
 *
 * @param {string} $plaintext The plain text for encryption.
 * @param {string} $input_key Base64 encoded encryption key.
 * @param {string} $input_iv Base64 encoded initialization vector.
 * @return {string} The base64 encoded cipher text.
 */
function encrypt($plaintext, $input_key, $input_iv) {
  $crypt = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_CBC, '');
  $raw_key = base64_decode($input_key);
  $raw_iv = base64_decode($input_iv);

  // node-rijndael handles this automatically
  if (mcrypt_enc_get_key_size($crypt) > strlen($raw_key))
    throw new OutOfBoundsException('key length does not match algorithm parameters');

  $init = mcrypt_generic_init($crypt, $raw_key, $raw_iv);

  if ($init === false || $init < 0)
    throw new RuntimeException('encryption failed');

  $ciphertext = mcrypt_generic($crypt, $plaintext);

  mcrypt_generic_deinit($crypt);
  mcrypt_module_close($crypt);

  return base64_encode($ciphertext);
}

/**
 * Decrypt the given ciphertext with the base64 encoded key and initialization
 * vector.
 *
 * Reverses PHP's automatic null-padding.
 *
 * @param {string} $ciphertext The base64 encoded ciphered text to decode.
 * @param {string} $input_key Base64 encoded encryption key.
 * @param {string} $input_iv Base64 encoded initialization vector.
 * @param {string} The decrypted plain text.
 */
function decrypt($ciphertext, $input_key, $input_iv) {
  $crypt = mcrypt_module_open(MCRYPT_RIJNDAEL_256, '', MCRYPT_MODE_CBC, '');
  $raw_key = base64_decode($input_key);
  $raw_iv = base64_decode($input_iv);

  // node-rijndael handles this automatically
  if (mcrypt_enc_get_key_size($crypt) > strlen($raw_key))
    throw new OutOfBoundsException('key length does not match algorithm parameters');

  $init = mcrypt_generic_init($crypt, $raw_key, $raw_iv);

  if ($init === false || $init < 0)
    throw new RuntimeException('decryption failed');

  $plaintext = mdecrypt_generic($crypt, $ciphertext);

  mcrypt_generic_deinit($crypt);
  mcrypt_module_close($crypt);

  return rtrim($plaintext, "\0");
}
