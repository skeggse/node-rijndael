var Rijndael = require('..');

var crypto = require('crypto');
var expect = require('expect.js');
var key = function() {
  return crypto.randomBytes(16).toString('hex');
};

// TODO: test for memory leaks

describe('Rijndael', function() {
  // test the constructor

  describe('encryption', function() {
    // test encryption/decryption
  });

  describe('compatibility', function() {
    // test encryption/decryption with php
  });
});
