var Rijndael = require('..');

var crypto = require('crypto');
var expect = require('chai').expect;

function key(size) {
  return crypto.randomBytes(size || 16).toString('hex');
}

// TODO: test for memory leaks

describe('Rijndael', function() {
  // test the constructor
  it('should support php-style autopadding', function() {
    var keys = [
      ['ksf', '6b736600000000000000000000000000'],
      ['ajd746kd63gxc', '616a643734366b643633677863000000'],
      [
        'sihjfohsvc984ozffs',
        '7369686a666f687376633938346f7a666673000000000000'
      ],
      [
        'diesuht397p9y5678hd3serhjksjhfg',
        '6469657375687433393770397935363738686433736572686a6b736a68666700'
      ]
    ];

    var types = [
      'binary',
      'hex',
      'base64',
      'ascii'
    ];

    keys.forEach(function(key, i) {
      var raw = new Buffer(key[0], 'utf-8');

      types.forEach(function(type) {
        var rijndael = new Rijndael(raw.toString(type), {
          encoding: type,
          mode: 'ecb'
        });

        expect(rijndael._key.toString('hex'))
          .to.equal(key[1]);
      });
    });
  });

  describe('encryption', function() {
    // test encryption/decryption
  });

  describe('compatibility', function() {
    // test encryption/decryption with php
  });
});
