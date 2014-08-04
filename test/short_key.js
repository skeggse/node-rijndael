#!/usr/bin/env node
process.env.NODE_ENV = 'dev';
process.env.DEBUG = '*';

var Rijndael = require('../index.js');

var msg = 'Goodbye, World!',
    params = {};

params.msg = msg;
params.mode = 'ecb';
params.key = new Buffer('ajd746kd63gxc');
params.iv = 'FbRCcdAUp7yF9nd24oUxUCjoGgdZt4xTETcjNlDho8k=';

var rijndael = new Rijndael(params.key, {
    mode: 'ecb',
    iv: new Buffer(params.iv, 'base64')
});

params.enc = rijndael.encrypt(msg, 'utf8', 'base64');
params.dec = rijndael.decrypt(params.enc, 'base64', 'utf8').replace(/\x00+$/g, '');
console.log(params);
