#include <node.h>
#include <nan.h>
#include <v8.h>
#include <node_buffer.h>

// dependency
#include <string.h>
#include <stdlib.h>
#include <mcrypt.h>

using namespace v8;
using namespace node;

NAN_METHOD(Rijndael) {
  MCRYPT rijndael_module;

  int argCount = info.Length();

  if (argCount < 1 || !Buffer::HasInstance(info[0])) {
    Nan::ThrowTypeError((char*) "data must be a buffer");
    return;
  }

  if (argCount < 2 || !Buffer::HasInstance(info[1])) {
    Nan::ThrowTypeError((char*) "key must be a buffer");
    return;
  }

  if (argCount < 3 || !info[2]->IsBoolean()) {
    Nan::ThrowTypeError((char*) "encryption must be a boolean");
    return;
  }

  // not actually used
  if (argCount < 4 || !info[3]->IsString()) {
    Nan::ThrowTypeError((char*) "block mode must be a string");
    return;
  }

  if (argCount < 5 || (!info[4]->IsNull() && !Buffer::HasInstance(info[4]))) {
    Nan::ThrowTypeError((char*) "iv must be a buffer or null");
    return;
  }

  size_t text_len = Buffer::Length(info[0]);

  if (text_len == 0) {
    info.GetReturnValue().Set(Nan::NewBuffer(NULL, 0).ToLocalChecked());
    return;
  }

  char *iv = info[4]->IsNull() ? NULL : Buffer::Data(info[4]);

  char *text = Buffer::Data(info[0]);
  char *key = Buffer::Data(info[1]);
  bool encrypt = info[2]->BooleanValue();
  char *mode = *Nan::Utf8String(info[3]->ToString());
  size_t key_len = Buffer::Length(info[1]);

  if (key_len != 16 && key_len != 24 && key_len != 32) {
    Nan::ThrowError("key length does not match algorithm parameters");
    return;
  }

  rijndael_module = mcrypt_module_open((char*) "rijndael-256", NULL, mode,
    NULL);
  if (rijndael_module == MCRYPT_FAILED) {
    Nan::ThrowError("rijndael mcrypt module failed to load");
    return;
  }

  int err = mcrypt_generic_init(rijndael_module, key, key_len, iv);
  if (err < 0) {
    Nan::ThrowError(mcrypt_strerror(err));
    return;
  }

  size_t data_size = (text_len + 0x1f) & ~0x1f;
  char *data = new char[data_size];
  memcpy(data, text, text_len);
  if (text_len < data_size) {
    memset(data + text_len, 0, data_size);
  }

  if (encrypt) {
    err = mcrypt_generic(rijndael_module, data, data_size);
  } else {
    err = mdecrypt_generic(rijndael_module, data, data_size);
  }

  if (err < 0) {
    mcrypt_module_close(rijndael_module);
    delete[] data;
    Nan::ThrowError(mcrypt_strerror(err));
    return;
  }

  mcrypt_generic_deinit(rijndael_module);
  mcrypt_module_close(rijndael_module);

  info.GetReturnValue().Set(Nan::NewBuffer(data, data_size).ToLocalChecked());
}

NAN_MODULE_INIT(Init) {
  NAN_EXPORT(target, Rijndael);
}
