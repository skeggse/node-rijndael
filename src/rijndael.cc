#include <node.h>
#include <nan.h>
#include <v8.h>
#include <node_buffer.h>

// dependency
#include <string.h>
#include <stdlib.h>
#include "mcrypt.h"

using namespace v8;
using namespace node;

NAN_METHOD(Rijndael) {
  NanScope();

  MCRYPT rijndael_module;

  int err = 0;
  char* error_message;
  int data_size;
  void* data;
  char* text;
  char* key;
  char* iv = NULL;

  int text_len;
  int key_len;
  bool encrypt;
  char* mode;

  if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
    err = 1; error_message = (char*) "data must be a buffer";
  } else if (args.Length() < 2 || !Buffer::HasInstance(args[1])) {
    err = 1; error_message = (char*) "key must be a buffer";
  } else if (args.Length() < 3 || !args[2]->IsBoolean()) {
    err = 1; error_message = (char*) "encryption must be a boolean";
  } else if (args.Length() < 4) {
    err = 1; error_message = (char*) "block mode must be a string";
  } else if (args.Length() < 5) {
    err = 1; error_message = (char*) "iv must be a buffer or null";
  }

  if (err == 1) {
    NanThrowTypeError(error_message);
    NanReturnUndefined();
  }

  if (Buffer::HasInstance(args[4])) {
    iv = Buffer::Data(args[4]);
  }

  String::Utf8Value modeStr(args[3]->ToString());

  text = Buffer::Data(args[0]);
  key = Buffer::Data(args[1]);
  encrypt = args[2]->BooleanValue();
  mode = *modeStr;

  text_len = Buffer::Length(args[0]);
  key_len = Buffer::Length(args[1]);

  if (key_len != 16 && key_len != 24 && key_len != 32) {
    NanThrowError("key length does not match algorithm parameters");
    NanReturnUndefined();
  }

  rijndael_module = mcrypt_module_open((char*) "rijndael-256", NULL, mode, NULL);
  if (rijndael_module == MCRYPT_FAILED) {
    NanThrowError("rijndael mcrypt module failed to load");
    NanReturnUndefined();
  }

  err = mcrypt_generic_init(rijndael_module, (void*) key, key_len, iv);
  if (err < 0) {
    mcrypt_module_close(rijndael_module);
    NanThrowError(mcrypt_strerror(err));
    NanReturnUndefined();
  }

  data_size = (((text_len - 1) / 32) + 1) * 32;
  data = malloc(data_size);
  memset(data, 0, data_size);
  memcpy(data, text, text_len);

  if (encrypt)
    err = mcrypt_generic(rijndael_module, data, data_size);
  else
    err = mdecrypt_generic(rijndael_module, data, data_size);

  if (err < 0) {
    mcrypt_module_close(rijndael_module);
    free(data);
    NanThrowError(mcrypt_strerror(err));
    NanReturnUndefined();
  }
  
  mcrypt_generic_deinit(rijndael_module);

  Local<Object> buffer = NanNewBufferHandle((char*) data, data_size);
  mcrypt_module_close(rijndael_module);
  free(data);
  NanReturnValue(buffer);
}

void init(Handle<Object> exports) {
  exports->Set(NanNew<String>("rijndael"),
    NanNew<FunctionTemplate>(Rijndael)->GetFunction());
}

NODE_MODULE(rijndael, init)
