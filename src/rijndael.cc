#include <node.h>
#include <v8.h>
#include <node_buffer.h>

// dependency
#include <string.h>
#include <stdlib.h>
#include <mcrypt.h>

using namespace v8;
using namespace node;

Handle<Value> Rijndael(const Arguments& args) {
  HandleScope scope;

  MCRYPT rijndael_module;

  int err = 0;
  char* error_message;
  int data_size;
  void* data;
  char* text;
  char* key;
  int text_len;
  int key_len;
  bool encrypt;

  if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
    err = 1; error_message = (char*) "data must be a buffer";
  } else if (args.Length() < 2 || !Buffer::HasInstance(args[1])) {
    err = 1; error_message = (char*) "key must be a buffer";
  } else if (args.Length() < 3 || !args[2]->IsBoolean()) {
    err = 1; error_message = (char*) "encryption must be a boolean";
  }

  if (err == 1) {
    ThrowException(Exception::TypeError(String::New(error_message)));
    return scope.Close(Undefined());
  }

  text = Buffer::Data(args[0]);
  key = Buffer::Data(args[1]);
  encrypt = args[2]->BooleanValue();

  text_len = Buffer::Length(args[0]);
  key_len = Buffer::Length(args[1]);

  if (key_len != 32) {
    ThrowException(Exception::Error(String::New("key length does not match algorithm parameters")));
    return scope.Close(Undefined());
  }

  rijndael_module = mcrypt_module_open((char*) "rijndael-256", NULL, (char*) "ecb", NULL);
  if (rijndael_module == MCRYPT_FAILED) {
    ThrowException(Exception::Error(String::New("rijndael mcrypt module failed to load")));
    return scope.Close(Undefined());
  }

  err = mcrypt_generic_init(rijndael_module, (void*) key, key_len, NULL);
  if (err < 0) {
    ThrowException(Exception::Error(String::New(mcrypt_strerror(err))));
    return scope.Close(Undefined());
  }

  data_size = (((text_len - 1) / 32) + 1) * 32;
  data = malloc(data_size);
  memset(data, 0, data_size);
  memcpy(data, text, text_len);

  if (encrypt)
    mcrypt_generic(rijndael_module, data, data_size);
  else
    mdecrypt_generic(rijndael_module, data, data_size);

  Buffer& buffer = *Buffer::New((char*) data, data_size);

  mcrypt_module_close(rijndael_module);

  free(data);

  return scope.Close(buffer.handle_);
}

void init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("rijndael"), FunctionTemplate::New(Rijndael)->GetFunction());
}

NODE_MODULE(rijndael, init)
