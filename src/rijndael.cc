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
    ThrowException(Exception::TypeError(String::New(error_message)));
    return scope.Close(Undefined());
  }

  if (Buffer::HasInstance(args[4])) {
    iv = Buffer::Data(args[4]);
  }

  v8::String::Utf8Value modeStr(args[3]->ToString());

  text = Buffer::Data(args[0]);
  key = Buffer::Data(args[1]);
  encrypt = args[2]->BooleanValue();
  mode = *modeStr;

  text_len = Buffer::Length(args[0]);
  key_len = Buffer::Length(args[1]);

  if (key_len != 16 && key_len != 24 && key_len != 32) {
    ThrowException(Exception::Error(String::New("key length does not match algorithm parameters")));
    return scope.Close(Undefined());
  }

  rijndael_module = mcrypt_module_open((char*) "rijndael-256", NULL, mode, NULL);
  if (rijndael_module == MCRYPT_FAILED) {
    ThrowException(Exception::Error(String::New("rijndael mcrypt module failed to load")));
    return scope.Close(Undefined());
  }

  err = mcrypt_generic_init(rijndael_module, (void*) key, key_len, iv);
  if (err < 0) {
    mcrypt_module_close(rijndael_module);
    ThrowException(Exception::Error(String::New(mcrypt_strerror(err))));
    return scope.Close(Undefined());
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
    ThrowException(Exception::Error(String::New(mcrypt_strerror(err))));
    return scope.Close(Undefined());
  }

  Buffer& buffer = *Buffer::New((char*) data, data_size);
  mcrypt_module_close(rijndael_module);
  free(data);
  return scope.Close(buffer.handle_);
}

void init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("rijndael"), FunctionTemplate::New(Rijndael)->GetFunction());
}

NODE_MODULE(rijndael, init)
