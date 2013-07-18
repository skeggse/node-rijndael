#include <node.h>
#include <v8.h>
#include <node_buffer.h>

// dependency
#include <string.h>
#include <stdlib.h>
#include <mcrypt.h>

using namespace v8;
using namespace node;

// rijndael.encrypt(plaintext, key)
Handle<Value> Encrypt(const Arguments& args) {
  HandleScope scope;

  if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
    ThrowException(Exception::TypeError(String::New("plaintext must be a buffer")));
    return scope.Close(Undefined());
  }

  if (args.Length() < 2 || !Buffer::HasInstance(args[1])) {
    ThrowException(Exception::TypeError(String::New("key must be a buffer")));
    return scope.Close(Undefined());
  }

  int err;
  int data_size;
  void* data;
  char* plaintext;
  char* key;

  plaintext = Buffer::Data(args[0]);
  key = Buffer::Data(args[1]);

  int text_len = Buffer::Length(args[0]);
  int key_len = Buffer::Length(args[1]);

  MCRYPT rinjdael_module = mcrypt_module_open((char*) "rijndael-256", NULL, (char*) "ecb", NULL);

  if (rinjdael_module == MCRYPT_FAILED) {
    ThrowException(Exception::TypeError(String::New("loading rijndael mcrypt module failed")));
    return scope.Close(Undefined());
  }

  if (key_len != 32) {
    ThrowException(Exception::Error(String::New("key length does not match algorithm parameters")));
    return scope.Close(Undefined());
  }

  data_size = (((text_len - 1) / 32) + 1) * 32;
  data = malloc(data_size);
  memset(data, 0, data_size);
  memcpy(data, plaintext, text_len);

  err = mcrypt_generic_init(rinjdael_module, (void*) key, key_len, NULL);
  if (err < 0) {
    ThrowException(Exception::Error(String::New(mcrypt_strerror(err))));
    return scope.Close(Undefined());
  }

  mcrypt_generic(rinjdael_module, data, data_size);

  Buffer& encrypted = *Buffer::New((char*) data, data_size);

  mcrypt_module_close(rinjdael_module);

  free(data);

  return scope.Close(encrypted.handle_);
}

/*Handle<Value> Decrypt(const Arguments& args) {
  HandleScope scope;

  if (!initialized) {
    ThrowException(Exception::Error(String::New("not initialized")));
    return scope.Close(Undefined());
  }

  if (args.Length() < 1 || !args[0]->IsString()) {
    ThrowException(Exception::TypeError(String::New("plaintext must be a string")));
    return scope.Close(Undefined());
  }

  int err;

  String::AsciiValue plaintext(args[0]->ToString());

  err = mcrypt_generic(rinjdael_module, plaintext, plaintext.length());

  return scope.Close(String::New("decrypting..."));
}*/

void init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("encrypt"), FunctionTemplate::New(Encrypt)->GetFunction());
  //exports->Set(String::NewSymbol("decrypt"), FunctionTemplate::New(Decrypt)->GetFunction());
}

NODE_MODULE(rijndael, init)
