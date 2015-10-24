#include "rijndael.h"

using v8::FunctionTemplate;

NAN_MODULE_INIT(InitAll) {
  Nan::Set(target, Nan::New("rijndael").ToLocalChecked(),
    Nan::GetFunction(Nan::New<FunctionTemplate>(Rijndael)).ToLocalChecked());
}

NODE_MODULE(Rijndael, InitAll)
