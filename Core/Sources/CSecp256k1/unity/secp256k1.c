// Compiles the unchanged upstream secp256k1.c without the 64-to-32 bit
// shortening warnings SwiftPM enables, which upstream builds do not.
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "../src/secp256k1.c"
