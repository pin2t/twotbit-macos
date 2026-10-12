// Compiles the unchanged upstream precomputed_ecmult.c without the 64-to-32 bit
// shortening warnings SwiftPM enables, which upstream builds do not.
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "../src/precomputed_ecmult.c"
