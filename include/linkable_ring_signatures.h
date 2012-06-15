#ifndef LINKABLE_RING_SIGNATURES_H_GUARD
#define LINKABLE_RING_SIGNATURES_H_GUARD

#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <set>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <gmp.h>
#include <cryptopp/integer.h>
#include <cryptopp/modarith.h>
#include <iomanip>
#include <cryptopp/randpool.h>
#include <cryptopp/filters.h>
#include <vector>
#include <cassert>

#include <stdexcept>
using std::runtime_error;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularExponentiation;

#include <cryptopp/dh.h>
using CryptoPP::DH;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

using namespace std;
using namespace CryptoPP;

#endif
