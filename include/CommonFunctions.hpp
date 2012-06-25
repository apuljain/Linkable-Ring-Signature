#ifndef COMMON_FUNCTIONS_H_GUARD
#define COMMON_FUNCTIONS_H_GUARD

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <cryptopp/integer.h>
#include <cryptopp/modarith.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/dh.h>

using namespace std;
using namespace CryptoPP;

void GetGroupParameters(Integer&, Integer&, Integer&);

/*Convert CryptoPP::Integer to std::string*/
string IntegerToString(Integer);

/*Generates string from vector*/
string GenerateString(vector<Integer>);

/*Calculate SHA1 hash*/
string Hash1(string input_string);

/*Calculate SHA1 hash*/
string Hash2(string, Integer, Integer, Integer);

#endif
