#ifndef RING_SIGN_VERIFIER_H_GUARD
#define RING_SIGN_VERIFIER_H_GUARD

#include <iostream>
#include <string>
#include <vector>
#include <cryptopp/integer.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/modarith.h>
#include <cryptopp/osrng.h>
#include <cryptopp/dh.h>
#include "CommonFunctions.hpp"

using namespace std;
using namespace CryptoPP;

/*Define Verifier Class*/
class LinkableRingSignVerifier
{
	public:

	//no. of members
	unsigned int num_members;

	//public keys
	vector<Integer> public_keys;

	//declare group order
	Integer q;

	//declare prime
	Integer p;

	//declare group generator
	Integer g;

	//set message
	string m;
	
	//constructor
	LinkableRingSignVerifier(unsigned int num_members, vector<Integer> pub_keys,
							 Integer q, Integer p, Integer g, string m);

	//function to verify signature.
	bool VerifySignature(Integer &C, vector<Integer> &S, Integer &Y);
};

#endif
