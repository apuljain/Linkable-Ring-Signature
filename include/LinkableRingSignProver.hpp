#ifndef LINKABLE_RING_SIG_PROVER_H_GUARD
#define LINKABLE_RING_SIG_PROVER_H_GUARD

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


class LinkableRingSignProver
{
	private:

	//private key
	Integer _private_key;
	
	//set member identity number
	unsigned int _self_identity;

	public:

	//no. of members
	unsigned int num_members;

	//declare group generator
	Integer g;

	//declare prime
	Integer p;

	//declare group order
	Integer q;

	//set message
	string m;
	
	//public keys
	vector<Integer> public_keys;

  /* XXX You might want to rethink the API here. I can imagine that someone
     using your signature library will want to initialize a Prover object
     (using some public keys and his/her private key) and then sign 
     many different messages using those same keys. If you think that that is 
     a likely scenario, you might want to tweak the API to make it possible
     to sign many different messages using the same set of keys.
  */

  /*
	 XXX Agreed. 
   */
	
	//constructor
	//@params: num_members, identity, g, p, q, public_keys and private key.

	LinkableRingSignProver(unsigned int n, unsigned int identity,
		 	       Integer g_in, Integer p_in, Integer q_in,
			       vector<Integer> public_keys_in,
			       Integer private_key_in);
	
	//@params: message - input message to be signed.
	//@params: updates signature variables (c1, s1....sn, y).
	void GenerateSignature(string message, Integer &c1, vector<Integer> &S,
			       Integer &Y);
};

#endif
