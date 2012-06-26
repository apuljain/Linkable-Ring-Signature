#include "LinkableRingSignProver.hpp"
#include "LinkableRingSignVerifier.hpp"
#include "CommonFunctions.hpp"

using namespace std;
using namespace CryptoPP;

//comment below line to disable debugging info on screen.
#define DEBUG TRUE

/*
  XXX If the binary that you produce is called "ringsign"
  then you should name this file either "main.cpp" or
  "ringsign.cpp" to make it easy to find.
*/

/*
  XXX Done.
*/

/*
	This function will generate public_keys and private key.
	@params: public_keys -- vector which will be updated with generated
				public keys.
	@params: private_key -- generated private key to be used.
	@params: num_members -- input no. of members.
	@params: self_identity -- identity to be used.
	@params: g, p, q       -- group parameters.
*/

void GeneratePublicPrivateKeys(vector<Integer> &public_keys, Integer &private_key, 
			       unsigned int num_members, unsigned int self_identity,
			       Integer g, Integer p, Integer q)
{
	//populate public keys randomly
	RandomPool rng;
	public_keys.clear();

	for(unsigned int i = 0; i < num_members; i++)
		public_keys.push_back(a_exp_b_mod_c(g, Integer(rng, 0, q - 1), 					                    p));			

	//generate private/public key pair
	private_key = Integer(rng, 0, q - 1);
	Integer public_key_self = a_exp_b_mod_c(g, private_key, p);

	//update public key in commonParameters class
	public_keys[self_identity] = public_key_self;
}


int main()
{
	//generate group parameters.
	Integer g, p, q;
	GetGroupParameters(g, p, q); /*Use this function to generate parameters.*/
/*	
	//manually set group parameters.
	Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14"
		   "266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E915"
		   "47F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F53"
		   "1DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97"
		   "C2A24855E6EEB22B3B2E5");

	Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52"
		  "D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C"
	          "3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FA"
		  "A31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA7"
		  "08DF1FB2BC2E4A4371");
	
	Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");
*/	
	//set number of members.
	unsigned int num_members = 4;
	
	//set self identity.
	unsigned int self_identity = 2;

	//generate public_keys and private key to be used for initialization.
	vector<Integer> public_keys;
	Integer private_key;

	//call function to generate keys.
	GeneratePublicPrivateKeys(public_keys, private_key, num_members,
				  self_identity, g, p, q);	
	
	assert(public_keys.size() != 0);

	//pass n, identity and message
	LinkableRingSignProver P(num_members, self_identity, g, p, q,
				 public_keys, private_key);

	assert(P.public_keys.size() != 0);
	
	Integer C, Y;
	vector<Integer> S;
	P.GenerateSignature("A very short message", C, S, Y);

	LinkableRingSignVerifier V(P.num_members, P.public_keys,
				   P.q, P.p, P.g, P.m);

	if(V.VerifySignature(C, S, Y))
		cout << "SUCCESS" << endl;

	return 0;	
}
