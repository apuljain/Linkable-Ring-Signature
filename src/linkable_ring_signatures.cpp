#include "../include/linkable_ring_signatures.h"

#define DEBUG TRUE			//comment this line to disable debugging info on screen.

void GetGroupParameters(Integer &g, Integer &p, Integer &q)
{
	AutoSeededRandomPool rnd;
	unsigned int bits = 1024;

	try
	{
	    DH dh;
		dh.AccessGroupParameters().GenerateRandomWithKeySize(rnd, bits);

		if(!dh.GetGroupParameters().ValidateGroup(rnd, 3))
			throw runtime_error("Failed to validate prime and generator");

		size_t count = 0;

		p = dh.GetGroupParameters().GetModulus();
		count = p.BitCount();
		
		q = dh.GetGroupParameters().GetSubgroupOrder();
		count = q.BitCount();

		g = dh.GetGroupParameters().GetGenerator();
		count = g.BitCount();

		#ifdef DEBUG
		cout << "P (" << std::dec << count << "): " << std::hex << p << endl;
		cout << "Q (" << std::dec << count << "): " << std::hex << q << endl;
		cout << "G (" << std::dec << count << "): " << std::dec << g << endl;
		#endif
		

		Integer v = ModularExponentiation(g, q, p);
		if(v != Integer::One())
			throw runtime_error("Failed to verify order of the subgroup");
	}

	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}

	catch(const std::exception& e)
	{
		cerr << e.what() << endl;
	}
}

/*Convert CryptoPP::Integer to std::string*/
string IntegerToString(Integer a)
{
	stringstream ss;
	ss<<a;
	string temp;
	temp = ss.str();
	return temp;
}

//generates string from vector
string GenerateString(vector<Integer> v)
{
	string output;
	Integer temp;
	//assuming 0th position is invalid

	for(vector<Integer>::iterator itr = v.begin() + 1; itr != v.end(); itr++)
	{
		temp = *itr;

		output = output + IntegerToString(temp);
	}
	return output;
}


class LinkableRingSignProver
{
	private:

	//private key
	Integer private_key;
	
	//set member identity number
	unsigned int self_identity;

	public:

	//no. of members
	unsigned int num_members;

	//declare group order
	Integer q;

	//declare prime
	Integer p;

	//declare group generator
	Integer g;

	//set message
	Integer m;
	
	//public keys
	vector<Integer> public_keys;
	
	//constructor
	//@params: num_members, private key, message
	LinkableRingSignProver(unsigned int n, unsigned int identity, Integer msg) 
	{	
		self_identity = identity;
	
		num_members = n;
		m = msg;

		//update group parameters		
		GetGroupParameters(g, p, q);

		//populate public keys randomly
		public_keys.push_back(-1);				//0th position is invalid

		RandomPool rng;

		for(int i = 1; i <= num_members; i++)
		{
			public_keys.push_back(a_exp_b_mod_c(g, Integer(rng, 0, q - 1), p));			
		}		

		//generate private/public key pair
	
		private_key = Integer(rng, 0, q - 1);
		Integer public_key_self = a_exp_b_mod_c(g, private_key, p);

		//update public key in commonParameters class
		public_keys[self_identity] = public_key_self;
	}

	void GenerateSignature(Integer &c1, vector<Integer> &S, Integer &Y);

};


/*Calculate SHA1 hash*/
string Hash1(string input_string)
{
	CryptoPP::SHA1 hash;
	byte digest[CryptoPP::SHA1::DIGESTSIZE];
	string output;

	//calculate hash
	hash.CalculateDigest(digest, (const byte *)input_string.c_str(), input_string.size());
	
	//encode in Hex
	CryptoPP::HexEncoder encoder;
	CryptoPP::StringSink *SS = new CryptoPP::StringSink(output);
	encoder.Attach(SS);
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	
	//prepend 0x
	output = "0x" + output;
	return output;
}


/*Calculate SHA1 hash*/
string Hash2(string input_string, Integer p, Integer q, Integer g)
{
	CryptoPP::SHA1 hash;
	byte digest[CryptoPP::SHA1::DIGESTSIZE];
	string output;

	//calculate hash
	hash.CalculateDigest(digest, (const byte *)input_string.c_str(), input_string.size());
	
	//encode in Hex
	CryptoPP::HexEncoder encoder;
	CryptoPP::StringSink *SS = new CryptoPP::StringSink(output);
	encoder.Attach(SS);
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	
	//prepend 0x
	output = "0x" + output;
	
	//convert into integer format
	Integer value(output.c_str());
	
	value = value%q;

	//get the element in group
	value = a_exp_b_mod_c(g, value, p);
	
	output = IntegerToString(value);

	//prepend 0x
	output = "0x" + output;
	
	return output;
}

void LinkableRingSignProver::GenerateSignature(Integer &c1, vector<Integer> &S, Integer &Y)
{
	//compute h = H2(L)
	string h_str = GenerateString(public_keys);
	Integer h(Hash2(h_str, p, q, g).c_str());
	
	Integer y_tilde = a_exp_b_mod_c(h, private_key, p); 	//##CHECK mod parameter##

	RandomPool rng;
	Integer u(rng, 0, q - 1);

	Integer *ci = new Integer[num_members + 1];		//0th position is invalid. 1...n are valid corresponding to each member i.
	ci[0] = -1;

	Integer *si = new Integer[num_members + 1];
	si[0] = -1;	

	string temp = GenerateString(public_keys) + IntegerToString(y_tilde) + IntegerToString(m) + IntegerToString(a_exp_b_mod_c(g, u, p)) + IntegerToString(a_exp_b_mod_c(h, u, p));

	Integer b(Hash1(temp).c_str());

	ci[self_identity % num_members + 1] = b;	
	
	//initialise parameter for iteration
	unsigned int i = (self_identity % num_members) + 2;
	
	if(self_identity == num_members - 1)
		i = 1;
	
	for(; i != self_identity + 1; i = (i % num_members) + 1)
	{
		int j = i - 1;

		if(i == 1)
			j = num_members;

		si[j] = (Integer(rng, 0, q - 1));
		
		temp = Hash1(GenerateString(public_keys) + IntegerToString(y_tilde) + IntegerToString(m) + IntegerToString(a_times_b_mod_c(a_exp_b_mod_c(g, si[j], p), a_exp_b_mod_c(public_keys[j], ci[j], p), p)) + IntegerToString(a_times_b_mod_c(a_exp_b_mod_c(h, si[j], p), a_exp_b_mod_c(y_tilde, ci[j], p), p)));

		ci[i] = Integer(temp.c_str());
	}

	//update si_pi value (i.e. corresponding to self identity)
	si[self_identity] = (u % q - a_times_b_mod_c(private_key, ci[self_identity], q)) % q;
  	
	//update signature parameters (input args)
	S.clear();	
	S.push_back(-1);		//0th position is invalid	

	for(int i = 1; i <= num_members; i++)
		S.push_back(si[i]);

	c1 = ci[1];
	Y = y_tilde;
}

/*Define Verifier Class*/
class RingSignVerifier
{
	private:

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
	Integer m;
	
	public:

	RingSignVerifier(unsigned int num_members, vector<Integer> pub_keys, Integer q, Integer p, Integer g, Integer m)
	{
		this->p = p; this->q = q; this->g = g;
		this->m = m; this->num_members = num_members;
		
		//clear vector
		public_keys.clear();

		//iterator
		vector<Integer>::iterator itr;

		for(itr = pub_keys.begin(); itr != pub_keys.end(); itr++)
		{
			public_keys.push_back(*itr);
		}
		
		assert(public_keys.size() != 0);
	
	}
	
	bool VerifySignature(Integer &C, vector<Integer> &S, Integer &Y);
	
};

bool RingSignVerifier::VerifySignature(Integer &C, vector<Integer> &S, Integer &Y)
{
	string temp_str = Hash2(GenerateString(public_keys), p, q, g); 
	Integer h(temp_str.c_str());
	
	// zi and zi'
	Integer zi, zi_dash;
	Integer ci = C;	

	for(unsigned int i = 1; i <= num_members; i++)
	{
		zi = a_times_b_mod_c(a_exp_b_mod_c(g, S[i], p), a_exp_b_mod_c(public_keys[i], ci, p), p);
		zi_dash = a_times_b_mod_c(a_exp_b_mod_c(h, S[i], p), a_exp_b_mod_c(Y, ci, p), p);

		ci = Integer(Hash1(GenerateString(public_keys) + IntegerToString(Y) + IntegerToString(m) + IntegerToString(zi) + IntegerToString(zi_dash)).c_str());
	}

	Integer h_dash = Integer(Hash1(GenerateString(public_keys) + IntegerToString(Y) + IntegerToString(m) + IntegerToString(zi) + IntegerToString(zi_dash)).c_str());

	#ifdef DEBUG
	cout<<"C : "<<C<<endl;
	cout<<"H': "<<h_dash<<endl;
	#endif

	if(C == h_dash)
		return true;

	else
		return false;	
}

int main()
{
	//pass n, identity and message
	LinkableRingSignProver P(4, 2, Integer("1010101"));
		
	Integer C, Y;
	vector<Integer> S;
	P.GenerateSignature(C, S, Y);

	RingSignVerifier V(P.num_members, P.public_keys, P.q, P.p, P.g, P.m);

	if(V.VerifySignature(C, S, Y))
		cout<<"SUCCESS"<<endl;

	return 0;	
}
