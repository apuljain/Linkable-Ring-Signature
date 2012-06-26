#include "CommonFunctions.hpp"

/*Generate group parameters*/
void GetGroupParameters(Integer &g, Integer &p, Integer &q)
{
	AutoSeededRandomPool rnd;
	unsigned int bits = 1024;

  /* XXX Did we conclude (I can't remember) that the p, q, and g paramters 
     from the RFC will work for this? I think that they should work fine 
     for your applications (but please correct me if I'm wrong!) and using
     static parameters will save lots of time. Finding DH parameters takes
     ~10 seconds on my laptop.
   */

  /*
	 XXX Yes, those given in RFC will work fine. I'll make them static.
   */

	DH dh;
	dh.AccessGroupParameters().GenerateRandomWithKeySize(rnd, bits);

	if(!dh.GetGroupParameters().ValidateGroup(rnd, 3))
	{
		cout << ("Failed to validate prime and generator");
		exit(1);
	}
	size_t count = 0;

	p = dh.GetGroupParameters().GetModulus();
	count = p.BitCount();

	#ifdef DEBUG
	cout << "P (" << std::dec << count << "): " << std::hex << p << endl;
	#endif
	
	q = dh.GetGroupParameters().GetSubgroupOrder();
	count = q.BitCount();
	
	#ifdef DEBUG
	cout << "Q (" << std::dec << count << "): " << std::hex << q << endl;
	#endif

	g = dh.GetGroupParameters().GetGenerator();
	count = g.BitCount();

	#ifdef DEBUG
	cout << "G (" << std::dec << count << "): " << std::dec << g << endl;
	#endif
		
}

/*Convert CryptoPP::Integer to std::string*/
string IntegerToString(Integer a)
{
	stringstream ss;
	ss<<a;
	return ss.str();
}

/*Generates string from vector*/
string GenerateString(vector<Integer> v)
{
	string output;
	Integer temp;
	//assuming 0th position is invalid

   /*
	 XXX all vectors in the implementation are assumed to be indexed as per 
	 group members identity - starting from 1 upto n.

   XXX Even if the description in the paper uses 1-based indexing, it's almost
   always a good idea to use 0-based indexing in C/C++ code. Otherwise you will have
   to add "+1" all over the place and people who come to use your code
   later on will get confused.
   */

   /*
	XXX	 Point taken. Code updated as per usual indexing - starting from 0.
	 But now "identity" of members are assumed to be starting from 0..(n-1).
     Should identity still range from 1...n? If so, I'll have to use identity-1
	 to access arrays.
	*/

	for(vector<Integer>::iterator itr = v.begin(); itr != v.end(); itr++)
	{
		temp = *itr;
		output = output + IntegerToString(temp);
	}
	return output;
}


/*Calculate SHA1 hash*/
string Hash1(string input_string)
{
	CryptoPP::SHA1 hash;
	byte digest[CryptoPP::SHA1::DIGESTSIZE];
	string output;

	//calculate hash
	hash.CalculateDigest(digest, (const byte *)input_string.c_str(), 
					     input_string.size());

	//encode in Hex
	CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output), true);
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	
	//prepend 0x
	output = "0x" + output;
	/*
	 XXX Can't delete SS pointer otherwise as it is attached with output.
	 If deleted, it gives segmentation fault.

   XXX Right. Whoever calls the function Hash1() will have to free the
   memory using "delete." If no one frees the memory, then your problem
   will "leak" memory. Check out some tutorials on "C++ heap memory" or
   "C++ dynamic memory mangement" to see how to use new/delete.

   One tool that is extremely useful is "valgrind" (available on most
   Unix-like OSs). The valgrind tool checks whether your C/C++ program
   frees all of the heap memory that you have allocated. When I run
   valgrind on ringsign, the output looks like:

   ==6515== 
   ==6515== HEAP SUMMARY:
   ==6515==     in use at exit: 5,288 bytes in 15 blocks
   ==6515==   total heap usage: 104,047 allocs, 104,032 frees, 12,303,328 bytes allocated
   ==6515== 
   ==6515== LEAK SUMMARY:
   ==6515==    definitely lost: 432 bytes in 3 blocks
   ==6515==    indirectly lost: 672 bytes in 10 blocks
   ==6515==      possibly lost: 0 bytes in 0 blocks
   ==6515==    still reachable: 4,096 bytes in 1 blocks
   ==6515==         suppressed: 88 bytes in 1 blocks
   ==6515== Rerun with --leak-check=full to see details of leaked memory
   ==6515== 

  As you can see, there are 432 unfreed 
bytes (these might be your 
  hash strings). Be aware that there are sometimes memory leaks in big
  C/C++ libraries, like Crypto++, so some leaks might not be your 
  fault.
	*/	


  /*
 	XXX Actually, here memory leaks are not due to above allocation.
	Cryptopp automatically takes care of it.
	Since StringSink SS is attached to encoder object, encoder will
	delete the memory allocated for SS when it is itself destroyed.
	Refer:http://open.code-shop.com/trac/openzoep/browser/trunk/thirdp/crypto/cryptopp/Readme.txt?rev=1#L66
	
	XXX Memory leak, as observed, was due to other allocations in 
	LinkableRingSignProver.cpp. These are fixed now.
   */
	return output;
}


/*Calculate SHA1 hash
  @params: input_string to Hash function, group parameters: p, q, and g.
*/
string Hash2(string input_string, Integer p, Integer q, Integer g)
{
	CryptoPP::SHA1 hash;
	byte digest[CryptoPP::SHA1::DIGESTSIZE];
	string output;

	//calculate hash
	hash.CalculateDigest(digest, (const byte *)input_string.c_str(), 
						 input_string.size());
	
	//encode in Hex
	CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output), true);
	encoder.Put(digest, sizeof(digest));
	encoder.MessageEnd();
	
	//prepend 0x
	output = "0x" + output;
	
	//convert into integer format
	Integer value(output.c_str());

   /* 
	 FIXME Yet to figure out better way to produce elements in the group.
	 Given that there are reasonable no. of users (~1000s), and q is of
	 the order of ~160 bits, this should not cause any major problem.
	*/

  /*
    XXX I respectfully disagree. :-)

        The number of bits or number of users will not affect the security of
        your hashing method. In other words, if your hash function is even 
        a little insecure, and attacker might be able to use that little
        bit of insecurity to his/her advantage. Since you probably don't
        want to get stuck on this, a FIXME comment is probably fine for now.
        You can also create a TODO file with a list of issues like this
        that you want to come back to later.
   */

	/*
		XXX Modulo method to map hash elements seems to be working fine.
		I'm not aware of the possible security holes due to this. However,
		I'll add this issue into TODO file to address it in future!
	*/

	value = value % q;

	//get the element in group
	value = a_exp_b_mod_c(g, value, p);
	
	output = IntegerToString(value);

	/*DO NOT PREPEND 0x - OUTPUT STRING IS ALREADY IN DECIMAL!*/
	/*THIS HAD BEEN CAUSING THE WHOLE PROBLEM SO LONG.*/
	//prepend 0x				
	//output = "0x" + output; 

	/*
	 XXX Can't delete SS pointer otherwise as it is attached with output.
	 If deleted, it gives segmentation fault.
	*/

  /* XXX Please refer to my comment on Hash1() */

  /*
     XXX Please refer to my answer for Hash1().
  */		
	
	return output;
}

