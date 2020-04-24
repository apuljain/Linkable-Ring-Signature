#include "LinkableRingSignProver.hpp"

/*
  Constructor to initialize parameters.
  @params: no. of members in the group, identity of member, g, p, q, public_keys,
   private_key.
*/

/*
   XXX You can use this C++ syntax shortcut to simplify your 
   constructor a little bit:

        LinkableRingSignProver::LinkableRingSignProver(unsigned int n, unsigned int identity, string msg) 
          _self_identity(identity),
          num_members(n),
          m(msg)
        {	
          //update group parameters
          ...

*/

/*
	XXX Done! But it looks a bit messy this time because of too many
	parameters.

	XXX Too many parameters can be avoided if we assume g, p, q will be set
	by accessing through the class object as these are public variables.
*/

LinkableRingSignProver::LinkableRingSignProver(unsigned int n, 
					       unsigned int identity, 
                                               Integer g_in, Integer p_in, 
                                               Integer q_in,
                                               vector<Integer> public_keys_in,
                                               Integer private_key_in):
     	 _private_key(private_key_in),
 	 _self_identity(identity),
	 num_members(n),
	 g(g_in), p(p_in), q(q_in)
{
	for(vector<Integer>::iterator itr = public_keys_in.begin(); 
             itr != public_keys_in.end(); itr++)
	{
	 	public_keys.push_back(*itr);
	}
}

/*Function to generate signature.
  returns updated arguments (i.e. signature : (c1, s1...sn, y)) 
*/
void LinkableRingSignProver::GenerateSignature(string message, Integer &c1,
					       vector<Integer> &S, Integer &Y)
{
	//set message
	this->m = message;

	//compute h = H2(L)
	string h_str = GenerateString(public_keys);
	Integer h(Hash2(h_str, p, q, g).c_str());
	
	Integer y_tilde = a_exp_b_mod_c(h, _private_key, p); 
	RandomPool rng;
	Integer u(rng, 0, q - 1);

	Integer *ci = new Integer[num_members];
	Integer *si = new Integer[num_members];

	string temp = GenerateString(public_keys) + IntegerToString(y_tilde) + 
		      m + IntegerToString(a_exp_b_mod_c(g, u, p)) +
		      IntegerToString(a_exp_b_mod_c(h, u, p));

	Integer b(Hash1(temp).c_str());

	ci[(_self_identity + 1) % num_members] = b;
	
	//initialise parameter for iteration
	unsigned int i = (_self_identity + 2) % num_members;
	
	for(; i != (_self_identity + 1 % num_members); i = (i + 1) % num_members)
	{
		int j = (i - 1) % num_members;
		si[j] = (Integer(rng, 0, q - 1));
		
	
		temp = Hash1(GenerateString(public_keys) + 
			     IntegerToString(y_tilde) + m +
		       	     IntegerToString(a_times_b_mod_c(a_exp_b_mod_c(g, si[j], p),
			     a_exp_b_mod_c(public_keys[j], ci[j], p), p)) +
			     IntegerToString(a_times_b_mod_c(a_exp_b_mod_c(h, si[j], p),
			     a_exp_b_mod_c(y_tilde, ci[j], p), p)));

		ci[i] = Integer(temp.c_str());
	}

	//update si_pi value (i.e. corresponding to self identity)
	si[_self_identity] = (u % q - a_times_b_mod_c(_private_key,
					              ci[_self_identity], q)) % q;
  	
	//update signature parameters (input args)
	S.clear();

	for(unsigned int i = 0; i < num_members; i++)
		S.push_back(si[i]);

	c1 = ci[0];
	Y = y_tilde;
	
	//free memory		
	delete[] ci;	/* RESPONSIBLE FOR MEMORY LEAKS!!*/
	delete[] si;
}

