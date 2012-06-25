#include "LinkableRingSignVerifier.hpp"

LinkableRingSignVerifier::LinkableRingSignVerifier(unsigned int num_members_in,
												   vector<Integer> pub_keys,
	 											   Integer q_in, Integer p_in,
												   Integer g_in, string m_in):
	num_members(num_members_in),
	q(q_in), p(p_in), g(g_in),
	m(m_in)
{
  /*
    XXX You might want to change the constructor parameters to names
    that don't conflict. For example: in_p, in_q, etc
  */
  /*
	XXX Done!
   */
	
	//clear vector
	public_keys.clear();

	for(vector<Integer>::iterator itr = pub_keys.begin(); itr != pub_keys.end();
	    itr++)
	{
		public_keys.push_back(*itr);
	}
	
	assert(public_keys.size() != 0);
}

/*Function to verify signature
@params: c1, s1..sn, y_tilde -- refer algo pdf for details.
*/
bool LinkableRingSignVerifier::VerifySignature(Integer &C, vector<Integer> &S,
											   Integer &Y)
{
	string temp_str = Hash2(GenerateString(public_keys), p, q, g); 
	Integer h(temp_str.c_str());
	
	// zi and zi'
	Integer zi, zi_dash;
	Integer ci = C;	

	for(unsigned int i = 0; i < num_members; i++)
	{
		zi = a_times_b_mod_c(a_exp_b_mod_c(g, S[i], p), a_exp_b_mod_c(
							 public_keys[i], ci, p), p);

		zi_dash = a_times_b_mod_c(a_exp_b_mod_c(h, S[i], p),
								  a_exp_b_mod_c(Y, ci, p), p);

		ci = Integer(Hash1(GenerateString(public_keys) + IntegerToString(Y) + 
			 m + IntegerToString(zi) + IntegerToString(zi_dash)).c_str());
	}

	
	#ifdef DEBUG
	cout << "C : " << C <<endl;
	cout << "H': " << ci <<endl;
	#endif

	return (C == ci);
}
