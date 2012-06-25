#include <limits.h>
#include "StandardLibraryHeaders.h"
#include "LinkableRingSignProver.h"
#include "CommonFunctions.h"
#include "LinkableRingSignProver.h"
#include "RingSignVerifier.h"
#include "gtest/gtest.h"

/*CommonFunctions TESTS*/
//--------------------------------------------------------------
//IntegerToStringTest
TEST(IntegerToStringTest, PositiveNos) { 

	Integer a = 123;
	Integer b("0xA");
    EXPECT_EQ ("18.", IntegerToString(18));
	EXPECT_EQ ("10.", IntegerToString(b));
	EXPECT_EQ ("123.", IntegerToString(a));
}

TEST(IntegerToStringTest, NegativeNos) { 

	Integer a = -123;
	//NOTE: -ve numbers in hexadecimal format is not supported.	
	Integer b("0x-A");
    EXPECT_EQ("-18.", IntegerToString(-18));
//	EXPECT_EQ("-10.", IntegerToString(b));
	EXPECT_EQ("-123.", IntegerToString(a));
}

//--------------------------------------------------------------
//GenerateStringTest
TEST(GenerateStringTest, LongStrings) {

	vector<Integer> vec_1, vec_2;
	Integer temp;
	string test;
	for(int i = 1; i <= 5; i++)
	{		
		vec_1.push_back(-1);
		//CAUTION: remember to pass large integers as string. otherwise overflow occurs.
		temp = Integer("123456789123456789123456789");
		vec_2.push_back(temp);
		test += "123456789123456789123456789.";
	}

	EXPECT_EQ("-1.-1.-1.-1.-1.", GenerateString(vec_1));
	EXPECT_EQ(test, GenerateString(vec_2));
}

//--------------------------------------------------------------
//GenerateGroupParameters
TEST(GenerateGroupParametersTest, IntegerInputs) {

	Integer p, q, g;
	GetGroupParameters(g, p, q);

	EXPECT_EQ(1, a_exp_b_mod_c(g, q, p));
}

//--------------------------------------------------------------
//LinkableRingSignProver constructor check
TEST(LinkableRingSignProverTest, DefaultArgs) {

	unsigned int n = 100, identity = 12;
	Integer g_in, p_in, q_in, private_key_in;
	vector<Integer> public_keys_in;

	GetGroupParameters(g_in, p_in, q_in);

	RandomPool rng;

	//set safe_NO for private key here.
	Integer SAFE_NO = 1231;
	//generate private_public keys
	for(unsigned int i = 1; i <= n; i++)
	{
		Integer a = Integer(rng, SAFE_NO, q_in - 1);
		if(i == 11)
			private_key_in = a;		
		public_keys_in.push_back(a_exp_b_mod_c(g_in, a, p_in));
	}
	
	LinkableRingSignProver P(n, identity, g_in, p_in, q_in, public_keys_in, private_key_in);
	EXPECT_EQ(P.num_members, n);
	EXPECT_EQ(P.g, g_in);	EXPECT_EQ(P.q, q_in); EXPECT_EQ(P.p, p_in);
	
	vector<Integer>::iterator itr = public_keys_in.begin();
	unsigned int j = 0;
	for(itr = public_keys_in.begin(); itr != public_keys_in.end(); itr++)
	{
		ASSERT_EQ(P.public_keys[j++], *itr);
	}
}


