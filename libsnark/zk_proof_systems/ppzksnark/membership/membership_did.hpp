#include <iostream>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <flint/fmpz.h>
#include <vector> 
#include <map>
#include <math.h>
#include <time.h>
#include <string.h>
#include <string>
#include <cstdlib>
#include <ctime>
#include <cassert>
#include <cstdio>

#include "membership.hpp"

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/field_utils/field_utils.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>

#include <complex>
#include <stdexcept>

using namespace std;


namespace memDID {
    using def_pp = libsnark::default_r1cs_gg_ppzksnark_pp;

    typedef struct {
        string attr_key;
        int attr_val;
    }attr_info;

    typedef struct {
        BIGNUM* addrIssuer;
        int rand;
        string attrCred_key;
        int attrCred_val;
        BIGNUM* c;    
    }credentials;

    typedef struct {
        vector<credentials*> holderCred;
        vector<attr_info*> info;
        BIGNUM* id;
    }holders;

     typedef struct {
        BIGNUM* addr_issuer;
        BIGNUM* h;
        BIGNUM* c;
    }transactions;

    

    void r1cs_gg_ppzksnark_keygen(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> &snark_ex, 
    int num_constraints, int input_size);
    
    void attrHash(BIGNUM* ret, BIGNUM* userID, string attrKey, int attrVal, int rand_num);

    void addrGen(BIGNUM* ret, BIGNUM* issuer_key);
    
    void credGen(BIGNUM* ret, BIGNUM* addrIssuer, BIGNUM* h);
    
    void userGen(holders* holder);
    
    void add(vector<BIGNUM*> &S, BIGNUM* elem);

    bool is_satisfied(holders* holder);
    
    void setup(membership::public_param* pp,  holders *holder);
    
    void issue(membership::public_param* pp, holders* holder, vector<BIGNUM*> &S, BIGNUM* &ACC);
    
    void proof(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> _snark, 
    const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof,
    membership::public_param* pp, libff::G1_vector<def_pp> &com_base, vector<BIGNUM*> S, 
    vector<BIGNUM*> _credentials, membership::mem_proof* memProof, bool is_opt);

    bool verify(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> _snark, 
    libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof,
    membership::public_param* pp, BIGNUM* &ACC, vector<BIGNUM*> S, membership::mem_proof* memProof, bool is_opt);
}


