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


#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>   
#include <libsnark/zk_proof_systems/ppzksnark/membership/membership_snark.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>



using namespace std;

namespace membership {
    using def_pp = libsnark::default_r1cs_gg_ppzksnark_pp;

    typedef struct {
        fmpz_t N;
        fmpz_t V;
        vector<BIGNUM*> vec_prime;
    }public_param;

    typedef struct {
        BIGNUM* W;
        BIGNUM* C_x;
        BIGNUM* C_y;
        BIGNUM* k;
        BIGNUM* opt_k;
        BIGNUM* h;
        BIGNUM* Q;
        BIGNUM* l;
    }mem_proof;

    int pp_init(public_param* pp);
    
    int pp_clear(public_param* pp);

    int groupGen(public_param* pp);
    
    void print_debug(const char* msg);

    void print_BN(BIGNUM* p, string s);

    void Hash1(BIGNUM* res, BIGNUM* sk);

    void Hash2(BIGNUM* ret, BIGNUM* W, BIGNUM* C_x, BIGNUM* C_y, BIGNUM* R);

    void setup(public_param* pp, int n);

    void add(vector<BIGNUM*> &S, vector<BIGNUM*> u);

    void accumulate(public_param* pp, vector<BIGNUM*> S, BIGNUM* &ACC);

    void compute(public_param* pp, const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key, 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    libff::G1_vector<def_pp> &commit_base, vector<BIGNUM*> S, vector<BIGNUM*> u, 
    mem_proof* proof, libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof);

    void optCompute(public_param* pp, const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key, 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    libff::G1_vector<def_pp> &commit_base, vector<BIGNUM*> S, vector<BIGNUM*> u, 
    mem_proof* proof, libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof);

    bool verify(public_param* pp, libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, BIGNUM* &ACC, 
    vector<BIGNUM*> S, mem_proof* proof, libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof);

    bool optVerify(public_param* pp, libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, BIGNUM* &ACC, 
    vector<BIGNUM*> S, mem_proof* proof, libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof);
}