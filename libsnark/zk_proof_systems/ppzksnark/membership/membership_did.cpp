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

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/field_utils/field_utils.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>

#include <complex>
#include <stdexcept>

#include "membership.hpp"


#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>


using namespace std;
using def_pp = libsnark::default_r1cs_gg_ppzksnark_pp;

namespace memDID {
    const int userID_len = 256;

// Actually, this struct include key, value, type. 
// However, we just fix the attribute type to be integer since this is very simple example.
// This will be modified in near future. 
    typedef struct {
        string attr_key;
        int attr_val;
    }attr_info;

    typedef struct {
        BIGNUM* addrIssuer;
        int* rand;
        string attrCred_key;
        int attrCred_val;
        BIGNUM* c;    
    }credentials;

    typedef struct {
        vector<credentials*> holderCred;
        vector<attr_info*> info;
        BIGNUM* id;
    }holders;

// The signature is omitted for now. Since we just show the flow of credential with membership. 
    typedef struct {
        BIGNUM* addr_issuer;
        BIGNUM* h;
        BIGNUM* c;
    }transactions;

    
    void r1cs_gg_ppzksnark_keygen(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> &snark_ex, int num_constraints, int input_size) {
        const bool test_serialization = true;
        snark_ex = libsnark::generate_r1cs_example_with_binary_input<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>>(num_constraints, input_size);

        assert(bit);    
    }
    
    // Is randomness is essential in this function?
    void attrHash(BIGNUM* ret, BIGNUM* userID, string attrKey, int attrVal, int rand_num) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(userID, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(userID));
        memcpy(temp, &attrKey, sizeof(string));
        SHA256_Update(&sha256, temp, sizeof(string));
        memcpy(temp, &attrVal, sizeof(int));
        SHA256_Update(&sha256, temp, sizeof(int));
        memcpy(temp, &rand_num, sizeof(int));
        SHA256_Update(&sha256, temp, sizeof(int));

        SHA256_Final(hash_digest, &sha256);   

        BN_bin2bn(hash_digest, 32, ret);
    }

    // Isn't randomness needed in this function? randomness "r"
    void credGen(BIGNUM* ret, BIGNUM* addrIssuer, BIGNUM* h) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(addrIssuer, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(addrIssuer));
        BN_bn2bin(h, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(h));

        SHA256_Final(hash_digest, &sha256);   

        BN_bin2bn(hash_digest, 32, ret);
    }

    // Arbitrary holder generation
    // holder has some ID, which is generated randomly in bignum form. 
    // This ID can be replaced as it needs. 
    void userGen(holders* holder) {
        // holder ID generation
        holder->id = BN_new();
        BN_rand(holder->id, userID_len, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        
        // Attribution information sample. 
        string temp_attr_key = "age";
        int val = 20;
        attr_info* tmp_info = new attr_info;
        tmp_info->attr_key = temp_attr_key;
        tmp_info->attr_val = val;
        
        holder->info.push_back(tmp_info);
    }

    void addrGen(BIGNUM* ret, BIGNUM* issuer_key) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(issuer_key, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(issuer_key));

        SHA256_Final(hash_digest, &sha256);   

        BN_bin2bn(hash_digest, 32, ret);
    }

    // User generation + Membership Setup
    void setup(membership::public_param* pp, holders* holder) {
        libff::start_profiling();
        libff::enter_block("Call to setup membership");

        membership::setup(pp);
        userGen(holder);

        libff::leave_block("Call to setup for membership");
    }

    void add(vector<BIGNUM*> &S, BIGNUM* elem) {
        S.push_back(elem);
    }

    // Issuer checks that holder satisfies some requirements for approval.
    // In current state, we only deal with about age requirement.
    bool is_satisfied(holders* holder) {
        bool pass = false;
        for(auto x: holder->info) {
            if(x->attr_key == "age") {
                if(x->attr_val > 19) {
                    pass = true;
                }
            }
        }
        return pass;
    }

    // Issuer generates set element only if holder satisfies some attributes that issuer requires
    // This would be changed according to which attribute is used.
    // In current state, this value is set as true for the brevity. 
    void issue(membership::public_param* pp, holders* holder, vector<BIGNUM*> &S, BIGNUM* &ACC) {
        libff::start_profiling();
        libff::enter_block("Call to issuer");

        BIGNUM* bn_issuer_key = BN_new();
        BIGNUM* addr = BN_new();
        BN_CTX* bn_ctx = BN_CTX_new();
        BN_rand(bn_issuer_key, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        addrGen(addr, bn_issuer_key);

        credentials* tmp_cred = new credentials;
        tmp_cred->addrIssuer = BN_new();
        tmp_cred->c = BN_new();
        BN_copy(tmp_cred->addrIssuer, addr);
        // Strictly, attr_key and attr_val is different from what attribute holder requests. 
        // In current state, we fix this as last element for ease. 
        tmp_cred->attrCred_key = holder->info.back()->attr_key;
        tmp_cred->attrCred_val = holder->info.back()->attr_val;

        transactions* tx = new transactions;
        tx->addr_issuer = BN_new();
        BN_copy(tx->addr_issuer, addr);
        tx->h = BN_new();
        tx->c = BN_new();

        bool _satisfied = is_satisfied(holder);

        int rand_num = 0;
        string ACC_val;
        
        if(!_satisfied) {
            membership::print_debug("This holder does not satisfy the requirement.");
            abort();
        }
        
        do {
            attrHash(tx->h, holder->id, holder->info.back()->attr_key, holder->info.back()->attr_val, rand_num);
            credGen(tx->c, addr, tx->h);
            rand_num += 1;
        }while(tx->c, 5, NULL, bn_ctx, NULL);

        tmp_cred->rand = &rand_num;
        tmp_cred->c = tx->c;
        
        add(S, tx->c);
        ACC_val = BN_bn2dec(ACC);
        // membership::print_debug("Element test in issue function");
        // cout << BN_bn2hex(tx->c) << endl << endl;
        // cout << BN_bn2hex(tmp_cred->c) << endl << endl;

        if(ACC_val == "1") {
            membership::print_debug("DEBUG ACCUMULATE");
            membership::accumulate(pp, S, ACC);
            cout << BN_bn2dec(ACC) << endl;
        }
        else {
            BIGNUM* modN = BN_new();
            BN_hex2bn(&modN, fmpz_get_str(NULL, 16, pp->N));
            BN_mod_exp(ACC, ACC, tx->c, modN, bn_ctx);
        }
        
        holder->holderCred.push_back(tmp_cred);

        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to issuer");
    }

    void proof(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> _snark, 
        const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof,
    membership::public_param* pp, libff::G1_vector<def_pp> &com_base, vector<BIGNUM*> S, 
    vector<BIGNUM*> _credentials, membership::mem_proof* memProof, bool is_opt) {
        if(!is_opt) {
            membership::compute(_snark, snark_key, snark_proof, pp, com_base, S, _credentials, memProof);
        }
        else {
            membership::print_debug("opt in");
            membership::optCompute(_snark, snark_key, snark_proof, pp, com_base, S, _credentials, memProof);
        }
    }

    bool verify(libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> _snark, 
    libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof,
    membership::public_param* pp, BIGNUM* &ACC, vector<BIGNUM*> S, membership::mem_proof* memProof, bool is_opt) {
        if(!is_opt) {
            return membership::verify(_snark, snark_vk, snark_proof, pp, ACC, S, memProof);
        }
        else {
            return membership::optVerify(_snark, snark_vk, snark_proof, pp, ACC, S, memProof);
        }
    }
}
