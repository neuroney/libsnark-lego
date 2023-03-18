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

#include "membership_did.hpp"

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/field_utils/field_utils.hpp>

#include <complex>
#include <stdexcept>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>


using namespace std;
using namespace membership;
using namespace libsnark;
using namespace memDID;

const string USAGE = 
    "Set membership for DID test\n\n\tUSAGE:\n\t\t./MembershipDID [Version] <batching_size> <set_size>\n\n\tVersion:\n\t\tnonopt: Non-optimized version; Membership proof: (W, C, k, h)\n\n\t\topt: Optimized version(with using PoKE); Membership proof: (W, C, k', h, Q, l)\n";

typedef libff::Fr<libff::default_ec_pp> FieldT;

typedef struct {
    string version;
    int batching_size;
    int set_size;
}input_args;


int main(int argc, char* argv[]) {
    input_args* args = new input_args;

    membership::public_param* pp = new membership::public_param();
    membership::mem_proof* memProof = new membership::mem_proof();
    
    vector<attr_info*> tmp_info;
    vector<credentials*> tmp_credential;
    holders* test_holder = new holders();
    test_holder->info = tmp_info;
    test_holder->holderCred = tmp_credential;

    bool is_opt, pass_vfy;

    if(argc != 4) {
        cout << "Invalid argument error!" << endl << endl;
        cout << USAGE << endl;
        return 0;
    }

    args->version = argv[1];
    args->batching_size = atoi(argv[2]);
    args->set_size = atoi(argv[3]);

    cout << args->version << endl;

    if(args->version == "nonopt") {
        is_opt = false;
    }
    else if(args->version == "opt") {
        is_opt = true;
    }
    
    vector<BIGNUM*> S; //element set S
    vector<holders*> holder_set;
    BIGNUM* ACC = BN_new(); // Accumulator initialization with value "1"
    BN_copy(ACC, BN_value_one());
    
    // Assume that there have been some existing elements 
    for(int i = 0; i < args->set_size; i++) {
        BN_CTX* bn_ctx = BN_CTX_new();
        memDID::holders* old_holder = new holders;
        old_holder->id = BN_new();
        memDID::credentials* tmp_cred = new credentials;
        tmp_cred->addrIssuer = BN_new();
        tmp_cred->c = BN_new();

        BIGNUM* bn_ik = BN_new();
        BN_rand(bn_ik, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        
        BN_rand(old_holder->id, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        int rand = 0;
        BIGNUM* bn_h = BN_new();
        memDID::addrGen(tmp_cred->addrIssuer, bn_ik);

        attr_info* tmp_info = new attr_info;
        tmp_info->attr_key = "age";
        tmp_info->attr_val = i + 20;
        old_holder->info.push_back(tmp_info);

        do {
            memDID::attrHash(bn_h, old_holder->id, old_holder->info.back()->attr_key, old_holder->info.back()->attr_val, rand);
            memDID::credGen(tmp_cred->c, tmp_cred->addrIssuer, bn_h);
            rand += 1;
        }while(!BN_is_prime(tmp_cred->c, 5, NULL, bn_ctx, NULL));
    
    
        tmp_cred->attrCred_key = "age";
        tmp_cred->attrCred_val = i + 20;
        tmp_cred->rand = rand;
        
        old_holder->holderCred.push_back(tmp_cred);

        

        S.push_back(tmp_cred->c);
        holder_set.push_back(old_holder);
        BN_CTX_free(bn_ctx);
    }

    libsnark::default_r1cs_gg_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    libff::G1_vector<libsnark::default_r1cs_gg_ppzksnark_pp> commit_base; 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark;

    r1cs_gg_ppzksnark_keygen(snark, 13100, args->batching_size);

    r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> snark_key = r1cs_gg_ppzksnark_generator<libsnark::default_r1cs_gg_ppzksnark_pp>(snark.constraint_system);
    snark_key.pk = libff::reserialize<r1cs_gg_ppzksnark_proving_key<default_r1cs_gg_ppzksnark_pp>>(snark_key.pk);
    snark_key.vk = libff::reserialize<r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp>>(snark_key.vk);

    r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> snark_proof; 

    for (int i = 0; i < args->batching_size; i++) {
        commit_base.push_back(snark_key.pk.A_query[i+1]);
    }



    setup(pp, test_holder);
    accumulate(pp, S, ACC);
    for(int i = 0; i < args->batching_size; i++) {
        issue(pp, test_holder, S, ACC);
    }
    vector<BIGNUM*> _credentials;
    for(auto x: test_holder->holderCred) {
        _credentials.push_back(x->c);
    }
    proof(snark, snark_key, snark_proof, pp, commit_base, S, _credentials, memProof, is_opt);
    pass_vfy = verify(snark, snark_key.vk, snark_proof, pp, ACC, S, memProof, is_opt);

    if(pass_vfy) {
        membership::print_debug("Verification Pass");
    }
    else {
        membership::print_debug("Verification Failed");
    }


    return 0;
}