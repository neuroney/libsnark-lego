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
#include <libff/algebra/fields/field_utils.hpp>

#include <complex>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/public_params.hpp>

#include <complex>
#include <stdexcept>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

#include <libsnark/jsnark_interface/CircuitReader.hpp>
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/membership/membership_snark.hpp>

using namespace std;
using namespace membership;
using namespace libsnark;

typedef libff::Fr<libff::default_ec_pp> FieldT;

const string USAGE = 
    "Set membership test\n\n\tUSAGE:\n\t\t./MembershipTest [Version] <batching_size> <set_size>\n\n\tVersion:\n\t\tnonopt: Non-optimized version; Membership proof: (W, C, k, h)\n\n\t\topt: Optimized version(with using PoKE); Membership proof: (W, C, k', h, Q, l)\n";

// This file executes zk-SNARK friendly membership proof from 

// Usage:
// ./MembershipTest [Version] <batching_size> <set_size> 
// Version: 
//      nonopt: non-optimized version, membership proof: W, C, k, h
//      opt: optimized version (with PoKE), membership proof: W, C, k', h, Q, l


typedef struct {    
    string version;
    int batching_size;
    int set_size;
}input_args;

template<typename ppT> 
void r1cs_gg_ppzksnark_keygen(libsnark::r1cs_example<libff::Fr<ppT>> &example, size_t num_constraints, size_t input_size) {
    libff::print_header("(enter) Test R1CS GG-ppzkSNARK");

    const bool test_serialization = true;
    example = generate_r1cs_example_with_binary_input<libff::Fr<ppT>>(num_constraints, input_size);

    assert(bit);    
 
    libff::print_header("(leave) Test R1CS GG-ppzkSNARK");
}

int main(int argc, char* argv[]) {
    int ver_flag;
    bool success_vfy;

    if(argc != 4) {
        cout << "Invalid argument error!" << endl << endl;
        cout << USAGE << endl;
        return 0;
    }

    input_args* args = new input_args;

    args->version = argv[1];
    args->batching_size = atoi(argv[2]); // the number of existing user sets
    args->set_size = atoi(argv[3]); // the number of users to be proved

    if(args->version == "nonopt") {
       ver_flag = 0;
    }
    else if(args->version == "opt") {
        ver_flag = 1;
    }
    else {
        cout << USAGE << endl;
        return 0;
    }

    // This is only for getting the commitment key, which is G_1, G_2, ... in SNARK. 
    // Thus, example is used. This part is used only for getting commitment base. 
    // (Example proof is used for checking wheter the snark proof is generated and verified well or not along membership.)
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    libff::G1_vector<default_r1cs_gg_ppzksnark_pp> commit_base; 
    r1cs_example<libff::Fr<default_r1cs_gg_ppzksnark_pp>> snark;

    r1cs_gg_ppzksnark_keygen<default_r1cs_gg_ppzksnark_pp>(snark, 13077, args->batching_size);

    r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> snark_key = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(snark.constraint_system);
    snark_key.pk = libff::reserialize<r1cs_gg_ppzksnark_proving_key<default_r1cs_gg_ppzksnark_pp>>(snark_key.pk);
    snark_key.vk = libff::reserialize<r1cs_gg_ppzksnark_verification_key<default_r1cs_gg_ppzksnark_pp>>(snark_key.vk);

    r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> snark_proof; 

    for (int i = 0; i < args->batching_size; i++) {
        commit_base.push_back(snark_key.pk.A_query[i+1]);
    }

    // Initialization public parameter struct and membership proof struct.
    public_param* pp = new public_param;
    mem_proof* proof = new mem_proof;
    
    vector<BIGNUM*> S; // User set S.
    
    BN_CTX* bn_ctx = BN_CTX_new();

    // Initialization accumulator with value one. 
    BIGNUM* ACC = BN_new();
    BN_copy(ACC, BN_value_one());
    
    // Existing user(assume) generation
    for(int i = 0; i < args->set_size; i++) {
        BIGNUM* old_sk = BN_new();
        BN_rand(old_sk, 64, 1, 0);
        BIGNUM* old_element = BN_new();
        Hash1(old_element, old_sk);
        S.push_back(old_element);
    }

    // New user generation to be added 
    vector<BIGNUM*> user_element; 
    for(int i = 0; i < args->batching_size; i++) {
        BIGNUM* user_sk = BN_new();
        BN_rand(user_sk, 64, 1, 0);
        BIGNUM* new_usr = BN_new();
        Hash1(new_usr, user_sk);
        user_element.push_back(new_usr);
    }
    
    if(!ver_flag){
        print_debug("(enter) Membership(non-opt) test out of circuit");    
    }
    else{
        print_debug("(enter) Membership(opt) test out of circuit");
    }

    setup(pp, args->batching_size);    
    add(S, user_element);    
    accumulate(pp, S, ACC);
    if(!ver_flag) {
        compute(pp, snark_key, snark, commit_base, S, user_element, proof, snark_proof);
        success_vfy = verify(pp, snark_key.vk, snark, ACC, S, proof, snark_proof);
       
        print_debug("(leave) Membership(non-opt) test out of circuit");
        if(success_vfy) {
            cout << "Verification Pass" << endl;
        }    
        else {
            cout << "Verification Failed" << endl;
        }
        print_debug("Membership proof size");
        cout << "k: " << BN_num_bits(proof->k) << endl;
    }
    else {
        optCompute(pp, snark_key, snark, commit_base, S, user_element, proof, snark_proof);
        success_vfy = optVerify(pp, snark_key.vk, snark, ACC, S, proof, snark_proof);
        print_debug("(leave) Membership(opt) test out of circuit");
        if(success_vfy) {
            cout << "Verification Pass" << endl;
        }
        else {
            cout << "Verification Failed" << endl;
        }
        print_debug("Membership proof size");
        cout << "k': " << BN_num_bits(proof->opt_k) << endl << endl;
    }

    pp_clear(pp);
    BN_CTX_free(bn_ctx);
    
    return 0;
}
