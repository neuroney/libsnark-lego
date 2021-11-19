#ifndef LEGO_CP_SNARK_TCC_
#define LEGO_CP_SNARK_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_g1.hpp>

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/membership/membership_snark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>


using namespace std;

namespace membership_snark
{
    template<typename ppT>
    struct Fr_element{
        vector<libff::Fr<ppT>> vec_s;
        vector<libff::Fr<ppT>> vec_r;
        vector<libff::Fr<ppT>> vec_u;
    };

    template<typename ppT>
    struct G1_element{    
        libff::G1_vector<ppT> vec_s;
        libff::G1_vector<ppT> vec_r;
        libff::G1_vector<ppT> vec_u;
    };

    template<typename ppT>
    struct commit_chunk{
        libff::G1<ppT> G_s;
        libff::G1<ppT> G_r;
        libff::G1<ppT> G_u;
    };

    template <typename ppT>
    void membership_statement<ppT>::print() const
    {
        libff::print_indent();
        printf("* Commitments : \n");
        for(int i=0;i < this->ck.size();i++){
            this->ck[i].print();
        }
    }

    template<typename ppT>
    void membership_statement<ppT>::commitIO_crs(vector<string> bn_vector_s, vector<string> bn_vector_r , vector<string> bn_vector_u , libff::G1<ppT> &commit_res){
        Fr_element<ppT>* fr_vec = new Fr_element<ppT>;
        G1_element<ppT>* group_vec = new G1_element<ppT>;
        commit_chunk<ppT>* com_chunk = new commit_chunk<ppT>;

        for(int i = 0; i < bn_vector_s.size(); i++) {
            fr_vec->vec_s.push_back(libff::Fr<ppT>(bn_vector_s[i].c_str()));
        }

        for(int i = 0; i < bn_vector_r.size(); i++) {
            fr_vec->vec_r.push_back(libff::Fr<ppT>(bn_vector_r[i].c_str()));
        }
        
        for(int i  = 0 ; i < bn_vector_u.size(); i++) {
            fr_vec->vec_u.push_back(libff::Fr<ppT>(bn_vector_u[i].c_str()));
        }
        

        for(int i = 0; i < fr_vec->vec_s.size(); i++) {
            group_vec->vec_s.push_back(fr_vec->vec_s[i] * ck[i]);
            com_chunk->G_s = com_chunk->G_s + group_vec->vec_s[i];
        }
        
        for(int i = 0; i < fr_vec->vec_r.size(); i++) {
            group_vec->vec_r.push_back(fr_vec->vec_r[i] * ck[i + (fr_vec->vec_s.size())]);
            com_chunk->G_r = com_chunk->G_r + group_vec->vec_r[i];
        }

        for(int i = 0; i < fr_vec->vec_u.size(); i++) {
            group_vec->vec_u.push_back(fr_vec->vec_u[i] * ck[i + (fr_vec->vec_s.size() + fr_vec->vec_r.size())]);
            com_chunk->G_u = com_chunk->G_u + group_vec->vec_u[i];
        }     
        
        commit_res = com_chunk->G_s + com_chunk->G_r + com_chunk->G_u;
    }
} // namespace libsnark

#endif