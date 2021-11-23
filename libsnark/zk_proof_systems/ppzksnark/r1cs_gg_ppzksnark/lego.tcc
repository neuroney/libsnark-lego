/** @file
*****************************************************************************

Implementation of interfaces for LegoGroth


*****************************************************************************
* @author     Matteo Campanelli
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#ifndef R1CS_GG_PPZKSNARK_LEGO_TCC_
#define R1CS_GG_PPZKSNARK_LEGO_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>


namespace libsnark {


template<typename ppT>
    lego_ck<ppT> lego_gen_ck(auto opn_size) {
        const libff::G1<ppT> g1_generator = libff::G1<ppT>::random_element();

        std::vector<libff::G1<ppT>> ck(opn_size);
        for (auto i = 0; i < ck.size(); i++) {
            ck[i] = libff::Fr<ppT>::random_element()*g1_generator;
        }
        return ck;
    }

template<typename ppT>
    lego_keypair<ppT> lego_kg(const auto &ck, const auto &cs) {
        const libff::G1<ppT> g1_generator = libff::G1<ppT>::random_element();
        const libff::G2<ppT> G2_gen = libff::G2<ppT>::random_element();

        /* -- Gro16 setup -- */ 
        auto gro16cs = cs.cs;
        const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
        const libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
        const libff::Fr<ppT> beta = libff::Fr<ppT>::random_element(); 
        const libff::Fr<ppT> gamma = libff::Fr<ppT>::random_element();
        const libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();

        libff::G1_vector<ppT> gamma_ABC_g1_values;

        lego_keypair<ppT> kp( 
            r1cs_gg_ppzksnark_keypair<ppT>::aux_kg(
                g1_generator, G2_gen, t, alpha, beta, gamma, delta, gro16cs, gamma_ABC_g1_values) 
        );
        /* -------- */ 

        auto eta =  libff::Fr<ppT>::random_element();
        auto delta_inverse  = delta.inverse();
        auto gamma_inverse  = gamma.inverse();
        auto eta_delta_inv = eta*delta_inverse;
        auto eta_gamma_inv = eta*gamma_inverse;

        // returns additional elements
        kp.eta_delta_inv_g1 = eta_delta_inv*g1_generator;
        kp.eta_gamma_inv_g1 = eta_gamma_inv*g1_generator;


        _lego_set_slice( kp.gamma_ABC_g1_x, gamma_ABC_g1_values, 0 , cs.x_size());
        _lego_set_slice( kp.gamma_ABC_g1_u, gamma_ABC_g1_values, cs.x_size(), cs.x_size()+cs.opn_size());

        /* END of ccGro16 KG */

        /* Linking KG */

        kp.lnk_key = cplink_kg<ppT>(ck, kp.gamma_ABC_g1_u);

        kp.ck = ck;
                
        return kp;
    }

template<typename ppT>
    lego_proof<ppT> lego_prv(const auto &kp, const auto &x, const auto &cm, const auto &opn,  const auto &omega)  {
        lego_proof<ppT> lego_prf;

        // x_concat_opn = x || u
        std::vector<libff::Fr<ppT>> x_concat_opn(x);
        x_concat_opn.insert( x_concat_opn.end(), opn.begin(), opn.end() );

        // produce Groth16 proof
        lego_prf.gro16prf = r1cs_gg_ppzksnark_prover<ppT>(kp.gro16pk(), x_concat_opn, omega);
        
        lego_prf.g_D = multiExpMA< libff::G1<ppT>, libff::Fr<ppT> >(kp.gamma_ABC_g1_u, opn);

        // run CPLin on (cm, opn) and D
        lego_prf.lnk_prf = cplink_prv<ppT>(kp.lnk_key, cm, lego_prf.g_D, opn);

        return lego_prf;
    }

template<typename ppT>
    bool lego_vfy(const auto &kp, const auto &x, const auto &cm,  const auto &prf) {
        // check gro16 prf
        auto gro16prf = prf.gro16prf;

        // it's more like a modified version of this:
        // bool gro16ans = libsnark::r1cs_gg_pprzksnark_vfy<ppT>(kp.gro16pvk(), x, gro16prf);
        bool gro16ans = true;

        libff::enter_block("ccSNARK verification");
        libff::enter_block("Accumulate input");
        const accumulation_vector<libff::G1<ppT> > accumulated_IC = kp.pvk.gamma_ABC_g1.template accumulate_chunk<libff::Fr<ppT> >(x.begin(), x.end(), 0);
        libff::G1<ppT> acc = accumulated_IC.first + prf.g_D; // add D for accumulation
        libff::leave_block("Accumulate input");

        gro16ans = vfy_aux<ppT>(kp.pvk, gro16prf, acc);
        libff::leave_block("ccSNARK verification");


        bool cplin_ans = true;
        cplin_ans = cplink_vfy<ppT>(kp.lnk_key, cm, prf.g_D, prf.lnk_prf);
        return gro16ans && cplin_ans;
    }
}

#endif // R1CS_GG_PPZKSNARK_LEGO_TCC_
