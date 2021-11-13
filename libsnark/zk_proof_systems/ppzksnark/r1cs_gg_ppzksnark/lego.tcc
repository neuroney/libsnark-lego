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
    lego_keypair<ppT> lego_kg(const auto &cs) {

    /* -- Gro16 setup -- */ 
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> gamma = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();

    const libff::G1<ppT> g1_generator = libff::G1<ppT>::random_element();
    const libff::G2<ppT> G2_gen = libff::G2<ppT>::random_element();

    lego_keypair<ppT> kp(r1cs_gg_ppzksnark_keypair<ppT>::aux_kg(g1_generator, G2_gen, t, alpha, beta, gamma, delta, cs));
    /* -------- */ 

    auto eta =  libff::Fr<ppT>::random_element();
    return kp;
    }

template<typename ppT>
    lego_proof<ppT> lego_prv(const auto &kp, const auto &cm, const auto &opn, const auto &x, const auto &omega)  {
        lego_proof<ppT> lego_prf;

        // produce Groth16 proof
        lego_prf.gro16prf = r1cs_gg_ppzksnark_prover<ppT>(kp.gro16pk(), x, omega);

        // produce additional Groth 16 element
        //auto D = ...

        // run CPLin on (cm, opn) and D

        return lego_prf;
    }

template<typename ppT>
    bool lego_vfy(const auto &kp, const auto &cm, const auto &x, const auto &prf) {
        // check gro16 prf
        // auto gro16prf = prf.gro16prf;

        // it's more like a modified version of this:
        // bool gro16ans = libsnark::r1cs_gg_pprzksnark_vfy<ppT>(kp.gro16pvk(), x, gro16prf);
        bool gro16ans = true;

        bool cplin_ans = true;
        // cplin_ans = cplin_vfy(...);
        return gro16ans && cplin_ans;
    }
}

#endif // R1CS_GG_PPZKSNARK_LEGO_TCC_
