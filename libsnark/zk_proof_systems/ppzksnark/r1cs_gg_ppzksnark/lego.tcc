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
        lego_keypair<ppT> kp(r1cs_gg_ppzksnark_generator<ppT>(cs));
        return kp;
    }

template<typename ppT>
    lego_proof<ppT> lego_prv(const auto &pk, const auto &cm, const auto &opn, const auto &x, const auto &omega)  {
        lego_proof<ppT> lego_prf;

        // produce Groth16 proof
        // auto gro16prf = libsnark::r1cs_gg_ppzksnark_generator<ppT>(...);

        // produce additional Groth 16 element
        // auto D = ...

        // run CPLin on (cm, opn) and D

        return lego_prf;
    }

template<typename ppT>
    bool lego_vfy(const auto &vk, const auto &cm, const auto &x, const auto &prf) {
        // check gro16 prf
        // auto gro16prf = prf.gro16prf;

        // it's more like a modified version of this:
        // bool gro16ans = libsnark::r1cs_gg_pprzksnark_vfy<ppT>(vk.gro16, x, gro16prf);
        bool gro16ans = true;

        bool cplin_ans = true;
        // cplin_ans = cplin_vfy(...);
        return gro16ans && cplin_ans;
    }
}

#endif // R1CS_GG_PPZKSNARK_LEGO_TCC_
