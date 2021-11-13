/** @file
*****************************************************************************

Declaration of interfaces for LegoGroth


*****************************************************************************
* @author     Matteo Campanelli
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/

#ifndef R1CS_GG_PPZKSNARK_LEGO_HPP_
#define R1CS_GG_PPZKSNARK_LEGO_HPP_
 
#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libsnark {

template<typename ppT>
class lego_keypair {
    public: 
   
    r1cs_gg_ppzksnark_keypair<ppT> gro16keypair; 
    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk;
    // cplink_k;

    lego_keypair( r1cs_gg_ppzksnark_keypair<ppT> _gro16keypair) :
        gro16keypair(_gro16keypair)
    {
        libff::print_header("Preprocess verification key");
        pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(gro16keypair.vk);
    }

    auto pk() const {
        return gro16keypair.pk;
    }

    auto vk() const {
        // return preprocessed vk
        return pvk;
    }
};

template<typename ppT>
struct lego_proof {
    libsnark::r1cs_gg_ppzksnark_proof<ppT> gro16prf;
    libff::G1<ppT> g_D;

    // cplink_prf

};

template<typename ppT>
    lego_keypair<ppT> lego_kg(const auto &cs);

template<typename ppT>
    lego_proof<ppT> lego_prv(const auto &pk, const auto &cm, const auto &opn, const auto &x, const auto &omega);

template<typename ppT>
    bool lego_vfy(const auto &vk, const auto &cm, const auto &x, const auto &prf);

}

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/lego.tcc>

#endif // R1CS_GG_PPZKSNARK_LEGO_HPP_
