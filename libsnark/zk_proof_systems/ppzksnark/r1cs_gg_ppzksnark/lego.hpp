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
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>

namespace libsnark {
    void lego_kg();
    void lego_prv();
    void lego_vfy();
}

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/lego.tcc>

#endif // R1CS_GG_PPZKSNARK_LEGO_HPP_
