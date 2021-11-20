/** @file
 *****************************************************************************

 Implementation of functionality that runs the R1CS GG-ppzkSNARK for
 a given R1CS example.

 See run_r1cs_gg_ppzksnark.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RUN_LEGO_TCC_
#define RUN_LEGO_TCC_


#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>


#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>


namespace libsnark {


template<typename ppT>
bool run_lego(const lego_example<ppT> &example)
{
    //libff::enter_block("Call to run_lego");

    libff::print_header("LegoGroth Generator");
    lego_keypair<ppT> keypair(lego_kg<ppT>(example.ck, example.r1cs()) );
    //printf("\n"); libff::print_indent(); libff::print_mem("after generator");



    libff::print_header("LegoGroth Prover");
    auto proof = lego_prv<ppT>(keypair,  example.x, example.cm, example.opn, example.omega);
    //printf("\n"); libff::print_indent(); libff::print_mem("after prover");




    libff::print_header("LegoGroth Verifier");
    const bool ans = lego_vfy<ppT>(keypair, example.x, example.cm, proof);
    //printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

  //      exit(1);


    //libff::leave_block("Call to run_lego");
        
    return true;
}

}

#endif // RUN_R1CS_GG_PPZKSNARK_TCC_
