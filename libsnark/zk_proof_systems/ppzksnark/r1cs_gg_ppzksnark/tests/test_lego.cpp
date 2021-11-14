/** @file
 *****************************************************************************
 Test program that exercises the ppzkSNARK (first generator, then
 prover, then verifier) on a synthetic R1CS instance.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_lego.hpp>

using namespace libsnark;

template<typename ppT>
void test_lego(const size_t num_constraints,
                const size_t size_pub_input,
                const size_t size_comm_input)
{
    libff::print_header("(enter) Test LegoGroth");

    auto example = 
        generate_lego_example_with_field_input<ppT>(num_constraints, size_pub_input, size_comm_input);
    const bool bit = true;
    run_lego(example);
   // const bool bit = run_r1cs_gg_ppzksnark<ppT>(example, test_serialization);
    assert(bit);

    libff::print_header("(leave) Test LegoGroth");
}

int main()
{
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    libff::start_profiling();

    test_lego<default_r1cs_gg_ppzksnark_pp>(1000, 100, 100);
}
