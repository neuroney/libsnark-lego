/*
 * run_ppzksnark.cpp
 *
 * 		// Runs legogroth16 on JSnark
 *      Author: Matteo Campanelli
 */

#include "CircuitReader.hpp"
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/examples/run_lego.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/lego.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>

#include "benchmark.h"
#include "bench_lego_utils.hpp"

//#include <format>

#include <filesystem>

using namespace std;

const size_t CHUNK_SIZE_BITS = 32;

void init_setmem_input_and_relation(string arith_file, string input_file, auto &input_rel)
{
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	int inputStartIndex = 1;	
	 	

	// Read the circuit, evaluate, and translate constraints
	const size_t MAX_FILE_NAME  = 256;
	char arith_c_str[MAX_FILE_NAME], input_c_str[MAX_FILE_NAME];
	strcpy(arith_c_str, arith_file.c_str()); 
	strcpy(input_c_str, input_file.c_str()); 
	CircuitReader reader(arith_c_str, input_c_str, pb);
	r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(
			*pb);
	const r1cs_variable_assignment<FieldT> full_assignment =
			get_variable_assignment_from_gadgetlib2(*pb);
	cs.primary_input_size = reader.getNumInputs() + reader.getNumOutputs();
	cs.auxiliary_input_size = full_assignment.size() - cs.num_inputs();

	// extract primary and auxiliary input
	const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(),
			full_assignment.begin() + cs.num_inputs());
	const r1cs_auxiliary_input<FieldT> auxiliary_input(
			full_assignment.begin() + cs.num_inputs(), full_assignment.end());


	// only print the circuit output values if both flags MONTGOMERY and BINARY outputs are off (see CMakeLists file)
	// In the default case, these flags should be ON for faster performance.

#if !defined(MONTGOMERY_OUTPUT) && !defined(OUTPUT_BINARY)
	cout << endl << "Printing output assignment in readable format:: " << endl;
	std::vector<Wire> outputList = reader.getOutputWireIds();
	int start = reader.getNumInputs();
	int end = reader.getNumInputs() +reader.getNumOutputs();	
	for (int i = start ; i < end; i++) {
		cout << "[output]" << " Value of Wire # " << outputList[i-reader.getNumInputs()] << " :: ";
		cout << primary_input[i];
		cout << endl;
	}
	cout << endl;
#endif

	//assert(cs.is_valid());

	// removed cs.is_valid() check due to a suspected (off by 1) issue in a newly added check in their method.
        // A follow-up will be added.
	if(!cs.is_satisfied(primary_input, auxiliary_input)){
		cout << "The constraint system is  not satisifed by the value assignment - Terminating." << endl;
		exit(-1);
	}


	//r1cs_example<FieldT> example(cs, primary_input, auxiliary_input);

	// NB: here we simplify this having all public input committed. Could be otherwise if we changed interface with JSnark
	auto pub_input = vector<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>>(0);
	auto committable_input = primary_input; 
	auto omega = auxiliary_input;

	input_rel = libsnark::gen_lego_example<libsnark::default_r1cs_gg_ppzksnark_pp>(cs, pub_input, committable_input, omega); 
}


auto msecs(auto secs)
{
	return secs/1000000;
}

enum HASH_TYPE {
	POSEIDON,
	SHA
};

void set_comm_input_sizes(size_t batchSize, size_t &u_size, size_t &sr_size) {
		auto bitsizeProdFirst256Primes = 2290;
        auto bitsize_h = 256;
        auto bitsize_u = 256*batchSize;
        auto bitsize_s = bitsizeProdFirst256Primes;
        auto bitsize_r = bitsize_s+bitsize_h+bitsize_u+128;

		u_size = bitsize_u / CHUNK_SIZE_BITS;
		sr_size = (bitsize_s+bitsize_r) / CHUNK_SIZE_BITS; 
    }

template<typename ppT>
size_t mt_constraints(size_t tree_depth, auto hash_type)
{

	size_t single_hasher_constraints;

	switch(hash_type) {
			case HASH_TYPE::POSEIDON:
			single_hasher_constraints = 300; // upper bound on poseidon_hasher
			break;

			case HASH_TYPE::SHA:
			single_hasher_constraints = 27534; // SHA-256
			break;

			default:
			cerr << "Should not be here";
			return 1;
		}


	const size_t digest_len = 256;
	const size_t hasher_constraints = tree_depth * single_hasher_constraints;
    const size_t propagator_constraints = tree_depth * digest_len;
    const size_t authentication_path_constraints = 2 * tree_depth * digest_len;
    const size_t check_root_constraints = 3 * libff::div_ceil(digest_len, libff::Fr<ppT>::ceil_size_in_bits());

    return hasher_constraints + propagator_constraints + authentication_path_constraints + check_root_constraints;
}

int main(int argc, char **argv) {

	using def_pp = libsnark::default_r1cs_gg_ppzksnark_pp;
	using rel_input_t = lego_example<def_pp>;

	/* Benchmark parameters */

	size_t nreps = 1;
	auto hash_type = POSEIDON;
	size_t tree_depth = 16;
	
	/* --------------- */


	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	

	const string arith_file_fmt = "../setmem_rel_inputs/setmem{}.arith";
	const string input_file_fmt = "../setmem_rel_inputs/setmem{}.in";

	rel_input_t relation_and_input;
	bool successBit = false;
	lego_proof<def_pp> cparith_prf; 
  

	// TODO: make loop
	size_t batch_size = 1;

	{
		/*  Block specific on batch size */ 
		string arith_file = fmt::format(arith_file_fmt, batch_size);
		string input_file = fmt::format(input_file_fmt, batch_size);

		// setup 
		init_setmem_input_and_relation(arith_file, input_file, relation_and_input);
		libff::print_header("## LegoGroth Generator");
		lego_keypair<def_pp> keypair(lego_kg<def_pp>(relation_and_input.ck, relation_and_input.r1cs()) );

		size_t cp_bound_pub_input_size,  cp_bound_comm_size, cp_bound_constraint_size;

		cp_bound_pub_input_size = 256;
		cp_bound_comm_size = batch_size;

		size_t u_size, sr_size;
		set_comm_input_sizes(batch_size, u_size, sr_size);
		
		cp_bound_constraint_size = batch_size*mt_constraints<def_pp>(tree_depth, hash_type);
	
		
		LegoBenchGadget<def_pp> cp_bound(cp_bound_pub_input_size, cp_bound_comm_size, cp_bound_constraint_size);

		// defined bench functions
		auto arith_prv_fn = [&] {
			cparith_prf = lego_prv<def_pp>(keypair,  relation_and_input.x, 
				relation_and_input.cm, relation_and_input.opn, relation_and_input.omega);
		};
		auto arith_vfy_fn = [&] {
			successBit = lego_vfy<def_pp>(keypair, relation_and_input.x, relation_and_input.cm, cparith_prf);
		};

		// run benchmarks

		// cparith
		libff::print_header("## Benchmarking CPArith Prover");
		fmt_time(fmt::format("## cparith_prv{}", batch_size), 
			TimeDelta::runAndAverage(arith_prv_fn, nreps));

		libff::print_header("## Benchmarking CPArith Verifier");
		fmt_time(fmt::format("## cparith_vfy{}", batch_size), 
			TimeDelta::runAndAverage(arith_vfy_fn, nreps));

		// cpbound
		cp_bound.bench_prv(nreps, fmt::format("## cpbound_prv{}", batch_size));
		cp_bound.bench_vfy(nreps, fmt::format("## cpbound_vfy{}", batch_size));


	
	}

	return 0;
}

