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


void init_input_and_relation(char **argv, auto &input_rel)
{
	ProtoboardPtr pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);

	int inputStartIndex = 1;	
	 	

	// Read the circuit, evaluate, and translate constraints
	CircuitReader reader(argv[1 + inputStartIndex], argv[2 + inputStartIndex], pb);
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

int main(int argc, char **argv) {

	using rel_input_t = lego_example<libsnark::default_r1cs_gg_ppzksnark_pp>;

	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	
	rel_input_t relation_and_input;
	init_input_and_relation(argv, relation_and_input);
	
	bool successBit = false;
	successBit = libsnark::run_lego<libsnark::default_r1cs_gg_ppzksnark_pp>(relation_and_input);
	

	if(!successBit){
		cout << "Problem occurred while running the ppzksnark algorithms .. " << endl;
		return -1;
	}	
	return 0;
}

