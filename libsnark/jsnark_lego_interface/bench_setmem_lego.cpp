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

#include <openssl/rsa.h>
#include <openssl/bn.h>
//#include <openssl/sha.h>

//#include <format>

#include <filesystem>

using namespace std;

using def_pp = libsnark::default_r1cs_gg_ppzksnark_pp;
using rel_input_t = lego_example<def_pp>;

const size_t CHUNK_SIZE_BITS = 32;
const size_t nreps = 50;
const size_t POSEIDON_SZ = 300;
const size_t SHA_SZ = 27534;

const size_t bitsizeProdFirst256Primes = 2290;
const size_t bitsize_h = 256;
const size_t bitsize_s = bitsizeProdFirst256Primes;


const char* RSA_2048 = "C7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5";


enum HASH_TYPE {
	POSEIDON,
	SHA
};

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



void set_comm_input_sizes(size_t batchSize, size_t &u_size, size_t &sr_size) {
		auto bitsizeProdFirst256Primes = 2290;
        auto bitsize_h = 256;
        auto bitsize_u = 256*batchSize;
        auto bitsize_s = bitsizeProdFirst256Primes;
        auto bitsize_r = bitsize_s+bitsize_h+bitsize_u+128;

		u_size = libff::div_ceil(bitsize_u, CHUNK_SIZE_BITS);
		sr_size = libff::div_ceil((bitsize_s+bitsize_r),CHUNK_SIZE_BITS); 
}

size_t get_bitsize_k(size_t batchSize) {

        auto bitsize_u = 256*batchSize;
        auto bitsize_r = bitsize_s+bitsize_h+bitsize_u+128;

	    auto bitsize_k = bitsize_r+1;
		return bitsize_k;
}


template<typename ppT>
size_t mt_constraints(size_t tree_depth, auto hash_type)
{

	size_t single_hasher_constraints;

	switch(hash_type) {
			case HASH_TYPE::POSEIDON:
			single_hasher_constraints = POSEIDON_SZ; // upper bound on poseidon_hasher
			break;

			case HASH_TYPE::SHA:
			single_hasher_constraints = SHA_SZ; // SHA-256
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


template <typename ppT>
void bench_merkle(size_t batch_size, size_t tree_depth, auto hash_type)
{

	
	/* Merkle tree part */
	size_t cp_merkle_pub_input_size,  cp_merkle_comm_size, cp_merkle_constraint_size;

	cp_merkle_pub_input_size = 256; // merkle tree root
	cp_merkle_comm_size = batch_size;

	cp_merkle_constraint_size = batch_size*mt_constraints<def_pp>(tree_depth, hash_type);

	LegoBenchGadget<def_pp> cp_merkle(cp_merkle_pub_input_size, cp_merkle_comm_size, cp_merkle_constraint_size);

	auto tag = (hash_type == SHA) ? "MerkleSHA" : "MerklePos";
	
	string tag_prv = fmt::format("## {}prv_dpt{}_batch{}", tag, tree_depth, batch_size);
	string tag_vfy = fmt::format("## {}vfy_dpt{}_batch{}", tag, tree_depth, batch_size);	

	cp_merkle.bench_prv(nreps, tag_prv);
	cp_merkle.bench_vfy(nreps, tag_vfy);

}

template<typename ppT>
void bench_rsa(size_t batch_size)
{

	// common input sizes
	size_t u_size, sr_size;
	set_comm_input_sizes(batch_size, u_size, sr_size);

	cout << fmt::format("u_size: {}, sr_size: {}", u_size, sr_size) << endl;
	
	const string arith_file_fmt = "../setmem_rel_inputs/setmem{}.arith";
	const string input_file_fmt = "../setmem_rel_inputs/setmem{}.in";

	rel_input_t relation_and_input;
	bool successBit = false;
	lego_proof<def_pp> cparith_prf; 

	/*  Block specific on batch size */ 
	string arith_file = fmt::format(arith_file_fmt, batch_size);
	string input_file = fmt::format(input_file_fmt, batch_size);

	// setup 
	init_setmem_input_and_relation(arith_file, input_file, relation_and_input);
	libff::print_header("## LegoGroth Generator");
	lego_keypair<def_pp> keypair(lego_kg<def_pp>(relation_and_input.ck, relation_and_input.r1cs()) );

	

	/* CPBound  part */
	size_t cp_bound_pub_input_size,  cp_bound_comm_size, cp_bound_constraint_size;

	cp_bound_pub_input_size = 0; // no public input
	cp_bound_comm_size = batch_size;

	// range proof by hashing the u-s. We use Poseidon for this
	cp_bound_constraint_size = batch_size*POSEIDON_SZ; 

	LegoBenchGadget<def_pp> cp_bound(cp_bound_pub_input_size, cp_bound_comm_size, cp_bound_constraint_size);

	/* -------- */
	
	// defined bench functions for comm and cparith

	// we measure commitment of r,s separately
	libff::G1<def_pp> cm_sr;
	vector<libff::Fr<def_pp>> sr(sr_size);
	for (auto i = 0; i < sr_size; i++) {
            sr[i] = libff::Fr<ppT>::random_element();
        }
	auto comm_fn = [&] {
		cm_sr = lego_commit<def_pp>(relation_and_input.ck, sr);
	};
	
	auto arith_prv_fn = [&] {
		cparith_prf = lego_prv<def_pp>(keypair,  relation_and_input.x, 
			relation_and_input.cm, relation_and_input.opn, relation_and_input.omega);
	};
	auto arith_vfy_fn = [&] {
		successBit = lego_vfy<def_pp>(keypair, relation_and_input.x, relation_and_input.cm, cparith_prf);
	};

	// run benchmarks

	fmt_time(fmt::format("## commit_rs{}", batch_size), 
		TimeDelta::runAndAverage(comm_fn, nreps));
	

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


void init_to_rnd(size_t lenbits, BIGNUM **res)
{
	auto len = lenbits/4; // hex length
	char *rnd = new char[len];
	for (size_t i = 0; i < len; i++) {
		auto rand_int = (rand() % 16);
		rnd[i] = (rand_int < 10) ? (rand_int + '0') : (rand_int + 'A' - 10);
	}

	BN_hex2bn(res, rnd);
	delete rnd;
}

template<typename ppT>
void bench_poke(size_t batch_size, size_t k_bitsize)
{
	const size_t ellsize = 256;
	const size_t usize = 256;

	const size_t rsa_sz = 2048;
	const size_t hsize = 256;

	// init vector of u-s
	vector<BIGNUM *> us(batch_size);
	for (auto i = 0; i < batch_size; i++) {
		us[i] = BN_new();
		init_to_rnd(usize, &us[i]);
	}

	// "setup"
	BIGNUM *N, *G, *H, *p, *k, *h, *s; 
	N = BN_new();
	G = BN_new();
	H = BN_new();
	p = BN_new();
	k = BN_new();

	h = BN_new();
	s = BN_new();


	BN_hex2bn(&N, RSA_2048);
	
	init_to_rnd(rsa_sz, &G);
	init_to_rnd(rsa_sz, &H);

	init_to_rnd(ellsize, &p);
	init_to_rnd(k_bitsize, &k);

	init_to_rnd(hsize, &h);
	init_to_rnd(bitsize_s, &s);

	auto prv_fn = [&] {
		// prv
		BN_CTX* bn_ctx = BN_CTX_new();
		BIGNUM* res_expG = BN_new();
		BIGNUM* res_expH = BN_new();
		BIGNUM* res_expMul = BN_new();
		BIGNUM* divres = BN_new();
		BIGNUM* remres = BN_new();

		BIGNUM* ures = BN_new();

		// extras: product of u-s, acc^h, acc^s, R
		for (auto i = 0; i < batch_size; i++) {
			BN_mul(ures, ures, us[i], bn_ctx);
		}

		// counts for acc^s
		BN_mod_exp(res_expG, G, s, N, bn_ctx);

		// counts for acc^h
		BN_mod_exp(res_expG, G, h, N, bn_ctx);

		// counts for R (k and r are basically same size)
		BN_mod_exp(res_expG, G, k, N, bn_ctx);


		BN_div(divres, remres, k, p, bn_ctx);
		// upper bound: three exponentiations for ell
		BN_mod_exp(res_expG, G, k, N, bn_ctx);
		BN_mod_exp(res_expH, H, k, N, bn_ctx);
		BN_mod_exp(res_expG, G, k, N, bn_ctx);




		BN_CTX_free(bn_ctx);
	};

	auto vfy_fn = [&]{
		// vfy
		BN_CTX* bn_ctx = BN_CTX_new();
		BIGNUM* res_expG = BN_new();
		BIGNUM* res_expH = BN_new();
		BIGNUM* res_expMul = BN_new();
		
		// counts for acc^h
		BN_mod_exp(res_expG, G, h, N, bn_ctx);

		for (auto i = 1; i <= 2; i++) {
			BN_mod_exp(res_expG, G, p, N, bn_ctx);
			BN_mod_exp(res_expH, H, p, N, bn_ctx);
			BN_mod_mul(res_expMul, res_expG, res_expH, N, bn_ctx);
		}

		BN_CTX_free(bn_ctx);
	};

	fmt_time(fmt::format("## poke_prv{}", batch_size), 
		TimeDelta::runAndAverage(prv_fn, nreps));

	fmt_time(fmt::format("## poke_vfy{}", batch_size), 
		TimeDelta::runAndKeepMedian(vfy_fn, nreps));

}

void print_err()
{
	cerr << "Error parsing args." << endl;
	cerr << "Usage:" << endl;
	cerr << "either, $ ./PROGRAM_NAME merkle [poseidon||sha] depth" << endl;
	cerr << "or,     $ ./PROGRAM_NAME rsa||pokeonly" << endl;
}

int main(int argc, char **argv) {

	// Usage:
	// either, $ ./PROGRAM_NAME merkle [poseidon||sha] depth
	// or,     $ ./PROGRAM_NAME rsa||pokeonly  

	std::vector<std::string> args(argv, argv+argc);

	bool doing_rsa = false;
	bool doing_pokeonly = false;
	auto hash_type = POSEIDON; // default
	size_t tree_dpt = 16;

	// process args 
	if (argc > 1 ) {
		if(args[1] == "rsa") {
			doing_rsa = true;
		} else if (args[1] == "pokeonly") {
			doing_pokeonly = true;
		} else if (args[1] != "merkle" || argc < 4) {
			print_err();
			return 1;
		} else {
				doing_rsa = false;
				if (args[2] == "sha")
					hash_type = SHA;
				tree_dpt = stoi(args[3]);

		}
	}

	/* Benchmark parameters */

	
	/* --------------- */


	libff::start_profiling();
	gadgetlib2::initPublicParamsFromDefaultPp();
	gadgetlib2::GadgetLibAdapter::resetVariableIndex();
	
	
	// TODO: make loop
	auto batches = {1, 16, 32, 64, 128};

	// setup poke = 

	for (size_t batch_size : batches ) {
		if (doing_pokeonly) {
			cout << endl << "## Benchmarking our PoKE component with batch n = " << batch_size << endl << endl;
			bench_poke<def_pp>(batch_size, get_bitsize_k(batch_size));
		}
		else if (doing_rsa) {
			cout << endl << "## Benchmarking our RSA-based protocol with batch n = " << batch_size << endl << endl;
			bench_rsa<def_pp>(batch_size);
		} else {
			cout << endl << "## Benchmarking " << args[2] << " Merkle with batch n = " << batch_size 
				<< " and depth " << tree_dpt << endl << endl;
			bench_merkle<def_pp>(batch_size, tree_dpt, hash_type);
		} 
	}


	return 0;
}

