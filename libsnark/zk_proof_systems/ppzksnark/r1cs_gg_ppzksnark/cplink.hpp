
#ifndef CPLINK_HPP_
#define CPLINK_HPP_
 

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libsnark {

    
template<typename G, typename F>
G multiExpMA(const std::vector<G> &gs, const std::vector<F> &xs)
{
  size_t n = std::min(gs.size(), xs.size());
	#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
	#else
    const size_t chunks = 1;
	#endif
      printf("NCHUNKS : %d\n", chunks);

	return libff::multi_exp_with_mixed_addition<G, F, libff::multi_exp_method_BDLO12>(
	  gs.begin(), gs.begin()+n,
	  xs.begin(), xs.begin()+n,
	  chunks);
}



template<typename ppT>
struct cplink_key
{
    // Pedersen commitment key and legogroth-key
    std::vector<libff::G1<ppT>> ck, lgk;

    std::vector<libff::G1<ppT>> P;
    libff::G2_precomp<ppT> C_ck_precomp, C_lg_precomp, a_precomp;
};

template<typename ppT>
auto cplink_kg(const auto &ck, const auto &lgk)
{
    // k, k'
    libff::Fr<ppT> k, kp;
    k = libff::Fr<ppT>::random_element();
    kp = libff::Fr<ppT>::random_element();

    //std::vector<libff::G1<ppT>> P(ck.size());

    cplink_key<ppT> ret;
    ret.P.resize(ck.size());

    for (auto i = 0; i < ck.size(); i++) {
            ret.P[i] = k*ck[i] + kp*lgk[i];
    }

    auto a = libff::G2<ppT>::random_element(); 
    ret.a_precomp = ppT::precompute_G2(a);
    ret.C_ck_precomp = ppT::precompute_G2(k*a);
    ret.C_lg_precomp = ppT::precompute_G2(kp*a);

    ret.ck = ck;
    ret.lgk = lgk;

    return ret;
}

template<typename ppT>
libff::G1<ppT> cplink_prv(const auto &lnk_key, auto cm, auto cm_lg, auto opn)
{
    return multiExpMA< libff::G1<ppT>, libff::Fr<ppT> >(lnk_key.P, opn);
}

template<typename ppT>
bool cplink_vfy(const auto &lnk_key, auto cm, auto cm_lg, auto prf)
{
    const libff::G1_precomp<ppT> cm_precomp = ppT::precompute_G1(cm);
    const libff::G1_precomp<ppT> cm_lg_precomp = ppT::precompute_G1(cm_lg);

    const libff::G1_precomp<ppT> prf_precomp = ppT::precompute_G1(prf);
    
    const libff::Fqk<ppT> lhs = ppT::miller_loop(prf_precomp,  lnk_key.a_precomp);
    const libff::Fqk<ppT> rhs = ppT::double_miller_loop(
        cm_precomp, lnk_key.C_ck_precomp,
        cm_lg_precomp, lnk_key.C_lg_precomp);
    const libff::GT<ppT> shouldBeOne = ppT::final_exponentiation(lhs* rhs.unitary_inverse());
    bool isGood = (shouldBeOne == libff::GT<ppT>::one());
    return isGood;
}

} // end namespace

#endif