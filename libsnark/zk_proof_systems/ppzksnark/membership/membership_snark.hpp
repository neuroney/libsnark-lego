#ifndef LEGO_CP_SNARK_HPP_
#define LEGO_CP_SNARK_HPP_

#include <memory>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/membership/membership_snark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark_params.hpp>

using namespace std;

namespace membership_snark
{
    template <typename ppT>
    class memebership_statement;

    template <typename ppT>
    class membership_statement
    {
        public:
            libff::G1_vector<ppT> ck;

            size_t commit_num() const
            {
                return ck.size();
            }

            membership_statement() = default;
            membership_statement(const membership_statement<ppT> &other) = default;
            membership_statement(membership_statement<ppT> &other) = default;
            membership_statement(libff::G1_vector<ppT> &&ck) :
                    ck(std::move(ck))
            {            };

            void print() const;

            void commitIO_crs(std::vector<std::string> bn_vector_s, std::vector<std::string> bn_vector_r , std::vector<std::string> bn_vector_u, libff::G1<ppT> &commit_res);

    };
} 

#include <libsnark/zk_proof_systems/ppzksnark/membership/membership_snark.tcc>

#endif // LEGO_CP_SNARK_HPP_
