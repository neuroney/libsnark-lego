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

namespace libsnark {
    void lego_kg() {
    }
    void lego_prv() {

    }
    void lego_vfy() {

    }
}

#endif // R1CS_GG_PPZKSNARK_LEGO_TCC_
