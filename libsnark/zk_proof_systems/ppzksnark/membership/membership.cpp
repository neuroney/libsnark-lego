#include <iostream>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <flint/fmpz.h>
#include <vector> 
#include <map>
#include <math.h>
#include <time.h>
#include <string.h>
#include <string>
#include <cstdlib>
#include <ctime>

#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>   
#include <libsnark/zk_proof_systems/ppzksnark/membership/membership_snark.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/jsnark_interface/CircuitReader.hpp>




using namespace std;


namespace membership{
    // RSA numbre is from #https://en.wikipedia.org/wiki/RSA_numbers#RSA-2048
    const char* RSA_2048 = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357";
    // Assume that the lambda is 256; if 128 -> 727 is the last element. 
    const vector<int> odd_prime = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 
        73,	79,	83,	89,	97,	101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 
        179, 181, 191, 193, 197, 199, 211, 223,	227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
        283, 293, 307, 311,	313, 317, 331, 337,	347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 
        419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479,	487, 491, 499, 503,	509, 521, 523, 541,
        547, 557, 563, 569, 571, 577, 587, 593,	599, 601, 607, 613, 617, 619, 631, 641,	643, 647, 653, 659, 
        661, 673, 677, 683, 691, 701, 709, 719, 727,
        733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
        863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009,
        1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 
        1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289,
        1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447,
        1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 
        1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621};
    const int len = 512;

    // Public parameter for membership proof
    // N is RSA modular where N <- p*q, and V is the group element. 
    // N is fixed with RSA_2048, which is known number. 
    // vec_prime is [e_i]_{i=1}^{\lambda} 
    typedef struct {
        fmpz_t N;
        fmpz_t V;
        vector<BIGNUM*> vec_prime;
    }public_param;

    // Proof for membership proof; including both opt and non-opt.
    // Since the commitment value C is from snark vk (G_1,G_2,G_3, ..)
    // C is a point on elliptic curve s.t. (C_x, C_y)
    typedef struct {
        BIGNUM* W;
        BIGNUM* C_x;
        BIGNUM* C_y;
        BIGNUM* k;
        BIGNUM* opt_k;
        BIGNUM* h;
        BIGNUM* Q;
        BIGNUM* l;
    }mem_proof;


    void print_debug(const char* msg) {
        cout << endl << "================================================================================" << endl;
        cout << msg << endl;
        cout  << "================================================================================" << endl << endl;
    }
    
    int pp_init(public_param* pp) {
        fmpz_init(pp->N);
        fmpz_init(pp->V);

        return 1;
    }

    int pp_clear(public_param* pp) {
        fmpz_clear(pp->N);
        fmpz_clear(pp->V);

        return 1;
    }

    // RSA group generation 
    int groupGen(public_param* pp) {
        pp_init(pp);
        fmpz_set_str(pp->N, RSA_2048, 10);
        fmpz_set_str(pp->V, "2", 10);
        pp_clear(pp);

        return 1;
    }


    void print_BN(BIGNUM* p, string s) {
        cout << s << endl;
        char *a;
        a = BN_bn2dec(p);
        cout << a << endl << endl;
    }

    // pk = H(sk); SHA256 
    // TODO: Give more options to choice hash s.t. MiMc, Poseidon..
    void Hash1(BIGNUM* res, BIGNUM* sk) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(sk, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(sk));

        SHA256_Final(hash_digest, &sha256);   

        BN_bin2bn(hash_digest, 32, res);
    }

    // ret = H(W||C||R) = H(W||C_x||C_y||R)
    void Hash2(BIGNUM* ret, BIGNUM* W, BIGNUM* C_x, BIGNUM* C_y, BIGNUM* R) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        BN_bn2bin(W, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(W));
        BN_bn2bin(C_x, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(C_x));
        BN_bn2bin(C_y, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(C_y));        
        BN_bn2bin(R, temp);
        SHA256_Update(&sha256, temp, BN_num_bytes(R));

        SHA256_Final(hash_digest, &sha256);

        BN_bin2bn(hash_digest, 32, ret);
    }

    // l <-Hash3(h), which is prime number. 
    // Based on Miller-Rabin primality test
    // Hash_to_prime in Boneh's USENIX? 
    void Hash3(BIGNUM* ret, BIGNUM* h) {
        unsigned char hash_digest[SHA256_DIGEST_LENGTH];
        unsigned char temp[2048];
        SHA256_CTX sha256_ctx;
        SHA256_Init(&sha256_ctx);
              
        BN_CTX* bn_ctx = BN_CTX_new();

        do{
            BN_bn2bin(h, temp);
            SHA256_Update(&sha256_ctx, temp, BN_num_bytes(h));

            SHA256_Final(hash_digest, &sha256_ctx);

            BN_bin2bn(hash_digest, 32, ret);        
        }while(!BN_is_prime(ret, 5, NULL, bn_ctx, NULL));
    }

    void setup(public_param* pp, int n) {
        libff::start_profiling();
        libff::enter_block("Call to setup for membership test");
        BN_CTX* ctx = BN_CTX_new();
        
        // Choose an unknown order group and generator of it. 
        groupGen(pp);

        // convert int prime to bignum prime
        for(int i = 0; i < odd_prime.size(); i++) {
            BIGNUM* bn_vec_temp = BN_new();
            string str_num = to_string(odd_prime[i]);
            BN_dec2bn(&bn_vec_temp, str_num.c_str()); 

            pp->vec_prime.push_back(bn_vec_temp);
        }

        BN_CTX_free(ctx);
        libff::leave_block("Call to setup for membership test");
    }

    void add(vector<BIGNUM*> &S, vector<BIGNUM*> u) {
        libff::start_profiling();
        libff::enter_block("Call to Add; add new user to existing set");
        for(auto x : u) {
            S.push_back(x);
        }
        libff::leave_block("Call to Add; add new user to existing set");
    }

    void accumulate(public_param* pp, vector<BIGNUM*> S, BIGNUM* &ACC) {
        libff::start_profiling();
        libff::enter_block("Call to Accumulate");

        BN_CTX* bn_ctx = BN_CTX_new();
        BIGNUM* bn_V = BN_new();    
        BN_hex2bn(&bn_V, fmpz_get_str(NULL, 16, pp->V));
    
        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));
      
        // exponentiation part, which is to be raised on ACC       
        BIGNUM* bn_acc_exp = BN_new(); 
        BN_copy(bn_acc_exp, BN_value_one());

        // multiplication all of the e_i which is vec_prime
        for(auto x : pp->vec_prime) {
            BN_mod_exp(bn_V, bn_V, x, bn_N, bn_ctx);
        }
        
        // multiplication e_i (bn_acc_exp) and u_j
        for(auto x : S) {
            BN_mod_exp(bn_V, bn_V, x, bn_N, bn_ctx);
        }

        BN_copy(ACC, bn_V);        
        
        BN_CTX_free(bn_ctx);      
        libff::leave_block("Call to accumulate");
    }

    void compute(public_param* pp, 
    const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    libff::G1_vector<libff::alt_bn128_pp> &commit_base, vector<BIGNUM*> S, vector<BIGNUM*> u, mem_proof* proof,
     libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof) {
        libff::start_profiling();
        libff::enter_block("Call to compute");
        vector<int> rand_b; // b_i <- {0, 1}
        BIGNUM* bn_w_exp = BN_new();
        proof->W = BN_new();
        proof->k = BN_new();
        proof->C_x = BN_new();
        proof->C_y = BN_new();
        proof->h = BN_new();
        BIGNUM* bn_s = BN_new();
        BIGNUM* bn_r = BN_new();    
        BN_CTX* bn_ctx = BN_CTX_new();

        BN_copy(bn_s, BN_value_one());

        BIGNUM* bn_V = BN_new(); 
        BN_hex2bn(&bn_V, fmpz_get_str(NULL, 16, pp->V));

        // bn_u is for storing the multiplication of all u_i ~ u_j, batching element.
        BIGNUM* bn_u = BN_new();
        BN_copy(bn_u, BN_value_one());

        for(int i = 0; i < u.size(); i++) {
            BN_mul(bn_u, bn_u, u[i], bn_ctx);
        }

        srand(time(NULL));

        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));

        // snark proof generation
        // libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof = libsnark::r1cs_gg_ppzksnark_prover(snark_pk.pk, snark_ex.primary_input, snark_ex.auxiliary_input);
        snark_proof = libsnark::r1cs_gg_ppzksnark_prover(snark_key.pk, snark_ex.primary_input, snark_ex.auxiliary_input);
       
        libff::enter_block("\tCall to compute (generate membership proof): V^{e_i}");
        // prod_{i=1}^n{{e_i}^{1-b_i}}
        for(int i = 0; i < pp->vec_prime.size(); i++) {
            rand_b.push_back(rand()%2); // generate random bit vector
            if(rand_b.back() == 0) {
                BN_mod_exp(bn_V, bn_V, pp->vec_prime[i], bn_N, bn_ctx);
                // BN_mul(bn_w_exp, bn_w_exp, pp->vec_prime[i], bn_ctx);
            }
        }
        libff::leave_block("\tCall to compute (generate membership proof): V^{e_i}");
       
        for(int i = 0; i < S.size(); i++) {
            if(!(find(u.begin(), u.end(), S[i]) != u.end())) {
                BN_mod_exp(bn_V, bn_V, S[i], bn_N, bn_ctx);
            }
       }

        // W <- V^bn_w_exp 
        BN_copy(proof->W, bn_V);
        
        // s <- prod_{i=1}^n {e_i}^{b_i}
        int cnt = 0;
        for(int i = 0; i < pp->vec_prime.size(); i++) {
            if(rand_b[i] == 1) {
                BN_mul(bn_s, bn_s, pp->vec_prime[i], bn_ctx);
            }
        }    
      
        BN_rand(bn_r, len, 1,  NULL); // r <- {0, 1}^len
        
        vector<string> bn_str_s, bn_str_r, bn_str_u;
        string str_tmp_s, str_tmp_r, str_tmp_u;
        str_tmp_s = BN_bn2hex(bn_s);
        str_tmp_r = BN_bn2hex(bn_r);
        str_tmp_u = BN_bn2hex(bn_u);
        size_t split_unit = 256;

        // split phase for s
        if(str_tmp_s.size() > split_unit) {
            int q_s = ceil(double(str_tmp_s.size()) / double(split_unit));
            int rem = str_tmp_s.size() % split_unit;

            for(int i = 0; i < q_s; i++) {  
                if((rem != 0) && (i == q_s-1)) {
                    bn_str_s.push_back(str_tmp_s.substr(i*split_unit, rem));
                }            
                bn_str_s.push_back(str_tmp_s.substr(i*split_unit, split_unit));
            }
        }
        else {
            bn_str_s.push_back(BN_bn2hex(bn_s));
        }

        // split phase for r 
        if(str_tmp_r.size() > split_unit) {
            int q_r = ceil(double(str_tmp_r.size()) / double(split_unit));
            int rem = str_tmp_r.size() % split_unit;

            for(int i = 0; i < q_r; i++) {                  
                if((rem != 0) && (i == (q_r - 1))) {
                    bn_str_r.push_back(str_tmp_r.substr(i*split_unit, rem));
                }
                else {
                    bn_str_r.push_back(str_tmp_r.substr(i*split_unit, split_unit));
                }
            }
        }
        else {
            bn_str_r.push_back(BN_bn2hex(bn_r));
        }

        // split phase for u
        if(str_tmp_u.size() > split_unit) {
            int q_u = ceil(double(str_tmp_u.size() / double(split_unit)));
            int rem = str_tmp_u.size() % split_unit;

            for(int i = 0; i < q_u; i++) {  
                if((rem != 0) && (i == q_u-1)) {
                    bn_str_u.push_back(str_tmp_u.substr(i*split_unit, rem));
                }
                bn_str_u.push_back(str_tmp_u.substr(i*split_unit, split_unit));
            }
        }
        else {
            bn_str_u.push_back(BN_bn2hex(bn_u));
        }
    
        // R <- W^r
        BIGNUM* bn_R = BN_new();
        BN_mod_exp(bn_R, proof->W, bn_r, bn_N, bn_ctx); 

        // com_val <- commitIO_crs(s, r, u) 
        libff::enter_block("    Call to compute (generate commit value from s, r, u)");
        libff::G1<libff::alt_bn128_pp> com_val; 

        membership_snark::membership_statement<libsnark::default_r1cs_gg_ppzksnark_pp> test(std::move(commit_base));
        test.commitIO_crs(bn_str_s, bn_str_r, bn_str_u, com_val);
        
        

        libff::bigint<4> bg_com_x = com_val.X.as_bigint();
        libff::bigint<4> bg_com_y = com_val.Y.as_bigint();
        char char_arr_x[1024] = "";
        char char_arr_y[1024] = "";

        gmp_sprintf(char_arr_x, "%Nd", bg_com_x.data, bg_com_x.N);
        gmp_sprintf(char_arr_y, "%Nd", bg_com_y.data, bg_com_y.N);

        

        BN_dec2bn(&proof->C_x, char_arr_x);
        BN_dec2bn(&proof->C_y, char_arr_y);
        libff::leave_block("    Call to compute (generate commit value from s, r, u)");

        // Since wire supports only 254bits, h, which can be maximum 256 bits, we just cut out exceeded bits. 
        // h <- H(W||C||R)
        libff::enter_block("    Call to compute (Hash value)");
        Hash2(proof->h, proof->W, proof->C_x, proof->C_y, bn_R);
        libff::leave_block("    Call to compute (Hash value)");
        
        // k <- r + u*s*h
        libff::enter_block("    Call to compute (generate proof k)");
        BIGNUM* bn_sh = BN_new();
        BIGNUM* bn_ush = BN_new();
        BN_copy(bn_ush, BN_value_one());
        BN_mul(bn_sh, bn_s, proof->h, bn_ctx);   
        BN_mul(bn_ush, bn_u, bn_sh, bn_ctx);
        BN_add(proof->k, bn_r, bn_ush);
        libff::leave_block("    Call to compute (generate proof k)");

        print_debug("Proof value check");
        cout << "k: " << endl << BN_bn2hex(proof->k) << endl;
        cout << "r: " << endl << BN_bn2hex(bn_r) << endl;
        cout << "s: " << endl << BN_bn2hex(bn_s) << endl;
        cout << "u: " << endl << BN_bn2hex(bn_u) << endl;
        cout << "h: " << endl << BN_bn2hex(proof->h) << endl;

        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to compute");
    }

    void optCompute(public_param* pp, 
    const libsnark::r1cs_gg_ppzksnark_keypair<libsnark::default_r1cs_gg_ppzksnark_pp> snark_key,
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, 
    libff::G1_vector<libff::alt_bn128_pp> &commit_base, vector<BIGNUM*> S, vector<BIGNUM*> u, mem_proof* proof,
     libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> &snark_proof) {
        libff::start_profiling();
        libff::enter_block("Call to Optimized Compute (generate membership proof)");
        
        vector<int> rand_b; // b_i <- {0, 1}
        BIGNUM* bn_w_exp = BN_new();
        proof->W = BN_new();
        proof->k = BN_new();
        proof->C_x = BN_new();
        proof->C_y = BN_new();
        proof->h = BN_new();
        BIGNUM* bn_s = BN_new();
        BIGNUM* bn_r = BN_new();    
        BN_CTX* bn_ctx = BN_CTX_new();

        BIGNUM* bn_V = BN_new();
        BN_hex2bn(&bn_V, fmpz_get_str(NULL, 16, pp->V));

        BN_copy(bn_s, BN_value_one());

        // bn_u is for storing the multiplication of all u_i ~ u_j
        BIGNUM* bn_u = BN_new();
        BN_copy(bn_u, BN_value_one());

        for(int i = 0; i < u.size(); i++) {
            BN_mul(bn_u, bn_u, u[i], bn_ctx);
        }

        // BN_copy(bn_w_exp, BN_value_one());
        srand(time(NULL));

        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));

        // snark proof generation
        // libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof = libsnark::r1cs_gg_ppzksnark_prover(snark_pk.pk, snark_ex.primary_input, snark_ex.auxiliary_input);
        snark_proof = libsnark::r1cs_gg_ppzksnark_prover(snark_key.pk, snark_ex.primary_input, snark_ex.auxiliary_input);
       
        libff::enter_block("Call to Optimized Compute (generate V^{e_i}"); 
       
        // prod_{i=1}^n{{e_i}^{1-b_i}}
        for(int i = 0; i < pp->vec_prime.size(); i++) {
            rand_b.push_back(rand()%2); // generate random bit vector
            if(rand_b.back() == 0) {
                BN_mod_exp(bn_V, bn_V, pp->vec_prime[i], bn_N, bn_ctx);
                // BN_mul(bn_w_exp, bn_w_exp, pp->vec_prime[i], bn_ctx);
            }
        }
        libff::leave_block("Call to Optimized Compute (generate V^{e_i}");

        // \prod_{i = 1}^n {e_i} \prod_{u_j \in S-{u}} u_j
       for(int i = 0; i < S.size(); i++) {
            if(!(find(u.begin(), u.end(), S[i]) != u.end())) {
                BN_mod_exp(bn_V, bn_V, S[i], bn_N, bn_ctx);
            }
       }

        // W <- V^bn_w_exp 
        BN_copy(proof->W, bn_V);
      
        // s <- prod_{i=1}^n {e_i}^{b_i}
        int cnt = 0;
        for(int i = 0; i < pp->vec_prime.size(); i++) {
            if(rand_b[i] == 1) {
                BN_mul(bn_s, bn_s, pp->vec_prime[i], bn_ctx);
            }
        }    

        // len = BN_num_bits(u) + BN_num_bits(bn_s) + BN_num_bits(proof->h)
        // int len = BN_num_bits(bn_u) + BN_num_bits(bn_s) + 256;
        BN_rand(bn_r, len , 1,  NULL); // r <- {0, 1}^len
        
        vector<string> bn_str_s, bn_str_r, bn_str_u;
        string str_tmp_s, str_tmp_r, str_tmp_u;
        str_tmp_s = BN_bn2hex(bn_s);
        str_tmp_r = BN_bn2hex(bn_r);
        str_tmp_u = BN_bn2hex(bn_u);
        size_t split_unit = 256;

        // split phase for s
        if(str_tmp_s.size() > split_unit) {
            int q_s = ceil(double(str_tmp_s.size()) / double(split_unit));
            int rem = str_tmp_s.size() % split_unit;

            for(int i = 0; i < q_s; i++) {  
                if((rem != 0) && (i == q_s-1)) {
                    bn_str_s.push_back(str_tmp_s.substr(i*split_unit, rem));
                }            
                bn_str_s.push_back(str_tmp_s.substr(i*split_unit, split_unit));
            }
        }
        else {
            bn_str_s.push_back(BN_bn2hex(bn_s));
        }

        // split phase for r 
        if(str_tmp_r.size() > split_unit) {
            int q_r = ceil(double(str_tmp_r.size()) / double(split_unit));
            int rem = str_tmp_r.size() % split_unit;

            for(int i = 0; i < q_r; i++) {                  
                if((rem != 0) && (i == (q_r - 1))) {
                    bn_str_r.push_back(str_tmp_r.substr(i*split_unit, rem));
                }
                else {
                    bn_str_r.push_back(str_tmp_r.substr(i*split_unit, split_unit));
                }
            }
        }
        else {
            bn_str_r.push_back(BN_bn2hex(bn_r));
        }

        // split phase for u
        if(str_tmp_u.size() > split_unit) {
            int q_u = ceil(double(str_tmp_u.size() / double(split_unit)));
            int rem = str_tmp_u.size() % split_unit;

            for(int i = 0; i < q_u; i++) {  
                if((rem != 0) && (i == q_u-1)) {
                    bn_str_u.push_back(str_tmp_u.substr(i*split_unit, rem));
                }
                bn_str_u.push_back(str_tmp_u.substr(i*split_unit, split_unit));
            }
        }
        else {
            bn_str_u.push_back(BN_bn2hex(bn_u));
        }
        
        // R <- W^r
        BIGNUM* bn_R = BN_new();
        BN_mod_exp(bn_R, proof->W, bn_r, bn_N, bn_ctx); 


        // com_val <- commitIO_crs(s, r, u) 
        libff::enter_block("Call to Optimized Compute (generate commit value from s, r, u)");
        libff::G1<libff::alt_bn128_pp> com_val; 

        membership_snark::membership_statement<libsnark::default_r1cs_gg_ppzksnark_pp> test(std::move(commit_base));
        test.commitIO_crs(bn_str_s, bn_str_r, bn_str_u, com_val);
        
        libff::bigint<4> bg_com_x = com_val.X.as_bigint();
        libff::bigint<4> bg_com_y = com_val.Y.as_bigint();
        char char_arr_x[1024] = "";
        char char_arr_y[1024] = "";

        gmp_sprintf(char_arr_x, "%Nd", bg_com_x.data, bg_com_x.N);
        gmp_sprintf(char_arr_y, "%Nd", bg_com_y.data, bg_com_y.N);

        BN_dec2bn(&proof->C_x, char_arr_x);
        BN_dec2bn(&proof->C_y, char_arr_y);

        libff::leave_block("Call to Optimized Compute (generate commit value from s, r, u)");

        // h <- H(W||C||R)
        Hash2(proof->h, proof->W, proof->C_x, proof->C_y, bn_R);
        
        // l <- H_3(h), l is the prime
        proof->l = BN_new();
        libff::enter_block("Call to Optimized Compute (generate l, which is prime)");
        Hash3(proof->l, proof->h);
        libff::leave_block("Call to Optimized Compute (generate l, which is prime)");
        
        // k <- r + u*s*h
        libff::enter_block("Call to Optimized Compute (generate membership proof k)");
        BIGNUM* bn_sh = BN_new();
        BIGNUM* bn_ush = BN_new();
        BN_copy(bn_ush, BN_value_one());
        BN_mul(bn_sh, bn_s, proof->h, bn_ctx);   
        BN_mul(bn_ush, bn_u, bn_sh, bn_ctx);
        BN_add(proof->k, bn_r, bn_ush);
        libff::leave_block("Call to Optimized Compute (generate membership proof k)");


        // k' <- k mod l 
        libff::enter_block("Call to Optimized Compute (generate optimized membership proof k')");
        proof->opt_k = BN_new();
        BN_nnmod(proof->opt_k, proof->k, proof->l, bn_ctx);
        libff::leave_block("Call to Optimized Compute (generate optimized membership proof k')");

        // Q <- W^(k/l)
        libff::enter_block("Call to Optimized Compute (generate optimized membership proof Q)");
        BIGNUM* bn_exp_ret = BN_new();
        proof->Q = BN_new();
        BN_div(bn_exp_ret, NULL, proof->k, proof->l, bn_ctx);
        BN_mod_exp(proof->Q, proof->W, bn_exp_ret, bn_N, bn_ctx);
        libff::leave_block("Call to Optimized Compute (generate optimized membership proof Q)");

        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to Optimized compute (generate membership proof)");
    }

    bool verify(public_param* pp, libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, BIGNUM* &ACC, vector<BIGNUM*> S,
     mem_proof* proof, libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof) {
        libff::start_profiling();
        libff::enter_block("Call to verification");
        BIGNUM* tmp = BN_new();
        BN_CTX* bn_ctx = BN_CTX_new();
        BIGNUM* bn_denom = BN_new(); //for storing ACC^h 
        BIGNUM* bn_num = BN_new(); // for storing W^k
        BIGNUM* bn_ret = BN_new();

        BN_copy(bn_denom, BN_value_one());
        BN_copy(bn_num, BN_value_one());
        BN_copy(bn_ret, BN_value_one());
        
        // SNARK Verification
        bool snark_verify = libsnark::r1cs_gg_ppzksnark_verifier_weak_IC(snark_vk, snark_ex.primary_input, snark_proof);
    
        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));
        
        BN_mod_exp(bn_denom, ACC, proof->h, bn_N, bn_ctx); // bn_denom <- ACC^h
        BN_mod_exp(bn_num, proof->W, proof->k, bn_N, bn_ctx); // bn_num <- W^k
        
        BN_mod_inverse(bn_denom, bn_denom, bn_N, bn_ctx); // bn_denom <- ACC^{-h}
        BN_mod_mul(bn_ret, bn_num, bn_denom, bn_N, bn_ctx); // bn_ret <- W^k * ACC^{-h}

        // H(W || C || ACC^h/W^k)
        Hash2(tmp, proof->W, proof->C_x, proof->C_y, bn_ret);

        bool vfy_pass = (!BN_cmp(proof->h, tmp) && snark_verify);
        libff::leave_block("Call to verification");
        BN_CTX_free(bn_ctx);

        return vfy_pass;
    }

    bool optVerify(public_param* pp, libsnark::r1cs_gg_ppzksnark_verification_key<libsnark::default_r1cs_gg_ppzksnark_pp> snark_vk, 
    libsnark::r1cs_example<libff::Fr<libsnark::default_r1cs_gg_ppzksnark_pp>> snark_ex, BIGNUM* &ACC, vector<BIGNUM*> S,
     mem_proof* proof, libsnark::r1cs_gg_ppzksnark_proof<libsnark::default_r1cs_gg_ppzksnark_pp> snark_proof) {
        libff::start_profiling();
        libff::enter_block("Call to Optimized verification");
        BIGNUM* tmp = BN_new();
        BN_CTX* bn_ctx = BN_CTX_new();
        BIGNUM* bn_denom = BN_new(); //for storing ACC^h 
        BIGNUM* bn_num_1 = BN_new(); // for storing Q^l
        BIGNUM* bn_num_2 = BN_new(); // for storing W^k' 
        BIGNUM* bn_num = BN_new(); // for storing Q^l * W^k'
        BIGNUM* bn_ret = BN_new();

        BN_copy(bn_denom, BN_value_one());
        BN_copy(bn_num_1, BN_value_one());
        BN_copy(bn_num_2, BN_value_one());
        BN_copy(bn_ret, BN_value_one());
        
        // SNARK Verification
        bool snark_verify = libsnark::r1cs_gg_ppzksnark_verifier_weak_IC(snark_vk, snark_ex.primary_input, snark_proof);
     
        BIGNUM* bn_N = BN_new();
        BN_hex2bn(&bn_N, fmpz_get_str(NULL, 16, pp->N));
        
        BN_mod_exp(bn_denom, ACC, proof->h, bn_N, bn_ctx); // bn_denom <- ACC^h
        BN_mod_exp(bn_num_1, proof->Q, proof->l, bn_N, bn_ctx); // bn_num_1 <- Q^l
        BN_mod_exp(bn_num_2, proof->W, proof->opt_k, bn_N, bn_ctx); // bn_num_2 <- W^k'
        BN_mod_mul(bn_num, bn_num_1, bn_num_2, bn_N, bn_ctx); // bn_num <- Q^l * W^k'

        
        BN_mod_inverse(bn_denom, bn_denom, bn_N, bn_ctx); // bn_denom <- ACC^{-h}
        BN_mod_mul(bn_ret, bn_num, bn_denom, bn_N, bn_ctx); // bn_ret <- Q^l * W^k' * ACC^{-h}

        // H(W || C || Q^l * W^k' * ACC^{-h})
        Hash2(tmp, proof->W, proof->C_x, proof->C_y, bn_ret); 

        bool vfy_pass = ((!BN_cmp(proof->h, tmp)) && snark_verify);
        BN_CTX_free(bn_ctx);
        libff::leave_block("Call to Optimized verification");
        
        return vfy_pass;
    }
}

   