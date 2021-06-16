/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include <vector>

#define length_vector 4 //defining the length of vector to be 4
#define L 3 //defining depth of the circui to be 3
#define err 10 //defining the range of error to be 10
#define pt_q 11 //defining the upper bound of noise 

typedef struct
{
    int64_t p[L]; 
    int64_t q[L]; //Modulus on level L
    int64_t rp[L]; 
} Public_Paramater; 

typedef struct 
{
    int64_t s[length_vector]; 
    std::vector<int64_t> skvec[length_vector]; 
} Secret_Key;

typedef struct
{
    int64_t a[length_vector]; 
    int64_t b[length_vector]; 
    std::vector<int64_t> pkveca[length_vector]; 
    std::vector<int64_t> pkvecb[length_vector]; 
}Public_Key;

typedef struct 
{
    int64_t c0[length_vector]; 
    int64_t c1[length_vector]; 
    std::vector<int64_t> ctvec0[length_vector]; 
    std::vector<int64_t> ctvec1[length_vector]; 
    int64_t depth; 
}Ciphertext;

typedef struct 
{
    int64_t m[length_vector]; 
    std::vector<int64_t> mvec[length_vector]; 
}Plaintext;

int64_t mod(int64_t a, int64_t n);
int64_t Extended_Euclid(int64_t a, int64_t b, int64_t &x, int64_t &y);
int64_t mod_inverse(int64_t a, int64_t n); 
int isprime(int64_t n); 
int64_t proper_prime(int64_t q, int64_t start); 
Public_Paramater SetUp(int64_t p); 
std::vector<int64_t> chineseRemainder(int64_t x, Public_Paramater pubpara); 
Secret_Key SecKeyGen(Public_Paramater pubpara); 
Public_Key PubKeyGen(Public_Paramater pubpara, Secret_Key sk); 
Ciphertext Encrypt(Public_Paramater pubpara, Public_Key pk, Plaintext message, int depth);
Plaintext Decrypt(Public_Paramater pubpara, Secret_Key sk, Ciphertext ct);  
int64_t invChineseRemainder(std::vector<int64_t> vec, Public_Paramater pubpara); 

#if defined(__cplusplus)
extern "C" {
#endif

void printf(const char *fmt, ...);
void printf_helloworld();

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
