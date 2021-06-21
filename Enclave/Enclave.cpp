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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <sgx_trts.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

// Completely right
void bgv_enc(char *buffer, size_t len) {

    // Construct plaintext object
    Plaintext pt;
    char *line = strtok(buffer, "\n");
    int i = 0;
    while (line) {
        pt.m[i] = atoi(line);
        line = strtok(NULL, "\n");
        i++;
    }

    // Encrypt plaintext
    int p = 941;
    int depth = 0;
    Public_Paramater pub = SetUp(p);
    Secret_Key sk = SecKeyGen(pub);
    Public_Key pk = PubKeyGen(pub, sk);
    Ciphertext ct = Encrypt(pub, pk, pt, depth);

    // Convert ct into a buffer
    char ct_buf[BUFSIZ];
    memset(ct_buf, '\0', BUFSIZ);
    std::string str;
    for (int i = 0; i < length_vector; i++) {
        str += std::to_string(ct.c0[i]);
        str += "\n";
    }
    str += "!\n";
    for (int i = 0; i < length_vector; i++) {
        str += std::to_string(ct.c1[i]);
        str += "\n";
    }
    str += "!\n";
    for (int i = 0; i < length_vector; i++) {
        for (int j = 0; j < ct.ctvec0[i].size(); j++) {
            str += std::to_string(ct.ctvec0[i][j]);
            str += "\n";
        }
    }
    str += "!\n";
    for (int i = 0; i < length_vector; i++) {
        for (int j = 0; j < ct.ctvec1[i].size(); j++) {
            str += std::to_string(ct.ctvec1[i][j]);
            str += "\n";
        }
    }
	str += "!\n";
	str += std::to_string(ct.depth);
	str += "\n";

    // Convert sk into a buffer
    char sk_buf[BUFSIZ];
    memset(sk_buf, '\0', BUFSIZ);
    std::string sk_str;
    for (int i = 0; i < length_vector; i++) {
        sk_str += std::to_string(sk.s[i]);
        sk_str += "\n";
    }
    sk_str += "!";
    sk_str += "\n";
    for (int i = 0; i < length_vector; i++) {
        for (int j = 0; j < sk.skvec[i].size(); j++) {
            sk_str += std::to_string(sk.skvec[i][j]);
            sk_str += "\n";
        }
    }

    // Return buffer containing ciphertext and secret key
    strlcpy(ct_buf, str.c_str(), BUFSIZ);
    strlcpy(sk_buf, sk_str.c_str(), BUFSIZ);
    return_ciphertext(ct_buf, BUFSIZ, sk_buf, BUFSIZ);
}

void bgv_dec(char *ciphertext, size_t len, char *secretkey, size_t len1) {
 
    // Constuct ciphertext object - DONE
    Ciphertext ct;
    char *line = strtok(ciphertext, "\n");
    int i = 0;
    int j = 0;
    int ex = 0;
    char *end;
    while (line) {
        if (*line == '!') {
            ex++;
            i = 0;
            j = 0;
            line = strtok(NULL, "\n");
            continue;
        }
        if (ex == 0) {
            ct.c0[i] = (uint64_t)strtoul(line, &end, 10);
            line = strtok(NULL, "\n");
            i++;
        }
        if (ex == 1) {
            ct.c1[i] = (uint64_t)strtoul(line, &end, 10);
            line = strtok(NULL, "\n");
            i++;
        }
        if (ex == 2) {
            ct.ctvec0[j].push_back((uint64_t)strtoul(line, &end, 10));
            line = strtok(NULL, "\n");
            i++;
            if (i == 4) {
                j++;
                i = 0;
            }
        }
        if (ex == 3) {
            ct.ctvec1[j].push_back((uint64_t)strtoul(line, &end, 10));
            line = strtok(NULL, "\n");
            i++;
            if (i == 4) {
                j++;
                i = 0;
            }
        }
		if (ex == 4) {
			ct.depth = (uint64_t)strtoul(line, &end, 10);
			line = strtok(NULL, "\n");
		}
    }

    // Construct Secret Key object - DONE
    Secret_Key sk;
    line = strtok(secretkey, "\n");
    i = 0;
    j = 0;
    ex = 0;
    while (line) {
        if (*line == '!') {
            ex++;
            i = 0;
            line = strtok(NULL, "\n");
            continue;
        }
        if (ex == 0) {
            sk.s[i] = (uint64_t)strtoul(line, &end, 10);
            line = strtok(NULL, "\n");
            i++;
        }
        if (ex == 1) {
            sk.skvec[j].push_back((uint64_t)strtoul(line, &end, 10));
            line = strtok(NULL, "\n");
            i++;
            if (i == 4) {
                j++;
                i = 0;
            }
        }
    }

 	// Decrypt ciphertext 
    int p = 941; 
    Public_Paramater pub = SetUp(p);
    Plaintext pt = Decrypt(pub, sk, ct);

    // Convert pt to a buffer 
    char pt_buf[BUFSIZ];
    memset(pt_buf, '\0', BUFSIZ);
    std::string str;
    for (int i = 0; i < length_vector; i++) {
        str += std::to_string(pt.m[i]);
        str += "\n";
    }

    // Return buffer containing plaintext
	printf("running decrypt");
    strlcpy(pt_buf, str.c_str(), BUFSIZ);
    return_plaintext(pt_buf, BUFSIZ);
}



/***************************************************************************/
/*                             Ting's BGV Code                             */
int64_t mod(int64_t a, int64_t n) //recoded mod to include the negatives
{
    int64_t b=a;
    if (b<0)
    {
        b = -b;
        b = b%n;
        b = (n-b)%n;
    }
    else
    {
        b = b%n;
    }
    return b;
}

int64_t Extended_Euclid(int64_t a, int64_t b, int64_t &x, int64_t &y)//Extended Euclid Algorithm
{
    if(b == 0)
    {
        x = 1; 
        y = 0; 
        return a; 
    }
    int64_t r = Extended_Euclid(b, a%b, x, y); 
    int64_t t = x; 
    x=y; 
    y = t-a/b * y; 
    return r; 
}

int64_t mod_inverse(int64_t a, int64_t n) //Find the modulo inverse of a
{
    int64_t d,x,y; 
    d = Extended_Euclid(a,n,x,y); 
    if(d == 1)
        return (x%n + n)%n; 
    else
        return -1; 
}

int isprime(int64_t n)//check if n is a prime
{
    int64_t check = 1; 
    for(int i = 2; i<n; i++)
    {
        if(n%i == 0)
        {
            check = 0; 
            break; 
        }
    }
    return check; 
}

int64_t proper_prime(int64_t q, int64_t start)//Find a prime that works for our setup
{
    int64_t i, result = 0; 
    for(i = start; ;i++)
    {
        if(isprime(i))
        {
            if((i-1)%q == 0)
            {
                result = i;
                break; 
            }
        }
    }
    if(!result)
    {
        printf("error\n");
    }
    return result; 
}

Public_Paramater SetUp(int64_t p)//Set up public parameter
{
    Public_Paramater pubpara; 
    pubpara.p[0] = p; 
    pubpara.q[0] = pubpara.p[0]; 
    pubpara.rp[0] = 1; 
    for(int i=0; i<L-1; i++)
    {
        pubpara.p[i+1] = proper_prime(pubpara.p[0], pubpara.p[i] + 1);
        pubpara.q[i+1] = pubpara.p[i+1] * pubpara.q[i]; 
        pubpara.rp[i] = mod_inverse(pubpara.p[i+1], pubpara.q[i]); 
    }
    return pubpara; 
}

std::vector<int64_t> chineseRemainder(int64_t x, Public_Paramater pubpara)
{
    std::vector<int64_t> conv; 
    for(int i = 0; i<L; i++)
    {
        conv.push_back(x % pubpara.p[i]); 
    }
    return conv; 
}

Secret_Key SecKeyGen(Public_Paramater pubpara)//Define Secret key
{
    Secret_Key sk;
    uint32_t r;
    for(int i = 0; i<length_vector; i++)
    {
        sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
        sk.s[i] = r % pubpara.q[L-1];
        sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
        sk.skvec[i] = chineseRemainder(r, pubpara); 
    }
    return sk; 
}

Public_Key PubKeyGen(Public_Paramater pubpara, Secret_Key sk)//Define Public Key
{
    Public_Key pk; 
    long error[length_vector]; 
    std::vector<int64_t> errorvec[length_vector];
    uint32_t r;
    for(int i = 0; i< length_vector; i++)
    {
        sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
        pk.a[i] = mod(r, pubpara.q[L-1]); 
        sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
        pk.pkveca[i] = chineseRemainder(r, pubpara); 
        for(int j = 0; j<L; j++)
        {
            sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
            errorvec[i].push_back(mod(r, err)); 
            pk.pkvecb[i].push_back(mod(pk.pkveca[i].at(j)* sk.skvec[i].at(j) + 
                pubpara.p[j] * errorvec[i].at(j), pubpara.q[L-1])); 
        }
        sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
        error[i] = mod(r, err);
        pk.b[i] = pk.a[i] * sk.s[i] + pubpara.p[0] * error[i]; 
        pk.b[i] = mod(pk.b[i], pubpara.q[L-1]); 
    }
    return pk; 
}

Ciphertext Encrypt(Public_Paramater pubpara, Public_Key pk, Plaintext message, int depth)
{
    int64_t voise[length_vector]; 
    std::vector<int64_t> voisevec[length_vector]; 
    int64_t e0[length_vector]; 
    std::vector<int64_t> e0vec[length_vector]; 
    int64_t e1[length_vector]; 
    std::vector<int64_t> e1vec[length_vector]; 
    Ciphertext ct;
    uint32_t r;
    for(int i = 0; i<length_vector; i++)
    {
        sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
        voise[i] = r % 2;
        sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
        e0[i] = r % err;
        sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
        e1[i] = r % err; 
        ct.c0[i] = pk.b[i] * voise[i] + pubpara.p[0] * e0[i] + message.m[i]; 
        ct.c0[i] = mod(ct.c0[i], pubpara.q[depth]);
        ct.c1[i] = pk.a[i] * voise[i] + pubpara.p[0] * e1[i]; 
        ct.c1[i] = mod(ct.c1[i], pubpara.q[depth]);  
        message.mvec[i] = chineseRemainder(message.m[i], pubpara); 
        for(int j = 0; j<L; j++)
        {
            sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
            voisevec[i].push_back(r % 2);
            sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
            e0vec[i].push_back(r % err);
            sgx_read_rand((unsigned char*) &r, sizeof(uint32_t));
            e1vec[i].push_back(r % err); 
            ct.ctvec0[i].push_back(mod((pk.pkvecb[i].at(j) * voisevec[i].at(j) + 
                pubpara.p[j]* e0vec[i].at(j) + message.mvec[i].at(j)), pubpara.q[L-1])); 
            ct.ctvec1[i].push_back(mod((pk.pkveca[i].at(j) * voisevec[i].at(j) + 
                pubpara.p[j]* e1vec[i].at(j)), pubpara.q[L-1])); 
        }
    }
    ct.depth = depth; 
    return ct; 
}

Plaintext Decrypt(Public_Paramater pubpara, Secret_Key sk, Ciphertext ct)
{
    Plaintext message; 
    for(int i = 0; i<length_vector; i++)
    {
        message.m[i] = ct.c0[i] - sk.s[i] * ct.c1[i]; 
        message.m[i] = mod(message.m[i], pubpara.q[ct.depth]); 
        message.m[i] = mod(message.m[i], pubpara.p[0]);
        /*for(int j = 0; j<L; j++)
        {
            message.mvec[i].push_back(mod(mod(ct.ctvec0[i].at(j) - sk.skvec[i].at(j) * ct.ctvec1[i].at(j), pubpara.q[L-1]),pubpara.p[j])); 
        }*/
    }
    return message; 
}

int64_t invChineseRemainder(std::vector<int64_t> vec, Public_Paramater pubpara)
{
    int64_t x = 0; 
    for(int i = 0; i<L; i++)
    {
        x = x + vec.at(i) * pubpara.q[L-1]/pubpara.p[i] * 
            mod_inverse(pubpara.q[L-1]/pubpara.p[i],pubpara.p[i]);
    }
    x = mod(x, pubpara.q[L-1]); 
    return x; 
}
