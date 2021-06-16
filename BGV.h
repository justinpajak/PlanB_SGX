#include <cstdio>
#include <cstdlib>
#include <ctime>
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