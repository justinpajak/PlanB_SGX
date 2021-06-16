#include "BGV.h"
#include <iostream>
#include <cstdint>
#include <array>

int main (){
	int64_t p = 941; 
	Public_Paramater pubpara = SetUp(p); 
	Secret_Key sk = SecKeyGen(pubpara); 
	Public_Key pk = PubKeyGen(pubpara, sk); 
	Plaintext message; 
	message.m[0] = 2064; 
	message.m[1] = 97; 
	message.m[2] = 974; 
	message.m[3] = 738; 
	int depth = 0; 
	Ciphertext ct = Encrypt(pubpara, pk, message, depth); 
	Plaintext aftercrypt; 
	aftercrypt = Decrypt(pubpara, sk, ct);  
	int64_t check0  = invChineseRemainder(aftercrypt.mvec[0],pubpara); 
	message.mvec[0] =  chineseRemainder(message.m[0], pubpara); 
	int64_t message0  = invChineseRemainder(message.mvec[0],pubpara); 
	/*if(aftercrypt.m[0] == message.m[0])
	{
		std::cout<<"YES for array"<<std::endl; 
	}
	else
	{
		std::cout<<"NO for array "<<aftercrypt.m[0]<<" "<<message.m[0]<<std::endl; 
	}
	if(check0 == message.m[0])
	{
		std::cout<<"YES for vector"<<std::endl; 
	}
	else
	{
		std::cout<<"NO for vector"<<check0<<" "<<message0<<std::endl; 
		std::cout<<"vector"<<message.mvec[0].at(1)<<" "<<aftercrypt.mvec[0].at(1)<<std::endl; 
	}*/
	for (int i = 0; i < length_vector; i++) {
		std::cout << message.m[i] << std::endl;
	}
	std::cout << std::endl;
	for (int i = 0; i < length_vector; i++) {
		std::cout << aftercrypt.m[i] << std::endl;
	}
}

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
	for(int i = 0; i<length_vector; i++)
	{
		sk.s[i] = rand() % pubpara.q[L-1]; 
		sk.skvec[i] = chineseRemainder(rand(), pubpara); 
	}
	return sk; 
}

Public_Key PubKeyGen(Public_Paramater pubpara, Secret_Key sk)//Define Public Key
{
	srand(2); 
	Public_Key pk; 
	long error[length_vector]; 
	std::vector<int64_t> errorvec[length_vector]; 
	for(int i = 0; i< length_vector; i++)
	{
		pk.a[i] = mod(rand(), pubpara.q[L-1]); 
		pk.pkveca[i] = chineseRemainder(rand(), pubpara); 
		for(int j = 0; j<L; j++)
		{
			errorvec[i].push_back(mod(rand(), err)); 
			pk.pkvecb[i].push_back(mod(pk.pkveca[i].at(j)* sk.skvec[i].at(j) + 
				pubpara.p[j] * errorvec[i].at(j), pubpara.q[L-1])); 
		}
		error[i] = mod(rand(), err);
		pk.b[i] = pk.a[i] * sk.s[i] + pubpara.p[0] * error[i]; 
		pk.b[i] = mod(pk.b[i], pubpara.q[L-1]); 
	}
	return pk; 
}

Ciphertext Encrypt(Public_Paramater pubpara, Public_Key pk, Plaintext message, int depth)
{
	srand(3); 
	int64_t voise[length_vector]; 
	std::vector<int64_t> voisevec[length_vector]; 
	int64_t e0[length_vector]; 
	std::vector<int64_t> e0vec[length_vector]; 
	int64_t e1[length_vector]; 
	std::vector<int64_t> e1vec[length_vector]; 
	Ciphertext ct; 
	for(int i = 0; i<length_vector; i++)
	{
		voise[i] = rand()%2; 
		e0[i] = rand()% err; 
		e1[i] = rand()% err; 
		ct.c0[i] = pk.b[i] * voise[i] + pubpara.p[0] * e0[i] + message.m[i]; 
		ct.c0[i] = mod(ct.c0[i], pubpara.q[depth]);
		ct.c1[i] = pk.a[i] * voise[i] + pubpara.p[0] * e1[i]; 
		ct.c1[i] = mod(ct.c1[i], pubpara.q[depth]);  
		message.mvec[i] = chineseRemainder(message.m[i], pubpara); 
		for(int j = 0; j<L; j++)
		{
			voisevec[i].push_back(rand()%2); 
			e0vec[i].push_back(rand()% err); 
			e1vec[i].push_back(rand()% err); 
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
		for(int j = 0; j<L; j++)
		{
			message.mvec[i].push_back(mod(mod(ct.ctvec0[i].at(j) - sk.skvec[i].at(j) * ct.ctvec1[i].at(j), 
				pubpara.q[L-1]),pubpara.p[j])); 
		} 
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
