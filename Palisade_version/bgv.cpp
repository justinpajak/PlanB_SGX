#include "palisade.h"
#include "include/PALISADEContainer.h"
#include <iostream>
#include <vector>
#include <string>
#include <fstream>

using std::vector;
using namespace lbcrypto;

int main(int argc, char *argv[]) {

	// Parse command line arguments
	int choice = -1;
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch(argv[i][1]) {
				case 'e':
					choice = 1;
					break;
				case 'd':
					choice = 0;
					break;
				default: 
					return EXIT_FAILURE;
			}
		} else {
			return EXIT_FAILURE;
		}
	}
	
	// Encryption
	if (choice) {

		// Create Palisade Container
		std::cout << "Encryption running" << std::endl;
		unsigned int plaintextModulus = 536903681;
		unsigned int depth = 2;
		PALISADEContainer pc(plaintextModulus, depth, 64);

		// Read plaintext integers from file
		FILE *f = fopen("plaintext.txt", "r+");
		if (!f) {
			fprintf(stderr, "unable to open plaintext.txt: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
		char buffer[BUFSIZ];
		vector<int64_t> data;
		while (fgets(buffer, BUFSIZ, f) > 0) {
			data.push_back(atoi(buffer));
		}

		// Encrypt data
		Ciphertext<DCRTPoly> ct = pc.context->Encrypt(pc.pk, pc.context->MakePackedPlaintext(data));
		
		// Write encrypted data to file
		std::ofstream enc("encrypted.txt");
		

		//pc.serialize("container", true);
	}

	// Decryption
	else {
	
	}

	// Encrypt data
	//Ciphertext<DCRTPoly> ct = cc->Encrypt(keyPair.publicKey, pt);

	// Decrypt data
	/*Plaintext res;
	cc->Decrypt(keyPair.secretKey, ct, &res);

	// Send data to file 
	FILE *d = fopen("decrypted.txt", "w+");
	if (!d) {
		fprintf(stderr, "unable to open decrypted.txt: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	std::vector<int64_t> res_vec = res->GetPackedValue();
	for (int i = 0; i < pt->GetLength(); i++) {
		fprintf(d, "%lu\n", res_vec[i]);
	}
	fclose(d);*/
}
