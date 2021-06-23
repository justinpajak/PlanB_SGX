#include "include/PALISADEContainer.h"
#include <scheme/bgvrns/bgvrns-ser.h>
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>

using std::vector;
using namespace lbcrypto;

int main(int argc, char *argv[]) {

	// Parse command line arguments
	int choice = -1;
	int n = 4096;
	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			switch(argv[i][1]) {
				case 'e':
					choice = 1;
					break;
				case 'd':
					choice = 0;
					break;
				case 'n':
					n = atoi(argv[++i]);
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

		auto start = std::chrono::high_resolution_clock::now();

		// Create Palisade Container
		std::cout << "Encryption running" << std::endl;
		unsigned int plaintextModulus = 65537;
		unsigned int depth = 2;
		PALISADEContainer pc(plaintextModulus, depth);

		// Read plaintext integers from file
		FILE *f = fopen("plaintext.txt", "r+");
		if (!f) {
			fprintf(stderr, "unable to open plaintext.txt: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
		char buffer[BUFSIZ];
		vector<int64_t> data;
		while (fgets(buffer, BUFSIZ, f) > 0) {
			data.push_back((int64_t)atoi(buffer));
		}
		fclose(f);

		// Encrypt data
		Plaintext pt = pc.context->MakePackedPlaintext(data);
		Ciphertext<DCRTPoly> ct = pc.context->Encrypt(pc.pk, pt);
	
		// Write data to file
		std::ofstream enc("encrypted.txt");
		Serial::Serialize(ct, enc, SerType::BINARY);

		pc.serialize("container", true);

		auto stop = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
		std::cout << "Time: " << duration.count() / double(1000000) << " seconds." << std::endl;
	}

	// Decryption
	else {

		auto start = std::chrono::high_resolution_clock::now();
		
		// Load Palisade Container
		PALISADEContainer pc("container", true);

		// Read in encrypted data and decrypt
		std::ifstream enc("encrypted.txt");
		Plaintext pt;
		Ciphertext<DCRTPoly> ct;
		Serial::Deserialize(ct, enc, SerType::BINARY);
		pc.context->Decrypt(pc.sk, ct, &pt);
		vector<int64_t> data = pt->GetPackedValue();

		// Write data to file
		FILE *f = fopen("decrypted.txt", "w+");
		if (!f) {
			fprintf(stderr, "unable to open decrypted.txt: %s\n", strerror(errno));
			return EXIT_FAILURE;
		}
		for (int i = 0; i < n; i++) {
			int64_t val = data[i];
			if (val < 0) {
				val += pc.plain_modulus();
			}
			fprintf(f, "%ld\n", val);
		}
		fclose(f);

		auto stop = std::chrono::high_resolution_clock::now();
		auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
		std::cout << "Time: " << duration.count() / double(1000000) << " seconds." << std::endl;

	}
}
