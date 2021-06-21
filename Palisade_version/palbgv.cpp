#include "palisade.h"
#include <iostream>
#include <vector>
#include <string>

using std::vector;
using namespace lbcrypto;

int main(int argc, char *argv[]) {

	// Set main parameters
	int plaintextModulus = 65537;
	double sigma = 3.2;
	SecurityLevel securityLevel = HEStd_128_classic;
	uint32_t depth = 2;

	// Crypto context
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
		depth, plaintextModulus, securityLevel, sigma, depth);

	// Enable features
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
	cc->Enable(LEVELEDSHE);

	// Generate public and private keys
	LPKeyPair<DCRTPoly> keyPair;
	keyPair = cc->KeyGen();
	cc->EvalMultKeysGen(keyPair.secretKey);

	// Read in data
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
	Plaintext pt = cc->MakePackedPlaintext(data);
	Ciphertext<DCRTPoly> ct = cc->Encrypt(keyPair.publicKey, pt);

	// Decrypt data
	Plaintext res;
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
	fclose(d);
}
