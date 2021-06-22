#ifndef PALISADECONTAINER_H
#define PALISADECONTAINER_H

//#include <iostream>
#include <sstream>
#include <cmath>

//Make sure you get the include directories right, or this will error
#include <palisade.h>
#include <palisade/pke/palisade.h>
#include <ciphertext-ser.h>
#include <cryptocontext.h>
#include <cryptocontext-ser.h>
#include <pubkeylp-ser.h>
#include <scheme/ckks/ckks-ser.h>
//#include <utils/serialize-binary.h>
#include <utils/serial.h>

using namespace lbcrypto;

#define CONTEXT_FILE "context"
#define PUBKEY_FILE "pubkey"
#define EMKEY_FILE "emkey"
#define SECKEY_FILE "seckey"
#define ROTKEY_FILE "rotkey"

class PALISADEContainer{

public:
  /*
  static const unsigned int DEGREE_DEFAULT = 8192;
  static const unsigned int PLAIN_MOD_SIZE_DEFAULT = 20;
  static const unsigned int PLAIN_DEFAULT = 1 << PLAIN_MOD_SIZE_DEFAULT;
  */
  static const constexpr double SIGMA = 3.2;
  static const SecurityLevel SECURITY = HEStd_128_classic;
  static const constexpr SerType::SERBINARY & SERIAL_FORMAT = SerType::BINARY; //SerType is not recognized...
  static const unsigned int BATCHSIZE_DEFAULT = 64;
  //static const unsigned int M_DEFAULT = 32768;

  //Change these 2 together
  static const constexpr unsigned int PLAIN_DEFAULT = 65537; //This must be prime!
  //TODO fix this up - linker error with static const apparently
  //const unsigned int PLAIN_DEFAULT_MIN_PRIMROOT = 6;
  static const constexpr unsigned int DEPTH_DEFAULT = 4;

  static const unsigned int SCALE_FACTOR_BITS = 50;

  CryptoContext<DCRTPoly> context = nullptr;
  LPPublicKey<DCRTPoly> pk = nullptr;
  LPPrivateKey<DCRTPoly> sk = nullptr;

  bool _has_secret_key = false;
  
  unsigned int _plain_modulus = 0;
  unsigned int depth = 0;

  //PALISADEContainer operator=(const PALISADEContainer & other) = default;
  //TODO may have to redefine these macros, or remove altogether
  //See https://gitlab.com/palisade/palisade-development/-/blob/master/src/pke/examples/simple-integers-serial.cpp
  //This constructor is for BGV - see new one below for CKKS
  PALISADEContainer(const unsigned int plain_in = PLAIN_DEFAULT, const unsigned int depth_in = DEPTH_DEFAULT, 
                    const unsigned int slots_in = BATCHSIZE_DEFAULT) : _plain_modulus(plain_in), depth(depth_in) {
    //See https://gitlab.com/palisade/palisade-release/-/blob/master/src/pke/include/cryptocontext.h
    context = CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(depth, _plain_modulus, SECURITY, SIGMA, depth, OPTIMIZED, BV);
    //context = CryptoContextFactory<DCRTPoly>::genCryptoContextNull(16384, 65537);

    context->Enable(ENCRYPTION);
    context->Enable(SHE);
    context->Enable(LEVELEDSHE);
    

    LPKeyPair<DCRTPoly> keyPair = context->KeyGen();
    if (!keyPair.good()) {
      std::cerr << "Key generation failed!" << std::endl;
      exit(1);
    }
    pk = keyPair.publicKey;
    sk = keyPair.secretKey;

    context->EvalMultKeysGen(sk);
    this->_has_secret_key = true;
  }

  //CKKS constructor - quick+dirty impl., not parameterized
  //Default for m should be 8192
  /*PALISADEContainer(unsigned int m, unsigned int depth_in, unsigned int p){
    static const int dcrtBits = 40;
    depth = depth_in;
    _plain_modulus = 0;
    unsigned int batchSize = m >> 2;

    context =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKSWithParamsGen(
          m, depth, //numPrimes
          dcrtBits, 10, //relinWindow
          batchSize,           //batch size
          OPTIMIZED, depth); 	// depth


    context->Enable(ENCRYPTION);
    context->Enable(SHE);
    context->Enable(LEVELEDSHE);
    

    LPKeyPair<DCRTPoly> keyPair = context->KeyGen();
    if (!keyPair.good()) {
      std::cerr << "Key generation failed!" << std::endl;
      exit(1);
    }
    pk = keyPair.publicKey;
    sk = keyPair.secretKey;

    context->EvalMultKeysGen(sk);
    this->_has_secret_key = true;
    //Generate rotation keys for ((N/2)/D)+1 of the indices
    //Let's start with (N/2)/D = 2, for a 50% reduction in the key switching
    vector<int> indices;
    unsigned int N = context->GetRingDimension()/2;
    int B = N/2;
    int reduction_factor = sqrt(B); //Factor we want to reduce by
    int D = B/reduction_factor; //Step size - need to generate all keys from 1 to D, and all multiples of D
    indices.reserve(D+(reduction_factor));
    //This loop would go up to <= D, but that's handled in the next one
    for(int i = 1; i < D; i++){
      indices.push_back(i);
    }
    //All the multiples of D, up to the batch size
    for(int i = D; i < B; i += D){
      indices.push_back(i);
    }

    //Hopefully this does not take up too much memory
    //May have to serialize these
    context->EvalAtIndexKeyGen(sk, indices);
  } */

  //This will fail if called on a nonexistent or empty file
  PALISADEContainer(const std::string & containername, const bool load_sk){
		if(this->deserialize(containername, load_sk)){
      std::cerr << "ERROR: failed to load PALISADEContainer from file " << containername << std::endl;
      exit(0);
    }
    this->_has_secret_key = load_sk;
  }

  inline LPPublicKey<DCRTPoly> public_key() const {
    return pk;
  }

  inline LPPrivateKey<DCRTPoly> secret_key() const {
    return sk;
  }
  
  
  /*int serialize(std::ostream & os, const bool save_sk){
    //Context
    if(!Serial::Serialize(context, os, SERIAL_FORMAT)){
      return 1;
    }
    //Public key 
    if(!Serial::Serialize(keyPair.publicKey, os, SERIAL_FORMAT)){
      return 1;
    }
    
    //Relin. keys
    if(!this->context->SerializeEvalMultKey(os, SERIAL_FORMAT)){
      return 1;
    }
    //Secret key always saved last
    if(save_sk){
      if(!Serial::Serialize(keyPair.secretKey, os, SERIAL_FORMAT)){
        return 1;
      }
    }
    return 0;
  }*/
  

  int serialize(const std::string & ofname, const bool save_sk){
    //Context
    std::string context_name = ofname + '/' + CONTEXT_FILE;
    if(!Serial::SerializeToFile(context_name, context, SERIAL_FORMAT)){
      std::cerr << "Failed to write context: " << context_name << std::endl;
      return 1;
    }
    //Public key 
    std::string pubkey_name = ofname + '/' + PUBKEY_FILE;
    if(!Serial::SerializeToFile(pubkey_name, pk, SERIAL_FORMAT)){
      std::cerr << "Failed to write pubkey: " << pubkey_name << std::endl;
      return 1;
    }
    
    //Relin. keys
    std::string rlk_file = ofname + '/' + EMKEY_FILE;
    std::ofstream os(rlk_file, std::ios::out | std::ios::binary);
    if(!os.is_open()){
      std::cerr << "ERROR: failed to open RLK file " << rlk_file << std::endl;
      return 1;
    }
    if(!this->context->SerializeEvalMultKey(os, SERIAL_FORMAT)){
      std::cerr << "Failed to write emkey: " << rlk_file << std::endl;
      return 1;
    }
    os.close();
    //Secret key always saved last
    if(save_sk){
      std::string seckey_name = ofname + '/' + SECKEY_FILE;
      if(!Serial::SerializeToFile(seckey_name, sk, SERIAL_FORMAT)){
        std::cerr << "Failed to write seckey: " << seckey_name << std::endl;
        return 1;
      }
    }
    //With separate files, the order doesn't matter
    std::string rot_file = ofname + '/' + ROTKEY_FILE;
    std::ofstream rots(rot_file, std::ios::out | std::ios::binary);
    if(!rots.is_open()){
      std::cerr << "ERROR: failed to open ROTKEY file " << rlk_file << std::endl;
      return 1;
    }
    if(!context->SerializeEvalAutomorphismKey(rots, SERIAL_FORMAT)){
      std::cerr << "Failed to write rotkey: " << rlk_file << std::endl;
      return 1;
    }
    return 0;
  }

  /*
  int serialize(std::string & ofname, const bool save_sk){
    std::ofstream ofs(ofname);
    return this->serialize(ofs, save_sk);
  }
  */
  
  /*
  int deserialize(std::istream & is, const bool load_sk){
    //Context
    if(!Serial::Deserialize(context, is, SERIAL_FORMAT)){
      return 1;
    }
    //Public key 
    if(!Serial::Deserialize(keyPair.publicKey, is, SERIAL_FORMAT)){
      return 1;
    }
    //Relin. keys
    if(!this->context->DeserializeEvalMultKey(is, SERIAL_FORMAT)){
      return 1;
    }
    //Secret key always saved last
    if(load_sk){
      if(!Serial::Deserialize(keyPair.secretKey, is, SERIAL_FORMAT)){
        return 1;
      }
    }
    this->_has_secret_key = load_sk;
    return 0;
  }
  */

  /*
  int deserialize(const std::string & fname, const bool load_sk){
    std::ifstream ifs(fname);
    return this->deserialize(ifs, load_sk);
  }
  */

  int deserialize(const std::string & fname, const bool load_sk){
    //Context
    std::string context_name = fname + '/' + CONTEXT_FILE;
    if(!Serial::DeserializeFromFile(context_name, context, SERIAL_FORMAT)){
      return 1;
    }
    //Public key 
    std::string pubkey_name = fname + '/' + PUBKEY_FILE;
    if(!Serial::DeserializeFromFile(pubkey_name, pk, SERIAL_FORMAT)){
      return 1;
    }
    
    //Relin. keys
    context->ClearEvalMultKeys();
    std::string rlk_file = fname + '/' + EMKEY_FILE;
    std::ifstream os(rlk_file, std::ios::in | std::ios::binary); //Bad naming
    if(!os.is_open()){
      return 1;
    }
    if(!this->context->DeserializeEvalMultKey(os, SERIAL_FORMAT)){
      return 1;
    }
    os.close();
    //Secret key always saved last, if all serialized to one file (not currently implemented)
    if(load_sk){
      std::string seckey_name = fname + '/' + SECKEY_FILE;
      if(!Serial::DeserializeFromFile(seckey_name, sk, SERIAL_FORMAT)){
        return 1;
      }
    }
    std::string rot_file = fname + '/' + ROTKEY_FILE;
    std::ifstream rots(rot_file, std::ios::in | std::ios::binary);
    if(!rots.is_open()){
      return 1;
    }
    if(!context->DeserializeEvalAutomorphismKey(rots, SERIAL_FORMAT)){
      std::cerr << "ERROR: failed to deserialize rotation keys from " << rot_file << std::endl;
      return 1;
    }
    return 0;
  }
  
  inline unsigned int slot_count() const {
    return context->GetEncodingParams()->GetBatchSize();
  }

  //Returns t from batching
  inline long plain_modulus() const {
  	return context->GetEncodingParams()->GetPlaintextModulus();
  }

  inline long ring_dimension() const {
    return context->GetRingDimension();
  }

  inline long cyclotomic_order() const {
    return context->GetCyclotomicOrder();
  }

  inline bool has_secret_key() const {
    return this->_has_secret_key;
  }
  
};












































#endif
