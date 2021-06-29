# PlanB_SGX
BGVrns Encryption and Decryption Implemented in two ways:<br/>
1. SGX using only SGX sdk
2. SGX using PALISADE and Graphene

How to build and run SGX sdk program:
------------------------------------
1. ./cleaner (Empties secretkey.txt, ciphertext.txt, and decrypted.txt)
2. ./gen.py  (Generate 4096 plaintext integers and put them in plaintext.txt)
3. make      (Make SGX program)
4. ./app -e  (Run encryption program - populates secretkey.txt and ciphertext.txt)
5. ./app -d  (Run decryption program - writes result decrypted.txt)

If the plaintext integers are less than the plaintext modulus specified twice in Enclave/Enclave.cpp:<br/>
- The contents of decrypted.txt and plaintext.txt should be exactlty the same 

However, if the integers are greater than the plaintext modulus:<br/>
- The contents of decrypted.txt will be the integer mod plaintext modulus.
- Ex: p = 941, x = 12365. Dec(Enc(x)) = x mod p = 132

How to build and run SGX PALISADE program:
-----------------------------------------
1. cd Palisade_version/ 
2. ./cleaner                   (Empties encrypted.txt and decrypted.txt)
3. ./gen.py                    (Generates 4096 plaintext integers and put them in plaintext.txt)
4. make                        (Makes bgv program)
5. make SGX=1 -f mk_graphene bgv.manifest.sgx bgv.token pal_loader
6. SGX=1 ./pal_loader ./bgv -e (Run encryption program - populates ciphertext.txt and container/)
7. SGX=1 ./pal_loader ./bgv -d (Run decryption program - writes result to decrypted.txt)
