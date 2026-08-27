#pragma once
#include "stockholm.hpp"

/**
 * @brief Decrypt the data stored in IN using an hybrid RSA-AES decryption
 * @param privkey Path to the RSA private.pem file to decrypt the AES key with
 * @param header Pointer to header struct, containing informations about the file
 * @param in BIO containing the encrypted data
 * @param out BIO that will hold the decrypted content of IN
 * @return 1 on SUCCESS, 0 on FAILURE
 */
int rsa_aes_hybrid_decryption(const char *privkey,
							  stockholm::header *header,
							  BIO *in,
							  BIO *out);

/**
 * @brief Encrypt data from IN to OUT using an hybrid RSA-AES encryption
 * @param pubkey Path to the RSA public.pem file to encrypt AES the key with
 * @param in BIO containing the data to encrypt
 * @param out output BIO
 * @return 1 on SUCCESS, 0 on FAILURE
 */
int rsa_aes_hybrid_encryption(const char *pubkey, BIO *in, BIO *out);

/**
 * @brief Create a local RSA identity and encrypt the private key
 * @param master_public_pem Path to the public.pem file to encrypt the key with
 * @return 1 on SUCCESS, 0 on FAILURE
 */
int create_local_rsa_id(const char *master_public_pem);
