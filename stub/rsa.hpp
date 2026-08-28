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
int DecryptData_HybridRSA_AES(const char *privkey,
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
int EncryptData_HybridRSA_AES(const char *pubkey, BIO *in, BIO *out);

/**
 * @brief Create a local RSA identity and encrypt the private key
 * @param publicPemPath Path to the public.pem file to encrypt the key with
 * @param localPublicPemPath Path where to write the local public pem
 * @param localEncryptedPrivatePemPath Path where to write the local encrypted private pem
 * @return  1 on SUCCESS, 0 on FAILURE
 */
int CreateLocalRSAIdentity(fs::path publicPemPath,
						   fs::path localPublicPemPath,
						   fs::path localEncryptedPrivatePemPath);
