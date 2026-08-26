#pragma once
#include "stockholm.hpp"

/**
 * @brief Decrypt the data stored in INFILE using an hybrid RSA-AES decryption
 * @param privkey Path to the RSA private.pem file to decrypt the AES key with
 * @param infile Path to the encrypted file
 * @param header Pointer to header struct, containing informations about the file
 * @param out Buffer that will hold the decrypted content of INFILE
 * @param outl Size of OUT
 * @return 1 on SUCCESS, 0 on FAILURE
 */
int rsa_aes_hybrid_decryption(const char *privkey, const char *infile,
							  stockholm::header *header, unsigned char **out, int *outl);

/**
 * @brief Encrypt IN of INL size data using an hybrid RSA-AES encryption
 * @param pubkey Path to the RSA public.pem file to encrypt AES the key with
 * @param outfile Path to the destination file
 * @param in Data to encrypt
 * @param inl Size of the data
 * @return 1 on SUCCESS, 0 on FAILURE
 */
int rsa_aes_hybrid_encryption(const char *pubkey, const char *outfile,
							  unsigned char *in, size_t inl);

/**
 * @brief Create a local RSA identity and encrypt the private key
 * @param master_public_pem Path to the public.pem file to encrypt the key with
 * @return 1 on SUCCESS, 0 on FAILURE
 */
int create_local_rsa_id(const char *master_public_pem);
