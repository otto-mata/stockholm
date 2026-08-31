#pragma once
#include <openssl/types.h>

EVP_PKEY *NewPublicKey(const unsigned char *data);
