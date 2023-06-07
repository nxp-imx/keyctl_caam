/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2020, 2021, 2023 NXP
 */

#ifndef CAAM_KEYGEN_PRIV_H
#define CAAM_KEYGEN_PRIV_H

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <openssl/evp.h>

#define KEY_SIZE		32   /* AES-256 key size in bytes */
#define IV_LEN			16    /* IV size in bytes */
#define SALT_SIZE		8   /* Salt size in bytes */
#define ITERATIONS		10000  /* Number of iterations for PBKDF2 */
#define SUCCESS			0
#define FAILURE			-1
#define DEVICE_NAME		"/dev/caam-keygen"

#define MKDIR_COMMAND		"mkdir -p "
#define QUOTES			"\""

/* Default location for keys and blobs */
#ifndef KEYBLOB_LOCATION
#define KEYBLOB_LOCATION	"/data/caam/"
#endif

/*
 * Minimum key size to be used is 16 bytes and maximum key size fixed
 * is 64 bytes.
 */
#define MIN_KEY_SIZE		16
#define MAX_KEY_SIZE		64
/* Tagged keys header size. */
#define TAG_OVERHEAD_SIZE	20
/*
 * A CCM Black key is a multiple of 8 byte, at least the size of the key
 * plus 6 byte for the nonce and 6 byte for the IV
 */
#define NONCE_SIZE		6
#define IV_SIZE			6
#define CCM_OVERHEAD		(NONCE_SIZE + IV_SIZE)

#define MAX_BLACK_KEY_SIZE	(MAX_KEY_SIZE + CCM_OVERHEAD +\
				 TAG_OVERHEAD_SIZE)

/* Define space required for blob key + MAC tag storage in any blob */
#define BLOB_OVERHEAD		(32 + 16)

/*
 * For blobs a randomly-generated, 256-bit blob key is used to
 * encrypt the data using the AES-CCM cryptographic algorithm.
 * Therefore, blob size is max key size, CCM_OVERHEAD, blob header
 * and MAC tag added by CAAM and the tagged object header size.
 */
#define MAX_BLOB_SIZE		(MAX_KEY_SIZE + CCM_OVERHEAD +\
				 BLOB_OVERHEAD + TAG_OVERHEAD_SIZE)

int caam_keygen_create(char *key_name, char *key_enc, char *key_mode,
		       char *key_value, char *text_type, int key_val_length);

int caam_keygen_import(char *blob_name, char *key_name);
void caam_keygen_derive_key(unsigned char *salt, const char *password,
			    const EVP_MD *digest, char *key_path);
#endif /* CAAM_KEYGEN_PRIV_H */
