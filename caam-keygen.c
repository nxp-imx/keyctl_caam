// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2021, 2023 NXP
 */

#include "caam-keygen.h"
#include "caam-keygen_priv.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <ctype.h>
int caam_keygen_fd;

void caam_keygen_usage(void)
{
	printf("CAAM keygen usage: caam-keygen [options]\n");
	printf("Options:\n");
	printf("create <key_name> <key_enc> <key_mode> <key_val> <text_type>\n");
	printf("\t<key_name> the name of the file that will contain the black key.\n");
	printf("\tA file with the same name, but with .bb extension, will contain the black blob.\n");
	printf("\t<key_enc> can be ecb or ccm\n");
	printf("\t<key_mode> can be -s or -t.\n");
	printf("\t   -s generate a black key from random with the size given in the next argument\n");
	printf("\t   -t generate a black key from a plaintext given in the next argument\n");
	printf("\t<key_val> the size or the plaintext based on the previous argument (<key_mode>)\n");
	printf("\t<text_type> can be -h or -p (default argument is -p)\n");
	printf("\t   -h generate a black key from the hex text that is "
		"provided in previous argument\n");
	printf("\t   -p generate a black key from the plain text that is "
		"provided in previous argument\n");
	printf("import <blob_name> <key_name>\n");
	printf("\t<blob_name> the absolute path of the file that contains the blob\n");
	printf("\t<key_name> the name of the file that will contain the black key.\n");
	printf("derive  [-pass <pass_phrase>]  [-md <digest>] [-S <salt>]");
	printf(" <derived_key_name> \n");
	printf("\t<pass_phrase> password value\n");
	printf("\t<digest> Supported digest:-\n");
	printf("\t	   -> sha1\n");
	printf("\t	   -> sha224\n");
	printf("\t	   -> sha256\n");
	printf("\t	   -> sha384\n");
	printf("\t	   -> sha512\n");
	printf("\t	  Note:- Default algorithm is sha-256.\n");
	printf("\t<salt> [Optional] The actual salt to use.\n");
	printf("\t	8 bytes salt value needs to be provided.\n");
	printf("\t	If salt value > 8 bytes, trim to 8 bytes.\n");
	printf("\t	If salt_value < 8 bytes, zero padding is added.\n");
	printf("\t	If no salt is provided, -nosalt option will be used.\n");
	printf("\t<derived_key_name> Black key obtained after using");
	printf(" PBKDF2 derivation function\n");
}

static int convert_to_hex(const char* input, unsigned char* output, unsigned int size)
{
	unsigned int i = 0, n = 0;
	unsigned char high_nibble, low_nibble;

	i = size * 2;
	n = strlen(input);
	if (n > i) {
		printf("Hex string is too long, ignoring excess\n");
		n = i; /* Ignoring extra part */
	} else if (n < i) {
		printf("Hex string is too short, padding with zero bytes to length\n");
	}

	memset(output, 0, size);
	for (i = 0; i < n; i += 2) {
		high_nibble = (unsigned char)*input++; /*first character */
		low_nibble = (unsigned char)*input++; /*second character */
		/* Check if both characters are valid hexadecimal digits */
		if (!isxdigit(high_nibble) || !isxdigit(low_nibble)) {
			printf("Non-hex digit\n");
			return FAILURE;
		}
	/* Convert nibble to its integer value */
	high_nibble = (unsigned char)OPENSSL_hexchar2int(high_nibble);
	low_nibble = (unsigned char)OPENSSL_hexchar2int(low_nibble);
	output[i / 2] = (high_nibble << 4) | low_nibble;
    }
    return SUCCESS;
}

/**
* caam_keygen_derive_key - Derives key & IV using OPENSSL's API
* for password based key derivation (PKCS5_PBKDF2_HMAC_SHA1)
*
* @salt: salt provided by user or NULL (by default).
*
* @password: passphrase provided by user through command line.
*
* @key_path: Location where black key after derivation will reside.
*
* Function that take salt, password and keypath as input and print salt &
* IV and stores key in the form of black key inside /data/caam/<key_name>
*
*/

void caam_keygen_derive_key(unsigned char *salt, const char *password,
			    const EVP_MD *digest, char *key_path)
{
	unsigned char keyivpair[KEY_SIZE + IV_LEN], key[KEY_SIZE];
	unsigned char iv[IV_LEN];
	int salt_len = (salt != NULL ? SALT_SIZE : 0);

	if (PKCS5_PBKDF2_HMAC(password, -1, salt, salt_len, ITERATIONS,
				   digest, KEY_SIZE + IV_LEN, keyivpair)) {
		memcpy(key, keyivpair, KEY_SIZE);
		memcpy(iv, keyivpair + KEY_SIZE, IV_LEN);
		if (salt_len) {
			printf("salt=");
			for (int i = 0; i < salt_len; i++)
				printf("%02X", salt[i]);
			printf("\n");
		}
		caam_keygen_create(key_path, "ecb", "-t", key, "-p",
				   KEY_SIZE);
		printf("iv=");
		for (int i = 0; i < IV_LEN; i++)
			printf("%02X", iv[i]);
		printf("\n");
	} else {
		ERR_print_errors_fp(stderr);
	}

}

int caam_keygen_create(char *key_name, char *key_enc, char *key_mode,
		       char *key_value, char *text_type, int key_val_length)
{
	FILE *f_key, *f_blob;
	struct caam_keygen_cmd param;
	char *blob_name;
	int ret = -1;

	/*
	 * Blob file is generated in the same location as the key,
	 * in KEYBLOB_LOCATION.
	 *
	 * blob_name = KEYBLOB_LOCATION/key_name.bb
	 * Add 4 for blob name size, including null terminator
	 */
	blob_name = malloc(strlen(key_name) + strlen(KEYBLOB_LOCATION) + 4);
	if (!blob_name) {
		printf("Failed to allocate memory for blob name.\n");
		return ret;
	}
	/* blob_name = KEYBLOB_LOCATION/key_name.bb */
	strcpy(blob_name, KEYBLOB_LOCATION);
	strcpy(blob_name, key_name);
	strcat(blob_name, ".bb");

	param.key_enc = (uintptr_t)key_enc;
	/* add 1 for null terminator */
	param.key_enc_len = strlen(key_enc) + 1;

	param.key_mode = (uintptr_t)key_mode;
	/* add 1 for null terminator */
	param.key_mode_len = strlen(key_mode) + 1;
	param.key_value_len = key_val_length;
	if (!strcmp(text_type, "-p")) {
		param.key_value = (uintptr_t)key_value;
	} else {
		/*
		 * initialize the ASCII code string as half the length of
		 * hex input.
		 */
		uint8_t *ascii = malloc(sizeof(uint8_t) * (param.key_value_len / 2));

		memset(ascii, 0, sizeof(uint8_t) * (param.key_value_len / 2));
		int count = 0;

		if (!ascii) {
			printf("Failed to allocate memory for hex text\n");
			free(blob_name);
			return ret;
		}
		for (size_t i = 0; i < param.key_value_len; i += 2) {
			/* extract two characters from hex string */
			char part[3];

			part[0] = key_value[i];
			part[1] = key_value[i + 1];
			part[2] = '\0';

			/* change it into base 16 and typecast as the uint8_t */
			uint8_t ch = strtoul(part, NULL, 16);
			/*
			 * increment value of count in each iteration
			 * add character at the end of ascii string
			 */
			ascii[count++] = ch;
		}
		param.key_value = (uintptr_t)ascii;
		param.key_value_len = count;
	}
	param.black_key_len = MAX_BLACK_KEY_SIZE;
	param.black_key = (uintptr_t)malloc(param.black_key_len);
	if (!param.black_key) {
		printf("Failed to allocate memory for black key.\n");
		goto error_blob_name;
	}

	param.blob_len = MAX_BLOB_SIZE;
	param.blob = (uintptr_t)malloc(param.blob_len);
	if (!param.blob) {
		printf("Failed to allocate memory for blob.\n");
		goto error_param_black_key;
	}

	ret = ioctl(caam_keygen_fd, CAAM_KEYGEN_IOCTL_CREATE, &param);
	if (ret) {
		/* Print error message received from kernel space */
		printf("%s\n", (char *)(uintptr_t)param.blob);
		caam_keygen_usage();
		goto error_param_blob;
	}

	f_blob = fopen(blob_name, "wb");
	if (!f_blob) {
		printf("Failed to open blob file.\n");
		goto error_param_blob;
	}

	f_key = fopen(key_name, "wb");
	if (!f_key) {
		printf("Failed to open key file.\n");
		goto error_open_keyfile;
	}

	/* Write key and blob to files */
	if (fwrite((void *)(uintptr_t)param.black_key, 1, param.black_key_len,
		   f_key) != param.black_key_len) {
		printf("Failed to write black key to file.\n");
		goto error_write;
	}
	if (fwrite((void *)(uintptr_t)param.blob, 1, param.blob_len, f_blob) !=
	    param.blob_len) {
		printf("Failed to write blob to file.\n");
		goto error_write;
	}

	/* Free resources */
	free((void *)(uintptr_t)param.blob);
	free((void *)(uintptr_t)param.black_key);
	free(blob_name);

	/* Close files */
	fclose(f_key);
	fclose(f_blob);

	return 0;

error_write:
	fclose(f_key);

error_open_keyfile:
	fclose(f_blob);

error_param_blob:
	free((void *)(uintptr_t)param.blob);

error_param_black_key:
	free((void *)(uintptr_t)param.black_key);

error_blob_name:
	free(blob_name);

	return ret;
}

int caam_keygen_import(char *blob_name, char *key_name)
{
	FILE *f_key, *f_blob;
	struct stat blob_st;
	struct caam_keygen_cmd param;
	int ret = -1;
	size_t blob_file_size = 0;

	/* Validate arguments for import operation */
	if (!blob_name || !key_name) {
		printf("Invalid arguments for import operation.\n");
		return ret;
	}

	/* Get blob file size */
	if (stat(blob_name, &blob_st)) {
		printf("Failed to get blob file status.\n");
		return ret;
	}
	blob_file_size = blob_st.st_size;

	/* Check blob size */
	if (blob_file_size <= BLOB_OVERHEAD) {
		printf("Invalid blob - file too small.\n");
		return ret;
	}

	param.blob_len = blob_file_size;
	param.blob = (uintptr_t)malloc(param.blob_len);
	if (!param.blob) {
		printf("Failed to allocate memory for blob.\n");
		return ret;
	}

	f_blob = fopen(blob_name, "rb");
	if (!f_blob) {
		printf("Failed to open blob file or the file doesn't exist.\n");
		goto error_param_blob;
	}

	/* Read blob from file */
	if (fread((void *)(uintptr_t)param.blob, 1, blob_file_size, f_blob) !=
	    blob_file_size) {
		printf("Failed to read blob from file.\n");
		fclose(f_blob);
		goto error_param_blob;
	}

	/* Close blob size */
	fclose(f_blob);

	param.black_key_len = MAX_BLACK_KEY_SIZE;
	param.black_key = (uintptr_t)malloc(param.black_key_len);
	if (!param.black_key) {
		printf("Failed to allocate memory for black key.\n");
		goto error_param_blob;
	}

	ret = ioctl(caam_keygen_fd, CAAM_KEYGEN_IOCTL_IMPORT, &param);
	if (ret) {
		/* Print error message received from kernel space */
		printf("%s\n", (char *)(uintptr_t)param.black_key);
		caam_keygen_usage();
		goto error_param_black_key;
	}

	/* Open key file */
	f_key = fopen(key_name, "wb");
	if (!f_key) {
		printf("Failed to open key file.\n");
		goto error_param_black_key;
	}

	/* Write key to file */
	if (fwrite((void *)(uintptr_t)param.black_key, 1, param.black_key_len,
		   f_key) != param.black_key_len) {
		printf("Failed to write black key to file.\n");
		goto error_write;
	}

	/* Free resources */
	free((void *)(uintptr_t)param.black_key);
	free((void *)(uintptr_t)param.blob);

	/* Close key file */
	fclose(f_key);

	return 0;

error_write:
	fclose(f_key);

error_param_black_key:
	free((void *)(uintptr_t)param.black_key);

error_param_blob:
	free((void *)(uintptr_t)param.blob);

	return ret;
}

int caam_create_keyblob_path(const char *dir)
{
	char *cmd = NULL;

	/* + 3 for 2 quotes and null terminator */
	cmd = malloc(strlen(dir) +  strlen(MKDIR_COMMAND) + 3);
	if (!cmd) {
		printf("Failed to allocate memory for mkdir command.\n");
		return -1;
	}

	strcpy(cmd, MKDIR_COMMAND);
	/* Add quotes for special characters from directory path */
	strcat(cmd, QUOTES);
	strcat(cmd, dir);
	strcat(cmd, QUOTES);

	if (system(cmd) < 0) {
		printf("Unable to create key and blob location path %s\n", dir);
		free(cmd);
		return -1;
	}

	free(cmd);

	return 0;
}

int main(int argc, char *argv[])
{
	char *key_name = NULL;
	char *key_enc = NULL;
	char *key_mode = NULL;
	char *key_value = NULL;
	char *blob_name = NULL;
	char *key_path = NULL;
	char *text_type = NULL;
	const char *pass_phrase = NULL, *digest = NULL;
	EVP_MD *dgst = NULL;
	char *hsalt = NULL;
	unsigned char salt[SALT_SIZE];
	struct stat st = {0};
	int status = 0, ret = 0;

	const char *op = argc >= 2 ? argv[1] : NULL;

	if (argc < 2)
		goto out_usage;

	if (!strcmp(op, "create")) {
		if (argc < 6)
			goto out_usage;
		key_name = argv[2];
		key_enc = argv[3];
		key_mode = argv[4];
		key_value = argv[5];
		if (!argv[6])
			text_type = "-p";
		else
			text_type = argv[6];
	} else if (!strcmp(op, "import")) {
		if (argc < 4)
			goto out_usage;
		blob_name = argv[2];
		key_name = argv[3];
	} else if (!strcmp(op, "derive")) {
		if (argc < 7)
			goto out_usage;
		if (!strcmp(argv[2], "-pass"))
			pass_phrase = argv[3];
		 else
			goto out_usage;
		if (!strcmp(argv[4], "-md")) {
			digest = argv[5];
			if (!strcmp(digest, "sha1") ||
			    !strcmp(digest, "SHA1")) {
				dgst = (EVP_MD *)EVP_sha1();
			} else if (!strcmp(digest, "sha224") ||
				   !strcmp(digest, "SHA224")) {
				dgst = (EVP_MD *)EVP_sha224();
			} else if (!strcmp(digest, "sha256") ||
				   !strcmp(digest, "SHA256")) {
				dgst = (EVP_MD *)EVP_sha256();
			} else if (!strcmp(digest, "sha384") ||
				   !strcmp(digest, "SHA384")) {
				dgst = (EVP_MD *)EVP_sha384();
			} else if (!strcmp(digest, "sha512") ||
				   !strcmp(digest, "SHA512")) {
				dgst = (EVP_MD *)EVP_sha512();
			} else {
				printf("Using default digest (SHA256)\n");
				dgst = (EVP_MD *)EVP_sha256();
			}
		} else {
			goto out_usage;
		}
		if (!strcmp(argv[6], "-S")) {
			ret = convert_to_hex(argv[7], salt, sizeof(salt));
			if (ret != FAILURE) {
				key_name = argv[8];
				hsalt = salt;
			} else {
				goto out_usage;
			}
		} else {
			key_name = argv[6];
		}
	} else {
		goto out_usage;
	}

	caam_keygen_fd = open(DEVICE_NAME, O_RDWR);
	if (caam_keygen_fd < 0) {
		printf("Unable to open device %s\n", DEVICE_NAME);
		return -1;
	}

	/* Create the directory for key and blob files */
	status = caam_create_keyblob_path(KEYBLOB_LOCATION);
	if (status < 0)
		return -1;

	key_path = malloc(strlen(key_name) + strlen(KEYBLOB_LOCATION) + 1);
	if (!key_path) {
		printf("Failed to allocate memory for key path.\n");
		return -1;
	}
	strcpy(key_path, KEYBLOB_LOCATION);
	strcat(key_path, key_name);

	if (!strcmp(op, "create"))
		caam_keygen_create(key_path, key_enc, key_mode, key_value,
				   text_type, strlen(key_value));
	if (!strcmp(op, "import"))
		caam_keygen_import(blob_name, key_path);

	if (!strcmp(op, "derive"))
		caam_keygen_derive_key(hsalt, pass_phrase, dgst, key_path);
	close(caam_keygen_fd);
	free(key_path);

	goto out;

out_usage:
	caam_keygen_usage();

out:
	return 0;
}
