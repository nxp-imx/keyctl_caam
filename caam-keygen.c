// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2020, 2021 NXP
 */

#include "caam-keygen.h"
#include "caam-keygen_priv.h"

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
}

int caam_keygen_create(char *key_name, char *key_enc, char *key_mode,
		       char *key_value, char *text_type)
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
	param.key_value_len = strlen(key_value);

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
	struct stat st = {0};
	int status;

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
				   text_type);
	if (!strcmp(op, "import"))
		caam_keygen_import(blob_name, key_path);

	close(caam_keygen_fd);
	free(key_path);

	goto out;

out_usage:
	caam_keygen_usage();

out:
	return 0;
}
