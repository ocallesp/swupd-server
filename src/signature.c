/*
 *   Software Updater - server side
 *
 *      Copyright © 2012-2016 Intel Corporation.
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, version 2 or later of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *   Authors:
 *         Tom Keel <thomas.keel@intel.com>
 *
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "swupd.h"


bool signature_initialize(void);
void signature_terminate(void);
bool signature_sign(const char *);
static char * get_signature_filename(const char *);
static void create_signature(FILE *);
static char *make_filename(const char *, const char *, const char *);

static FILE *fp_privkey = NULL;
static FILE *fp_sig = NULL;
static EVP_PKEY *pkey = NULL;
static char *passphrase = NULL;
static char *leaf_key = NULL;
static bool initialized = false;



/*
 * Initialize this module.
 * @return true <=> success
 */
bool signature_initialize(void)
{
	if (!enable_signing) {
		return true;
	}

	char *cdir;
	char *pphr;
	struct stat s;

	if (initialized) {
		return true;
	}
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

	cdir = getenv("SWUPD_CERTS_DIR");
	if (cdir == NULL || cdir[0] == '\0') {
		printf("No certificates directory specified\n");
		goto err;
	}
	if (stat(cdir, &s)) {
		printf("Can't stat certificates directory '%s' (%s)\n", cdir,
		       strerror(errno));
		goto err;
	}
	leaf_key = make_filename(cdir, "LEAF_KEY", "leaf key");
	if (leaf_key == NULL) {
		goto err;
	}
	pphr = getenv("PASSPHRASE");
	if (pphr == NULL || (passphrase = strdup(pphr)) == NULL) {
		goto err;
	}
	if (stat(passphrase, &s)) {
		printf("Can't stat '%s' (%s)\n", passphrase,
		       strerror(errno));
		goto err;
	}

    /* Read private key */
    fp_privkey = fopen(leaf_key, "r");
    if (!fp_privkey) {
        fprintf(stderr, "Failed fopen %s\n",leaf_key);
        exit(1);
    }
    pkey = PEM_read_PrivateKey(fp_privkey, NULL, NULL, (void *)passphrase);
    if (!pkey) {
        ERR_print_errors_fp(stderr);
         exit(1);
    }

	initialized = true;
	return true;
err:
	signature_terminate();
	return false;
}


/* Make filename from dir name and env variable containing basename */
static char *make_filename(const char *dir, const char *env, const char *desc)
{
    char *fn = getenv(env);
    char *result = NULL;
    struct stat s;

    if (fn == NULL || fn[0] == '\0') {
        printf("No %s file specified\n", desc);
        return NULL;
    }
    string_or_die(&result, "%s/%s", dir, fn);
    if (stat(result, &s)) {
        printf("Can't stat %s '%s' (%s)\n", desc, result, strerror(errno));
        free(result);
        return NULL;
    }
    return result;
}

/*
 * Terminate this module, free resources.
 */
void signature_terminate(void)
{
	if (!enable_signing) {
		return false;
	}

	free(leaf_key);
	free(passphrase);

    fclose(fp_privkey);
    fclose(fp_sig);

    fp_privkey = NULL;
    fp_sig = NULL;
	leaf_key = NULL;
	passphrase = NULL;

    /* frees up the private key */
    EVP_PKEY_free(pkey);
    /* removes all ciphers and digests from the table */
    EVP_cleanup();

    initialized = false;
    return true;
}

/*
 * Write the signature file corresponding to the given data file.
 * The name of the signature file is the name of the data file with suffix
 * ".signed" appended.
 */
bool signature_sign(const char *filename)
{

	if (!enable_signing) {
		return true;
	}

	if (!initialized) {
		return false;
	}

   	FILE *fp_data = NULL;


   	char *signature_filename = get_signature_filename(filename);
   	printf("signature file: %s\n", signature_filename);


   	/* read data from file */
   	fp_data = fopen(filename, "r");
   	if (!fp_data) {
       	fprintf(stderr, "Failed fopen %s\n", filename);
       	exit(1);
   	}

   	fp_sig = fopen(signature_filename, "w");
   	if (!fp_sig) {
       	fprintf(stderr, "Failed fopen %s\n", signature_filename);
       	exit(1);
   	}

   	create_signature(fp_data);

   	free(signature_filename);
   	fclose(fp_data);

    return true;
}

static char * get_signature_filename(const char *filename)
{
    char *signature_filename = NULL;
    size_t len = 0;

    len = strlen(filename);
    signature_filename = (char *)malloc(len + 8);
    sprintf(signature_filename,"%s.signed", filename);

    return signature_filename;
}



#define BUFFER_SIZE   4096
static void create_signature(FILE *fp_data)
{
    char buffer[BUFFER_SIZE];
    unsigned char sig_buffer[4096];
    unsigned int sig_len;
    EVP_MD_CTX md_ctx;

    /* get size of file */
    fseek(fp_data, 0, SEEK_END);
    size_t data_size = ftell(fp_data);
    fseek(fp_data, 0, SEEK_SET);

    if (!EVP_SignInit(&md_ctx, EVP_sha256())) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    /* read all bytes from file to calculate digest using sha256 and then sign it */
    size_t len = 0;
    size_t bytes_left = data_size;
    while (bytes_left > 0) {
        const size_t count = (bytes_left > BUFFER_SIZE ? BUFFER_SIZE : bytes_left);
        len = fread(buffer, 1, count, fp_data);
        if (len != count) {
            fprintf(stderr, "Failed len!= count\n");
            exit(1);
        }

        if (!EVP_SignUpdate(&md_ctx, buffer, len)) {
            ERR_print_errors_fp(stderr);
            exit(1);
        }
        bytes_left -= len;
    }

    /* Do the signature */
    if (!EVP_SignFinal(&md_ctx, sig_buffer, &sig_len, pkey)) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    size_t sig_len_tmp = fwrite(sig_buffer, 1, sig_len, fp_sig);
    if (sig_len_tmp != sig_len) {
        fprintf(stderr, "Failed fwrite sign file\n");
        exit(1);
    }

}
