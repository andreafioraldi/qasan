/* Copyright 2013-2016 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <stdbool.h>
#include <types.h>
#include "container.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>
#include <sysexits.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#define PREFIX_HDR 0
#define SOFTWARE_HDR 1

char *progname;
int debug;

void usage(int status);

void getPublicKeyRaw(ecc_key_t *pubkeyraw, char *inFile)
{
	EVP_PKEY* pkey;
	EC_KEY *key;
	const EC_GROUP *ecgrp;
	const EC_POINT *ecpoint;
	BIGNUM *pubkeyBN;
	unsigned char pubkeyData[1 + 2*EC_COORDBYTES];

	FILE *fp = fopen( inFile, "r");
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	assert(pkey);

	key = EVP_PKEY_get1_EC_KEY(pkey);
	assert(key);
	ecgrp = EC_KEY_get0_group(key);
	assert(ecgrp);
	ecpoint = EC_KEY_get0_public_key(key);
	assert(ecpoint);
	pubkeyBN = EC_POINT_point2bn(ecgrp, ecpoint, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
	BN_bn2bin(pubkeyBN, pubkeyData);

	if (debug)
		printBytes((char *)"pubkey (RAW) = ", &pubkeyData[1], sizeof(pubkeyData) - 1, 32);

	memcpy(*pubkeyraw, &pubkeyData[1], sizeof(ecc_key_t));

	EC_KEY_free(key);
	EVP_PKEY_free(pkey);
	fclose(fp);

	return;
}

void getSigRaw(ecc_signature_t *sigraw, char *inFile)
{
	ECDSA_SIG* signature;
	int fdin;
	struct stat s;
	void *infile;
	unsigned char outbuf[2*EC_COORDBYTES];
	int r, rlen, roff, slen, soff;
	const BIGNUM *sr, *ss;

	fdin = open(inFile, O_RDONLY);
	assert(fdin > 0);
	r = fstat(fdin, &s);
	assert(r==0);

	infile = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	assert(infile);

	signature = d2i_ECDSA_SIG(NULL, (const unsigned char **) &infile, 7 + 2*EC_COORDBYTES);

	memset(&outbuf, 0, sizeof(outbuf));

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ECDSA_SIG_get0(signature, &sr, &ss);
#else
	sr = signature->r;
	ss = signature->s;
#endif
	rlen = BN_num_bytes(sr);
	roff = 66 - rlen;
	BN_bn2bin(sr, &outbuf[roff]);

	slen = BN_num_bytes(ss);
	soff = 66 + (66 - slen);
	BN_bn2bin(sr, &outbuf[soff]);

	if (debug)
		printBytes((char *)"sig (RAW)    = ", outbuf, sizeof(outbuf), 32);

	memcpy(*sigraw, outbuf, 2*EC_COORDBYTES);

	ECDSA_SIG_free(signature);
	close(fdin);

	return;
}

void writeHdr(void *hdr, const char *outFile, int hdr_type)
{
	int fdout;
	int r, hdr_sz=0;
	const char *lead;
	unsigned char md[SHA512_DIGEST_LENGTH];

	fdout = open(outFile, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	assert(fdout > 0);

	switch (hdr_type) {
	case PREFIX_HDR:
		hdr_sz = sizeof(ROM_prefix_header_raw);
		break;
	case SOFTWARE_HDR:
		hdr_sz = sizeof(ROM_sw_header_raw);
		break;
	}

	r = write(fdout, (const void *)hdr, hdr_sz);
	assert(r > 0);

	if (debug) {
		if (hdr_type == PREFIX_HDR)
			lead = "PR hdr hash  = ";
		else
			lead = "SW hdr hash  = ";

		SHA512(hdr, r, md);
		printBytes((char *)lead, md, sizeof(md), 32);
	}

	close(fdout);

	return;
}

void printBytes(char *lead, unsigned char *buffer, size_t buflen, int wrap)
{
	int i;
	int leadbytes = strlen(lead);
	leadbytes = leadbytes > 30 ? 30 : leadbytes;

	fprintf (stderr, "%s", lead);
	for (i = 1; i < buflen + 1; i++) {
		fprintf (stderr, "%02x", buffer[i - 1]);
		if (((i % wrap) == 0) && (i < buflen))
			fprintf (stderr, "\n%*c", leadbytes, ' ');
	}
	fprintf (stderr, "\n");
}

__attribute__((__noreturn__)) void usage (int status)
{
	if (status != 0) {
			fprintf(stderr, "Try '%s --help' for more information.\n", progname);
	}
	else {
		printf("Usage: %s [options]\n", progname);
		printf(
			"\n"
			"Options:\n"
			" -d, --debug             show additional debug info\n"
			" -h, --help              display this message and exit\n"
			" -a, --hw_key_a          file containing HW key A private key in PEM format\n"
			" -b, --hw_key_b          file containing HW key B private key in PEM format\n"
			" -c, --hw_key_c          file containing HW key C private key in PEM format\n"
			" -p, --sw_key_p          file containing SW key P private key in PEM format\n"
			" -q, --sw_key_q          file containing SW key Q private key in PEM format\n"
			" -r, --sw_key_r          file containing SW key R private key in PEM format\n"
			" -A, --hw_sig_a          file containing HW key A signature in DER format\n"
			" -B, --hw_sig_b          file containing HW key B signature in DER format\n"
			" -C, --hw_sig_c          file containing HW key C signature in DER format\n"
			" -P, --sw_sig_p          file containing SW key P signature in DER format\n"
			" -Q, --sw_sig_q          file containing SW key Q signature in DER format\n"
			" -R, --sw_sig_r          file containing SW key R signature in DER format\n"
			" -L, --payload           file containing the payload to be signed\n"
			" -I, --imagefile         file to write containerized payload (output)\n"
			"     --dumpPrefixHdr     file to dump Prefix header blob (to be signed)\n"
			"     --dumpSwHdr         file to dump Software header blob (to be signed)\n"
			"\n");
	};
	exit(status);
}

static struct option const opts[] = {
	{ "debug",            no_argument,       0,  'd' },
	{ "help",             no_argument,       0,  'h' },
	{ "hw_key_a",         required_argument, 0,  'a' },
	{ "hw_key_b",         required_argument, 0,  'b' },
	{ "hw_key_c",         required_argument, 0,  'c' },
	{ "sw_key_p",         required_argument, 0,  'p' },
	{ "sw_key_q",         required_argument, 0,  'q' },
	{ "sw_key_r",         required_argument, 0,  'r' },
	{ "hw_sig_a",         required_argument, 0,  'A' },
	{ "hw_sig_b",         required_argument, 0,  'B' },
	{ "hw_sig_c",         required_argument, 0,  'C' },
	{ "sw_sig_p",         required_argument, 0,  'P' },
	{ "sw_sig_q",         required_argument, 0,  'Q' },
	{ "sw_sig_r",         required_argument, 0,  'R' },
	{ "payload",          required_argument, 0,  'L' },
	{ "imagefile",        required_argument, 0,  'I' },
	{ "dumpPrefixHdr",    required_argument, 0,  128 },
	{ "dumpSwHdr",        required_argument, 0,  129 },
	{NULL, 0, 0, 0}
};

static struct {
	char *hw_keyfn_a;
	char *hw_keyfn_b;
	char *hw_keyfn_c;
	char *sw_keyfn_p;
	char *sw_keyfn_q;
	char *sw_keyfn_r;
	char *hw_sigfn_a;
	char *hw_sigfn_b;
	char *hw_sigfn_c;
	char *sw_sigfn_p;
	char *sw_sigfn_q;
	char *sw_sigfn_r;
	char *imagefn;
	char *payloadfn;
	char *prhdrfn;
	char *swhdrfn;
} params;


int main(int argc, char* argv[])
{
	int fdin, fdout;
	void *container = malloc(SECURE_BOOT_HEADERS_SIZE);
	struct stat s;
	char *buf = malloc(4096);
	off_t l;
	void *infile;
	int r;
	ROM_container_raw *c = (ROM_container_raw*)container;
	ROM_prefix_header_raw *ph;
	ROM_prefix_data_raw *pd;
	ROM_sw_header_raw *swh;
	ROM_sw_sig_raw *ssig;

	unsigned char md[SHA512_DIGEST_LENGTH];
	void *p;
	ecc_key_t pubkeyraw;
	ecc_signature_t sigraw;
	int indexptr;

	progname = strrchr (argv[0], '/');
	if (progname != NULL)
		++progname;
	else
		progname = argv[0];

	memset(container, 0, SECURE_BOOT_HEADERS_SIZE);

	while (1) {
		int opt;
		opt = getopt_long(argc, argv, "a:b:c:p:q:r:A:B:C:P:Q:R:L:I:dh", opts, &indexptr);
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
		case '?':
			usage(EX_OK);
			break;
		case 'd':
			debug = 1;
			break;
		case 'a':
			params.hw_keyfn_a = optarg;
			break;
		case 'b':
			params.hw_keyfn_b = optarg;
			break;
		case 'c':
			params.hw_keyfn_c = optarg;
			break;
		case 'p':
			params.sw_keyfn_p = optarg;
			break;
		case 'q':
			params.sw_keyfn_q = optarg;
			break;
		case 'r':
			params.sw_keyfn_r = optarg;
			break;
		case 'A':
			params.hw_sigfn_a = optarg;
			break;
		case 'B':
			params.hw_sigfn_b = optarg;
			break;
		case 'C':
			params.hw_sigfn_c = optarg;
			break;
		case 'P':
			params.sw_sigfn_p = optarg;
			break;
		case 'Q':
			params.sw_sigfn_q = optarg;
			break;
		case 'R':
			params.sw_sigfn_r = optarg;
			break;
		case 'L':
			params.payloadfn = optarg;
			break;
		case 'I':
			params.imagefn = optarg;
			break;
		case 128:
			params.prhdrfn = optarg;
			break;
		case 129:
			params.swhdrfn = optarg;
			break;
		default:
			usage(EX_USAGE);
		}
	}
//	}

	fdin = open(params.payloadfn, O_RDONLY);
	assert(fdin > 0);
	r = fstat(fdin, &s);
	assert(r==0);
	infile = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	assert(infile);
	fdout = open(params.imagefn, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	assert(fdout > 0);

	c->magic_number = cpu_to_be32(ROM_MAGIC_NUMBER);
	c->version = cpu_to_be16(1);
	c->container_size = cpu_to_be64(SECURE_BOOT_HEADERS_SIZE + s.st_size);
	c->target_hrmor = 0;
	c->stack_pointer = 0;
	memset(c->hw_pkey_a, 0, sizeof(ecc_key_t));
	memset(c->hw_pkey_b, 0, sizeof(ecc_key_t));
	memset(c->hw_pkey_c, 0, sizeof(ecc_key_t));
	if (params.hw_keyfn_a) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_a);
		memcpy(c->hw_pkey_a, pubkeyraw, sizeof(ecc_key_t));
	}
	if (params.hw_keyfn_b) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_b);
		memcpy(c->hw_pkey_b, pubkeyraw, sizeof(ecc_key_t));
	}
	if (params.hw_keyfn_c) {
		getPublicKeyRaw(&pubkeyraw, params.hw_keyfn_c);
		memcpy(c->hw_pkey_c, pubkeyraw, sizeof(ecc_key_t));
	}

	ph = container + sizeof(ROM_container_raw);
	ph->ver_alg.version = cpu_to_be16(1);
	ph->ver_alg.hash_alg = 1;
	ph->ver_alg.sig_alg = 1;
	ph->code_start_offset = 0;
	ph->reserved = 0;
	ph->flags = cpu_to_be32(0x80000000);
	memset(ph->payload_hash, 0, sizeof(sha2_hash_t));
	ph->ecid_count = 0;

	pd = (ROM_prefix_data_raw*)ph->ecid;
	memset(pd->hw_sig_a, 0, sizeof(ecc_signature_t));
	memset(pd->hw_sig_b, 0, sizeof(ecc_signature_t));
	memset(pd->hw_sig_c, 0, sizeof(ecc_signature_t));
	if (params.hw_sigfn_a) {
		getSigRaw(&sigraw, params.hw_sigfn_a);
		memcpy(pd->hw_sig_a, sigraw, sizeof(ecc_key_t));
	}
	if (params.hw_sigfn_b) {
		getSigRaw(&sigraw, params.hw_sigfn_b);
		memcpy(pd->hw_sig_b, sigraw, sizeof(ecc_key_t));
	}
	if (params.hw_sigfn_c) {
		getSigRaw(&sigraw, params.hw_sigfn_c);
		memcpy(pd->hw_sig_c, sigraw, sizeof(ecc_key_t));
	}
	memset(pd->sw_pkey_p, 0, sizeof(ecc_key_t));
	memset(pd->sw_pkey_q, 0, sizeof(ecc_key_t));
	memset(pd->sw_pkey_r, 0, sizeof(ecc_key_t));
	if (params.sw_keyfn_p) {
		getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_p);
		memcpy(pd->sw_pkey_p, pubkeyraw, sizeof(ecc_key_t));
		ph->sw_key_count++;
	}
	if (params.sw_keyfn_q) {
		getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_q);
		memcpy(pd->sw_pkey_q, pubkeyraw, sizeof(ecc_key_t));
		ph->sw_key_count++;
	}
	if (params.sw_keyfn_r) {
		getPublicKeyRaw(&pubkeyraw, params.sw_keyfn_r);
		memcpy(pd->sw_pkey_r, pubkeyraw, sizeof(ecc_key_t));
		ph->sw_key_count++;
	}
	ph->payload_size = cpu_to_be64(ph->sw_key_count * sizeof(ecc_key_t));
	p = SHA512(pd->sw_pkey_p, sizeof(ecc_key_t) * ph->sw_key_count, md);
	assert(p);
	memcpy(ph->payload_hash, md, sizeof(sha2_hash_t));

	if (params.prhdrfn)
		writeHdr((void *)ph, params.prhdrfn, PREFIX_HDR);

	swh = (ROM_sw_header_raw*)(((uint8_t*)pd) + sizeof(ecc_signature_t)*3 + be64_to_cpu(ph->payload_size));
	swh->ver_alg.version = cpu_to_be16(1);
	swh->ver_alg.hash_alg = 1;
	swh->ver_alg.sig_alg = 1;
	swh->code_start_offset = 0;
	swh->reserved = 0;
	swh->flags = 0;
	swh->reserved_0 = 0;
	swh->payload_size = cpu_to_be64(s.st_size);
	p = SHA512(infile, s.st_size, md);
	assert(p);
	memcpy(swh->payload_hash, md, sizeof(sha2_hash_t));

	if (params.swhdrfn)
		writeHdr((void *)swh, params.swhdrfn, SOFTWARE_HDR);

	ssig = (ROM_sw_sig_raw*)(((uint8_t*)swh) + sizeof(ROM_sw_header_raw));
	memset(ssig->sw_sig_p, 0, sizeof(ecc_signature_t));
	memset(ssig->sw_sig_q, 0, sizeof(ecc_signature_t));
	memset(ssig->sw_sig_r, 0, sizeof(ecc_signature_t));
	if (params.sw_sigfn_p) {
		getSigRaw(&sigraw, params.sw_sigfn_p);
		memcpy(ssig->sw_sig_p, sigraw, sizeof(ecc_key_t));
	}
	if (params.sw_sigfn_q) {
		getSigRaw(&sigraw, params.sw_sigfn_q);
		memcpy(ssig->sw_sig_q, sigraw, sizeof(ecc_key_t));
	}
	if (params.sw_sigfn_r) {
		getSigRaw(&sigraw, params.sw_sigfn_r);
		memcpy(ssig->sw_sig_r, sigraw, sizeof(ecc_key_t));
	}

	r = write(fdout, container, SECURE_BOOT_HEADERS_SIZE);
	assert(r == 4096);
	read(fdin, buf, s.st_size%4096);
	write(fdout, buf, s.st_size%4096);
	l = s.st_size - s.st_size%4096;
	while (l) {
		read(fdin, buf, 4096);
		write(fdout, buf, 4096);
		l-=4096;
	};
	close(fdin);
	close(fdout);

	free(container);
	free(buf);
	return 0;
}
