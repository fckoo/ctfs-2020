#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

unsigned char __private_key_raw[] = {
	0x30, 0x82, 0x02, 0x5c, 0x02, 0x01, 0x00, 0x02, 0x81, 0x81, 0x00, 0xae,
	0x68, 0x61, 0xd4, 0x73, 0xa6, 0x33, 0x31, 0x33, 0xc2, 0x1a, 0x5e, 0xbe,
	0xf5, 0xec, 0x90, 0xea, 0x85, 0x77, 0xea, 0xc2, 0xdb, 0x62, 0x73, 0xb5,
	0x29, 0x5d, 0xc2, 0xbb, 0x3a, 0x3c, 0xd1, 0x50, 0xbb, 0xd4, 0xd4, 0x9e,
	0xee, 0x33, 0xdd, 0x3b, 0x30, 0x45, 0x3c, 0xeb, 0xbe, 0xf1, 0x1f, 0x67,
	0xe4, 0x05, 0x5c, 0x8b, 0x9c, 0x6f, 0x3a, 0x56, 0xba, 0xe2, 0xba, 0xec,
	0x9a, 0xa7, 0xd0, 0x43, 0xed, 0xbc, 0x27, 0x50, 0x46, 0xc8, 0x40, 0x92,
	0x2e, 0x87, 0xb6, 0x24, 0xe3, 0xf4, 0xc3, 0x1b, 0xd6, 0xbd, 0xad, 0x55,
	0xa4, 0x51, 0x64, 0x23, 0x10, 0xd1, 0x6c, 0x14, 0xfd, 0x35, 0xa8, 0x18,
	0xa1, 0x9f, 0xab, 0x33, 0x14, 0xf9, 0x3e, 0x50, 0x34, 0xc4, 0x3c, 0x28,
	0xb6, 0x10, 0xd2, 0xfc, 0x90, 0x9b, 0x97, 0x60, 0xd5, 0x9a, 0x13, 0xe5,
	0x3e, 0xbf, 0x38, 0xd0, 0x52, 0x66, 0x7d, 0x02, 0x03, 0x01, 0x00, 0x01,
	0x02, 0x81, 0x80, 0x03, 0x7e, 0x81, 0xdf, 0x40, 0xc5, 0xe6, 0xa6, 0xa8,
	0xb3, 0xcd, 0xd5, 0x72, 0x1b, 0xf9, 0x36, 0x5a, 0x0c, 0x7c, 0x7f, 0x8e,
	0x91, 0xd8, 0xa2, 0x1a, 0xd2, 0x0e, 0x57, 0xd5, 0x6a, 0x70, 0x47, 0x7d,
	0x47, 0x96, 0x17, 0x00, 0x6c, 0x23, 0x4b, 0xde, 0x60, 0xb4, 0x32, 0x69,
	0x42, 0xb5, 0x0f, 0xfd, 0x03, 0xdb, 0x7b, 0xa4, 0x2c, 0x69, 0x2a, 0x11,
	0x0c, 0xc3, 0x78, 0x1d, 0x3f, 0x67, 0xf7, 0x42, 0xbc, 0xba, 0x38, 0xae,
	0xcc, 0x26, 0xdb, 0xca, 0x81, 0x1e, 0x49, 0xfd, 0xfa, 0x06, 0xbd, 0x32,
	0x83, 0x3b, 0x9e, 0x66, 0x1e, 0x9b, 0x8b, 0x4f, 0xf5, 0x04, 0x5e, 0x81,
	0xda, 0x69, 0xdb, 0x91, 0x7e, 0x0f, 0x96, 0x69, 0xa1, 0x51, 0x93, 0xb3,
	0x50, 0xf4, 0x84, 0x10, 0xd8, 0x49, 0x24, 0xc6, 0xb0, 0x51, 0x2b, 0xbc,
	0x7a, 0xe0, 0x26, 0xdf, 0x42, 0xef, 0xbb, 0x9b, 0x57, 0xe2, 0xdd, 0x02,
	0x41, 0x00, 0xd9, 0x8b, 0x83, 0xa9, 0xf6, 0xbd, 0x94, 0xcc, 0xef, 0x93,
	0x34, 0x5a, 0x35, 0xee, 0x8b, 0xb3, 0x4e, 0x32, 0x41, 0x7c, 0xc6, 0x9c,
	0x2a, 0x5e, 0xf0, 0x97, 0xc2, 0x45, 0x3d, 0x8f, 0x68, 0x1e, 0x34, 0xb7,
	0xb0, 0x5f, 0xaf, 0x5e, 0x9e, 0xfd, 0x41, 0xb8, 0xee, 0x5c, 0x8b, 0x5a,
	0xca, 0x4e, 0xb7, 0x51, 0x7a, 0xde, 0x57, 0x21, 0x37, 0xaa, 0x40, 0x9e,
	0x23, 0x0a, 0x51, 0x1d, 0xed, 0x6b, 0x02, 0x41, 0x00, 0xcd, 0x3c, 0xcb,
	0x39, 0x7e, 0xce, 0xdf, 0x9f, 0xd2, 0xc8, 0x67, 0x9d, 0x64, 0x86, 0x22,
	0xd3, 0xe5, 0xbc, 0x3f, 0x0a, 0x33, 0x32, 0xb8, 0xe0, 0x3f, 0xdc, 0xa0,
	0x7f, 0xe6, 0xa6, 0xfc, 0x87, 0xdf, 0x4e, 0x86, 0x80, 0x81, 0x3a, 0xe4,
	0xe0, 0x5e, 0xe1, 0x41, 0x1a, 0xd0, 0xf4, 0xb8, 0xc2, 0x4e, 0x00, 0x91,
	0x9a, 0x1a, 0xf0, 0x1e, 0x38, 0x9f, 0xca, 0x55, 0xe2, 0xa3, 0x2d, 0xcd,
	0xb7, 0x02, 0x41, 0x00, 0x81, 0x29, 0x7b, 0x77, 0xeb, 0x5e, 0xae, 0x3d,
	0x6b, 0x35, 0x0c, 0x4d, 0x4f, 0x5e, 0x1d, 0xa5, 0xcd, 0x14, 0xbb, 0x9b,
	0x18, 0xd4, 0xd9, 0xb7, 0x5a, 0xc3, 0xcf, 0xfd, 0x8a, 0x4a, 0x5d, 0xf8,
	0x29, 0x36, 0xb2, 0xca, 0x6c, 0xf6, 0x12, 0x11, 0xad, 0xf6, 0xdd, 0xd7,
	0x26, 0x8a, 0x36, 0x39, 0xbc, 0x4f, 0xed, 0x52, 0x9b, 0x8a, 0xc6, 0x61,
	0x18, 0x52, 0x8b, 0xdd, 0x71, 0x42, 0x02, 0x97, 0x02, 0x40, 0x12, 0xad,
	0x51, 0xa1, 0x2d, 0xd5, 0x0d, 0xac, 0xb1, 0xb5, 0xe3, 0x18, 0x03, 0xa9,
	0xe1, 0x49, 0x7f, 0x42, 0x9e, 0x4a, 0x03, 0x56, 0xbe, 0x54, 0x49, 0xfb,
	0x7d, 0xef, 0xa5, 0xc1, 0xd4, 0x81, 0x58, 0xe5, 0x00, 0x80, 0x79, 0x42,
	0x2e, 0xc9, 0xec, 0x58, 0x7b, 0x60, 0x41, 0x5b, 0xc3, 0xe4, 0x8a, 0xcc,
	0xaa, 0x73, 0x67, 0xb8, 0x2a, 0x47, 0xe4, 0xe2, 0xb8, 0xe6, 0x23, 0x0b,
	0x6c, 0x09, 0x02, 0x40, 0x3e, 0x76, 0x64, 0x63, 0xd4, 0x83, 0xb0, 0x0e,
	0x62, 0x46, 0xb8, 0x1f, 0x0d, 0xe3, 0x30, 0x3e, 0xe9, 0x16, 0x40, 0x79,
	0x8f, 0x8a, 0x77, 0x30, 0x66, 0xae, 0x25, 0xe6, 0xc3, 0x3b, 0x75, 0x7e,
	0xab, 0x7e, 0xff, 0x4a, 0x09, 0xe0, 0x38, 0xec, 0xb6, 0x5d, 0xeb, 0xb3,
	0x85, 0x59, 0xc0, 0x6d, 0x55, 0x4e, 0xa8, 0x05, 0xc3, 0x71, 0xef, 0x60,
	0x18, 0xdb, 0x2b, 0x6d, 0xcc, 0x1e, 0x92, 0xfc
};
unsigned int __private_key_raw_len = 608;


const unsigned char __encrypted_data[] = { 0x6f,0x86,0xe4,0x96,0x29,0xbe,0x8a,0x5e, 0x21,0xe2,0xc0,0xda,0x25,0xb7,0x95,0xe0, 0x5f,0x0a,0x6c,0xe9,0x44,0xdb,0x12,0x4c, 0x3a,0x6c,0x14,0x87,0xc6,0x36,0x6b,0x6d, 0x95,0x06,0x1c,0x2d,0x11,0x9e,0xf8,0x72, 0xcc,0x9b,0x74,0x87,0x73,0xa7,0x52,0x72, 0x0c,0x5b,0x92,0x8d,0x7c,0xa9,0x35,0xeb, 0xc5,0xd6,0x1e,0x1c,0x9e,0x7e,0xd3,0x6e, 0x43,0x35,0x93,0xd0,0x6c,0x26,0xb4,0x95, 0xe5,0x99,0x28,0x63,0x5e,0xeb,0xad,0x40, 0xce,0x26,0x67,0xf7,0x32,0xb2,0x03,0x0d, 0x30,0x24,0x93,0x84,0x3a,0x19,0xac,0x6f, 0x11,0xbb,0x0b,0x5b,0x41,0x8d,0x9d,0x49, 0x1a,0xb1,0x21,0xd9,0x79,0x43,0xbc,0x83, 0x1c,0x36,0x98,0xb9,0x5a,0x53,0xd9,0xf4, 0xa3,0x99,0x34,0x67,0xa2,0x8b,0xce,0x06, };

int main()
{
	char decrypted[4096] = {};
	BIO *bio_struct = BIO_new_mem_buf(__private_key_raw, __private_key_raw_len);
	if (bio_struct == NULL)
		return -1;

	EVP_PKEY *evp_struct = NULL;
	d2i_PrivateKey_bio(bio_struct, &evp_struct);
	if (evp_struct == NULL)
		return -1;

	RSA *keypair = EVP_PKEY_get1_RSA(evp_struct);
	if (keypair == NULL)
		return -1;

	printf("[+] Decrypting data...\n");
	if (RSA_public_decrypt(RSA_size(keypair), __encrypted_data, decrypted, keypair, 1) == -1)
		exit(-1);

	printf("[FLAG IS] %s\n", decrypted);

	return 0;
}
