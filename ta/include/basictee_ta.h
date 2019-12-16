#ifndef TA_BASICTEE_H
#define TA_BASICTEE_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_BASICTEE_UUID \
	{ 0x0e8033f8, 0x6878, 0x41c6, \ 
		{ 0x80, 0x27, 0xe8, 0xf7, 0x4e, 0x9b, 0x41, 0x08} }


/* --------------------------------------------------- */
#define TA_RANDOM_CMD_GENERATE		0		
/* --------------------------------------------------- */
#define TA_SECURE_STORAGE_CMD_READ_RAW		1

#define TA_SECURE_STORAGE_CMD_WRITE_RAW		2

#define TA_SECURE_STORAGE_CMD_DELETE		3
/* --------------------------------------------------- */
#define TA_AES_CMD_PREPARE		4

#define TA_AES_ALGO_ECB			0
#define TA_AES_ALGO_CBC			1
#define TA_AES_ALGO_CTR			2

#define TA_AES_SIZE_128BIT		(128 / 8)
#define TA_AES_SIZE_256BIT		(256 / 8)

#define TA_AES_MODE_ENCODE		1
#define TA_AES_MODE_DECODE		0

#define TA_AES_CMD_SET_KEY		5

#define TA_AES_CMD_SET_IV		6

#define TA_AES_CMD_CIPHER		7		
/* ----------------------------------------------- */

#endif /*TA_BASICTEE_H*/