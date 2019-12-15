#ifndef TA_BASICTEE_H
#define TA_BASICTEE_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_BASICTEE_UUID \
	{ 0xfd30d1f0, 0x057a, 0x4a33, \ 
		{ 0xb3, 0x53, 0xfa, 0x47, 0xd2, 0xa4, 0xf6, 0x40} }


/* --------------------------------------------------- */
#define TA_AES_CMD_PREPARE		0

#define TA_AES_ALGO_ECB			0
#define TA_AES_ALGO_CBC			1
#define TA_AES_ALGO_CTR			2

#define TA_AES_SIZE_128BIT		(128 / 8)
#define TA_AES_SIZE_256BIT		(256 / 8)

#define TA_AES_MODE_ENCODE		1
#define TA_AES_MODE_DECODE		0

#define TA_AES_CMD_SET_KEY		1

#define TA_AES_CMD_SET_IV		2

#define TA_AES_CMD_CIPHER		3		
/* ----------------------------------------------- */

#define TA_SECURE_STORAGE_CMD_READ_RAW		4

#define TA_SECURE_STORAGE_CMD_WRITE_RAW		5

#define TA_SECURE_STORAGE_CMD_DELETE		6

#endif /*TA_BASICTEE_H*/