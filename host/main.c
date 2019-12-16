#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <basictee_ta.h>

#define AES_TEST_BUFFER_SIZE	10
#define AES_TEST_KEY_SIZE	16
#define AES_BLOCK_SIZE		16

#define DECODE			0
#define ENCODE			1


struct test_ctx {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_tee_session(struct test_ctx *ctx)
{
	TEEC_UUID uuid = TA_BASICTEE_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, origin);
}

void terminate_tee_session(struct test_ctx *ctx)
{
	TEEC_CloseSession(&ctx->sess);
	TEEC_FinalizeContext(&ctx->ctx);
}


/*
*	PRODUCE RANDOM data
*/
void produce_random_value(struct test_ctx *ctx, char random_uuid_value[])
{
	TEEC_Result res;
	TEEC_Operation op = { 0 };
	char random_uuid[16] = { 0 };
	// char random_uuid_value[16];
	uint32_t err_origin;
	int i;

	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = random_uuid;
	op.params[0].tmpref.size = sizeof(random_uuid);

	/*
	 * TA_EXAMPLE_RANDOM_GENERATE is the actual function in the TA to be
	 * called.
	 */
	printf("Invoking TA to generate random UUID... \n");
	res = TEEC_InvokeCommand(&ctx->sess, TA_RANDOM_CMD_GENERATE, &op, &err_origin);

	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	printf("TA generated UUID value = 0x");
	for (i = 0; i < 16; i++)
	{
		printf("%x", random_uuid[i]);
		random_uuid_value[i] = random_uuid[i];
	}
	
	printf("\n");
}



/*
*	READ-WRITE-DELETE data
*/

TEEC_Result read_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_READ_RAW,
				 &op, &origin);
	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_SHORT_BUFFER:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command READ_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result write_secure_object(struct test_ctx *ctx, char *id,
			char *data, size_t data_len)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	op.params[1].tmpref.buffer = data;
	op.params[1].tmpref.size = data_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_WRITE_RAW,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);

	switch (res) {
	case TEEC_SUCCESS:
		break;
	default:
		printf("Command WRITE_RAW failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

TEEC_Result delete_secure_object(struct test_ctx *ctx, char *id)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
	size_t id_len = strlen(id);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = id;
	op.params[0].tmpref.size = id_len;

	res = TEEC_InvokeCommand(&ctx->sess,
				 TA_SECURE_STORAGE_CMD_DELETE,
				 &op, &origin);

	switch (res) {
	case TEEC_SUCCESS:
	case TEEC_ERROR_ITEM_NOT_FOUND:
		break;
	default:
		printf("Command DELETE failed: 0x%x / %u\n", res, origin);
	}

	return res;
}

#define TEST_OBJECT_SIZE	10


/*
*	ENCRYPT-DECRYPT data
*/

void prepare_aes(struct test_ctx *ctx, int encode)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_VALUE_INPUT,
					 TEEC_NONE);

	op.params[0].value.a = TA_AES_ALGO_CTR;
	op.params[1].value.a = TA_AES_SIZE_128BIT;
	op.params[2].value.a = encode ? TA_AES_MODE_ENCODE :
					TA_AES_MODE_DECODE;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x",
			res, origin);
}

void set_key(struct test_ctx *ctx, char *key, size_t key_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = key;
	op.params[0].tmpref.size = key_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x",
			res, origin);
}

void set_iv(struct test_ctx *ctx, char *iv, size_t iv_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = iv;
	op.params[0].tmpref.size = iv_sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_IV,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(SET_IV) failed 0x%x origin 0x%x",
			res, origin);
}

void cipher_buffer(struct test_ctx *ctx, char *in, char *out, size_t sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = in;
	op.params[0].tmpref.size = sz;
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sz;

	res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_CIPHER,
				 &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand(CIPHER) failed 0x%x origin 0x%x",
			res, origin);
}

int main( int argc, char *argv[] )
{
	struct test_ctx ctx;

	if(argc == 1)
	{
		printf(" Missing arguments! ");
		return 0;
	}
	else
	{

		printf("Prepare session with the TA\n");
		prepare_tee_session(&ctx);

		TEEC_Result res;

		if( strcmp(argv[1], "store") == 0 )
		{
			// STORE
			res = write_secure_object(&ctx, argv[2], argv[3], sizeof(argv[3]));
			if (res != TEEC_SUCCESS)
				errx(1, "Failed to create/load an object");

		}
		else if( strcmp(argv[1], "load") == 0 )
		{
			// LOAD
			char obj1_data[TEST_OBJECT_SIZE];
			res = read_secure_object(&ctx, argv[2], obj1_data, sizeof(obj1_data));
			if (res != TEEC_SUCCESS && res != TEEC_ERROR_ITEM_NOT_FOUND)
					errx(1, "Unexpected status when reading an object : 0x%x", res);
			if (res == TEEC_ERROR_ITEM_NOT_FOUND) 
			{
				char data[] = "This is data stored in the secure storage.\n";
				printf("- Object not found in TA secure storage, create it.\n");

			} 
			else
				printf( " %s \n", obj1_data );

		}
		else if( strcmp(argv[1], "encrypt") == 0 )
		{
			char iv[TEST_OBJECT_SIZE];
			char ciph[TEST_OBJECT_SIZE];

			prepare_aes(&ctx, ENCODE);
			set_key(&ctx, argv[2], AES_TEST_KEY_SIZE );
			memset(iv, 0, sizeof(iv)); /* Load some dummy value */
			set_iv(&ctx, iv, AES_BLOCK_SIZE);
			cipher_buffer(&ctx, argv[3], ciph, AES_TEST_BUFFER_SIZE);

			printf(" Cipher is: %s \n", ciph);
		}
		else if( strcmp(argv[1], "decrypt") == 0 )
		{
			char iv[TEST_OBJECT_SIZE];
			char temp[TEST_OBJECT_SIZE];
			
			prepare_aes(&ctx, DECODE);
			set_key(&ctx, argv[2], AES_TEST_KEY_SIZE );
			memset(iv, 0, sizeof(iv)); /* Load some dummy value */
			set_iv(&ctx, iv, AES_BLOCK_SIZE);
			cipher_buffer(&ctx, argv[3], temp, AES_TEST_BUFFER_SIZE);
			
			printf(" Text is: %s \n", temp);
		}
		
		terminate_tee_session(&ctx);
	}
	
	
	// ------------------------------------------------------------------------

	return 0;
}