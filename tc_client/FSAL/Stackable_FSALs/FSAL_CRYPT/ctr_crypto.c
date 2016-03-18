/**
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * @file  ctr_crypto.c
 * @brief Encrypt and decrypt data
 */

#include "ctr_crypto.h"
#include <rpc/des_crypt.h>

/** Number of of 8-byte units in block */
#define BLOCK_SIZE_UINT64	(BLOCK_SIZE_BYTES/sizeof(uint64_t))

/** Block number that an offset belongs to */
#define BLOCK_ALIGN_MASK	(0xffffffffffffffff << BLOCK_SIZE_LOG2)
#define BLOCK_COUNT(a)		((a) >> BLOCK_SIZE_LOG2)

/** Offset within a block */
#define BLOCK_OFFSET_MASK	(~BLOCK_ALIGN_MASK)
#define BLOCK_OFFSET(a)		((a) & BLOCK_OFFSET_MASK)

/**
 * 8-byte key
 * 
 * Generated using kernel random number generator in shell:
 * od -vAn -N8 -tx8 -w8 < /dev/urandom
 */
uint64_t g_key = 0x5bd86c166d7ea8c3;

/**
 * 64-byte nonce
 *
 * Generated using kernel random number generator in shell:
 * od -vAn -N64 -tx8 -w16 < /dev/urandom
 */
uint64_t g_nonce[BLOCK_SIZE_UINT64] =  {
	0x92f4358a2ec66502, 0x1997a4a44d0de805,
	0x860ffa6d8628ba6d, 0x5622c0666a4a0091,
	0xe68313f0731f13aa, 0x8c9ae8f4227d26fe,
	0x87ba65fd1a797c78, 0x21a8e54e023f1119 
};

/**
 * @brief Generate counter block
 *
 * Generate counter block by combining nonce with count.
 * Counter block is updated in nonce.
 * Note: Size of block is BLOCK_SIZE_BYTES.
 *
 * @param[in, out] nonce Nonce of size BLOCK_SIZE_BYTES. Output counter block.
 * @param[in]      count Count of block of size BLOCK_SIZE_BYTES
 */
static void counter_block(uint64_t *nonce, uint64_t count) {

	if(nonce == NULL)
		return;

	uint64_t *bytes8 = nonce;
	int i;

	for(i = 0; i < BLOCK_SIZE_UINT64; i ++) {
		(*bytes8) ^= count;
		bytes8 ++;
	}

	// TODO: Counter block is unique for count if initialization vector is
	// constant. Performance can be improved by storing results rather than
	// computing each time.
}

/**
 * @brief Perform DES encryption of a block message
 *
 * Block is of size BLOCK_SIZE_BYTES
 *
 * @param[in]      key  8-byte key for DES encryption
 * @param[in, out] data Message of size BLOCK_SIZE_BYTES to be encrypted.
 *                      Output encrypted message.
 *
 * @retval CRYPTFS_CRYPTO_NO_ERR No error, encryption successful
 * @retval CRYPTFS_CRYPTO_ERROR  Error occurred during encryption.
 */
static int des_crypt_block_msg(char *key, uint64_t *data) {

	if(key == NULL || data == NULL)
		return CRYPTFS_CRYPTO_ERROR;

	int ret = CRYPTFS_CRYPTO_NO_ERR;
	int i;

	char *bytes8 = (char*)data;

	if(DES_FAILED(ecb_crypt(key, bytes8, BLOCK_SIZE_BYTES, DES_ENCRYPT))) {
		ret = CRYPTFS_CRYPTO_ERROR;
	}

	return ret;
}

/**
 * @brief XOR plaintext with encrypted message block
 *
 * XOR operation is done as follows (2 cases):
 * (1) All of plaintext data is XORed:
 *
 * <- BLOCK_SIZE_BYTES ->
 * +--------------------+
 * |           |     |  | msg
 * +-----------+-----+--+
 * <- offset ->| XOR |
 *             +-----+
 *             |/////| ciphertext data
 *             +-----+
 *             <----->
 *             datalen
 *
 * XORed bytes(size of ciphertext): datalen
 *
 * (2) Part of plaintext data is XORed:
 *
 * <- BLOCK_SIZE_BYTES ->
 * +--------------------+
 * |           |        | msg
 * +-----------+--------+
 * <- offset ->|  XOR   |
 *             +--------+-----------+
 *             |////////|           |
 *             +--------+-----------+
 *             <-------->
 *             ciphertext
 *
 *             <----- datalen ------>
 *
 * XORed bytes (size of ciphertext): (BLOCK_SIZE_BYTES - offset)
 *
 * @param[in, out] data    Plaintext data input. Ciphertext data output
 * @param[in]      msg     Message for XORing with plaintext
 * @param[in]      offset  Offset of plaintext
 * @param[in]      datalen Length of plaintext data
 *
 * @return Number of bytes XORed (size of ciphertext output)
 */
static int plaintext_xor_enc_msg(char *data, char *msg, uint64_t offset, uint64_t datalen) {

	if(data == NULL || msg == NULL)
		return 0;

	unsigned i;
	char *byte_d = data;
	char *byte_m = msg + BLOCK_OFFSET(offset);
	int byte_count, remain_bytes;
	byte_count = remain_bytes = MIN(datalen, (BLOCK_SIZE_BYTES - BLOCK_OFFSET(offset)));

	for(; remain_bytes >= sizeof(uint64_t); remain_bytes -= sizeof(uint64_t)) {

		(*(uint64_t*)byte_d) ^= (*(uint64_t*)byte_m);
		byte_d += sizeof(uint64_t);
		byte_m += sizeof(uint64_t);
	}

	for(; remain_bytes > 0; remain_bytes --) {

		(*byte_d) ^= (*byte_m);
		byte_d ++;
		byte_m ++;
	}

	return byte_count;
}

/**
 * @brief Initialize counter block with nonce (initialization vector)
 *
 * g_nonce is the nonce (initialization vector) and is of size BLOCK_SIZE_BYTES.
 *
 * @param[out] msg Initialization vector is output here.
 */
static void initialize_block_msg(char *msg) {

	if(msg == NULL)
		return;

	memcpy((void*)msg, (void*)g_nonce, BLOCK_SIZE_BYTES);
}

/**
 * @brief Do encryption in counter (CTR) mode
 *
 * Perform encryption of 'data' of length 'datalen' assuming it is at an
 * 'offset' using 'key' and initialization vector obtained from
 * initialize_block_msg()
 *
 * @param[in]      key     Key used for encryption
 * @param[in, out] data    Input plaintext. Ouput ciphertext.
 * @param[in]      datalen Length of plaintext
 * @param[in]      offset  Offset of data in file
 *
 * @retval CRYPTFS_CRYPTO_NO_ERR No error, encryption successful
 * @retval CRYPTFS_CRYPTO_ERROR  Error occurred during encryption.
 */
static int ctr_crypt(char *key, char *data, uint64_t datalen, uint64_t offset) {
	uint64_t msg[8];
	uint64_t remain_bytes = datalen;
	uint64_t curr_offset = offset;
	char *data_ptr = data;

	if(key == NULL || data == NULL)
		return CRYPTFS_CRYPTO_ERROR;

	if(datalen == 0)
		return CRYPTFS_CRYPTO_NO_ERR;

	while(remain_bytes > 0) {

		initialize_block_msg((char*)msg);
		counter_block(msg, BLOCK_COUNT(curr_offset));
		if(des_crypt_block_msg(key, msg) != CRYPTFS_CRYPTO_NO_ERR)
			return CRYPTFS_CRYPTO_ERROR;

		int bytes = plaintext_xor_enc_msg(data_ptr, (char*)msg, curr_offset, remain_bytes);

		if(bytes == 0)
			return CRYPTFS_CRYPTO_ERROR;

		remain_bytes -= bytes;
		curr_offset += bytes;
		data_ptr += bytes;
	}

	return CRYPTFS_CRYPTO_NO_ERR;
}

fsal_status_t cryptfs_encrypt(uint64_t offset, size_t buffer_size, void *buffer) {

	if(ctr_crypt((char*)&g_key, (char*)buffer, (uint64_t)buffer_size, offset) == CRYPTFS_CRYPTO_NO_ERR) {
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}

	return fsalstat(ERR_FSAL_IO, 0);
}


fsal_status_t cryptfs_decrypt(uint64_t offset, size_t buffer_size, void *buffer) {

	if(ctr_crypt((char*)&g_key, (char*)buffer, (uint64_t)buffer_size, offset) == CRYPTFS_CRYPTO_NO_ERR) {
		return fsalstat(ERR_FSAL_NO_ERROR, 0);
	}

	return fsalstat(ERR_FSAL_IO, 0);
}

