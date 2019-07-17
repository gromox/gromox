#include "hmacmd5.h"
#include <string.h>

/* the microsoft version of hmac_md5 initialisation */
void hmacmd5_init(HMACMD5_CTX *ctx, const uint8_t *key, int key_len)
{
	int i;
	uint8_t tk[16];
	
	if (key_len > 64) {
		key_len = 64;
	}
	memset(&ctx->k_ipad, 0, sizeof(ctx->k_ipad));
	memset(&ctx->k_opad, 0, sizeof(ctx->k_opad));
	memcpy( ctx->k_ipad, key, key_len);
	memcpy( ctx->k_opad, key, key_len);
	/* XOR key with ipad and opad values */
	for (i=0; i<64; i++) {
		ctx->k_ipad[i] ^= 0x36;
		ctx->k_opad[i] ^= 0x5c;
	}
	MD5_Init(&ctx->ctx);
	MD5_Update(&ctx->ctx, ctx->k_ipad, 64);  
}

void hmacmd5_update(HMACMD5_CTX *ctx, const uint8_t *text, int text_len)
{
	MD5_Update(&ctx->ctx, text, text_len);
}

void hmacmd5_final(HMACMD5_CTX *ctx, uint8_t *digest)
{
	MD5_CTX ctx_o;

	MD5_Final(digest, &ctx->ctx);          
	MD5_Init(&ctx_o);
	MD5_Update(&ctx_o, ctx->k_opad, 64);   
	MD5_Update(&ctx_o, digest, 16); 
	MD5_Final(digest, &ctx_o);
}
