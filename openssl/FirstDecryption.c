#include <openssl/bio.h>
#include<openssl/evp.h>
#include <stdlib.h>
#include<string.h>
#include <stdio.h>
#include<openssl/bio.h>
#include<openssl/buffer.h>

#define ENC 1
#define DEC 0

int base64_decode(const char *base64, unsigned char **decoded, int *len){
    BIO *b64, *bmem;
    int decodedLen = strlen(base64)*3/4;
    *decoded =(unsigned char *)malloc(decodedLen+1);
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf(base64, -1);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    *len = BIO_read(bmem, *decoded, decodedLen);
    BIO_free_all(bmem);
    return 1;
}

int main(int argc, char **argv){
	unsigned char keyInHex[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
	unsigned char ivInHex[] = "11111111111111112222222222222222";
	unsigned char ciphertextHex[] = "jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==";

    unsigned char *ciphertext;
    int ciphertextLen = 0;
    if(!base64_decode(ciphertextHex, &ciphertext, &ciphertextLen)){
        fprintf(stderr, "RIP");
        return 1;
    }
    // for(int i=0; i< ciphertextLen; i++) printf("%c", ciphertext[i]);

	unsigned char key[strlen((char *)keyInHex)/2];
    for(int i = 0; i < strlen((char *)keyInHex)/2;i++){
        sscanf(&keyInHex[2*i],"%2hhx", &key[i]);
    }

    unsigned char iv[strlen(ivInHex)/2];
    for(int i = 0; i < strlen(ivInHex)/2; i++){
        sscanf(&ivInHex[2*i],"%2hhx", &iv[i]);
    }
    unsigned char plaintext[1024];
    int updateLen = 0, final_len = 0, decLen = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(EVP_CipherInit_ex2(ctx, EVP_chacha20(), key, iv, DEC, NULL)!=1) exit(1);
    if(EVP_CipherUpdate(ctx, plaintext, &updateLen, ciphertext, ciphertextLen) !=1) exit(2);
    decLen += updateLen;
    EVP_CipherFinal_ex(ctx, plaintext+updateLen, &final_len);
    decLen += final_len;
    EVP_CIPHER_CTX_free(ctx);
    decLen += final_len;
    printf("decLen: %d updatedLed: %d final_len: %d", decLen, updateLen, final_len);
    for(int i=0; i<decLen; i++) printf("%c", plaintext[i]);
	return 0;
}