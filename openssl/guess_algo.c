#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_OUTPUT_LEN 1024

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

void test_cipher(const EVP_CIPHER *cipher, const char *name, void *arg) {
   struct {
      unsigned char *ciphertext;
      int ciphertext_len;
   } *ctx_data = arg;

   if (EVP_CIPHER_key_length(cipher) != 16 ||
       EVP_CIPHER_iv_length(cipher) != 16)
      return;

   unsigned char key[16] = "0123456789ABCDEF";
   unsigned char iv[16] = "0123456789ABCDEF";
   unsigned char plaintext[MAX_OUTPUT_LEN];
   int out_len1 = 0, out_len2 = 0;

   EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
   if (!ctx) return;

   if (!EVP_CipherInit(ctx, cipher, key, iv, 0)) {
      EVP_CIPHER_CTX_free(ctx);
      return;
   }

   if (!EVP_CipherUpdate(ctx, plaintext, &out_len1, ctx_data->ciphertext,
                         ctx_data->ciphertext_len)) {
      EVP_CIPHER_CTX_free(ctx);
      return;
   }

   if (!EVP_CipherFinal(ctx, plaintext + out_len1, &out_len2)) {
      EVP_CIPHER_CTX_free(ctx);
      return;
   }

   int total_len = out_len1 + out_len2;

   // Stampiamo il risultato nel formato richiesto
   printf("CRYPTO25{");
   fwrite(plaintext, 1, total_len, stdout);
   printf("%s}\n", EVP_CIPHER_get0_name(cipher));

   EVP_CIPHER_CTX_free(ctx);
}

int main() {
   ERR_load_crypto_strings();

   // === Step 1: Decode Base64 ===
   const char *b64_ciphertext = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=";
   int ciphertext_len;
   unsigned char *ciphertext;
   base64_decode(b64_ciphertext, &ciphertext, &ciphertext_len);

   // === Step 2: Setup context to pass ciphertext ===
   struct {
      unsigned char *ciphertext;
      int ciphertext_len;
   } ctx_data;
   const char toTest[][15] = {
      "ARIA-128-CBC",
      "ARIA-128-CFB",
      "ARIA-128-CTR",
      "ARIA-128-OCB",
      "ARIA-128-CFB1",
      "ARIA-128-CFB8",
      "ARIA-128-OFB",
   };

   ctx_data.ciphertext = ciphertext;
   ctx_data.ciphertext_len = ciphertext_len;

   for(int i =0; i< 7; i++) test_cipher(EVP_get_cipherbyname((const char *)toTest[i]), "toTest[i]", &ctx_data);
   // EVP_CIPHER_do_all_sorted(test_cipher, &ctx_data);

   free(ciphertext);
   EVP_cleanup();
   ERR_free_strings();
   return 0;
}
