#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include<stdlib.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors() {
  ERR_print_errors_fp(stderr);
  abort();
}

int main(int argc, char **argv) {

  unsigned char key[] = "keykeykeykeykeykey";
  EVP_MAC *sha256 = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if(sha256 == NULL) {
    printf("OH NOOO");
    exit(1);
  }
  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(sha256);
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0),
    OSSL_PARAM_construct_end()
  };
  EVP_MAC_init(ctx, key, strlen(key), params);

  if (argc != 3) {
    fprintf(stderr, "Invalid parameters. Usage: %s filename1 filename2\n", argv[0]);
    exit(1);
  }

  FILE *f1, *f2;
  if ((f1 = fopen(argv[1], "r")) == NULL || (f2=fopen(argv[2], "r")) == NULL) {
    fprintf(stderr, "Couldn't open the input file, try again\n");
    exit(1);
  }

  size_t n, final;
  unsigned char buffer[30720];
  while ((n = fread(buffer, 1, MAXBUF, f1)) > 0) {
    // Returns 1 for success and 0 for failure.
    if (!EVP_MAC_update(ctx, buffer, n))
      handle_errors();
  }
  fclose(f1);
  while ((n = fread(buffer, 1, MAXBUF, f2)) > 0) {
    // Returns 1 for success and 0 for failure.
    if (!EVP_MAC_update(ctx, buffer, n))
      handle_errors();
  }
  fclose(f2);
  EVP_MAC_final(ctx, buffer, &final, sizeof(buffer));
  EVP_MAC_CTX_free(ctx);

  printf("CRYPTO25{");
  for (int i = 0; i < final; i++)
    printf("%02x", buffer[i]);
  printf("}\n");

  return 0;
}