#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{
    unsigned char secret[] = "this_is_my_secret";
    // unsigned char test[strlen(secret)/2];

    // for (int i = 0; i < strlen(secret); i++)
    //     sscanf(&secret[2 * i], "%2hhx", &test[i]);

    if (argc != 2)
    {
        fprintf(stderr, "Invalid parameters. Usage: %s filename\n", argv[0]);
        exit(1);
    }

    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL)
    {
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(1);
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex2(ctx, EVP_sha512(), NULL))
    {
        fprintf(stderr, "Init failed\n");
        handle_errors();
    }

    int n_read;
    unsigned char buffer[MAXBUF];
    if (!EVP_DigestUpdate(ctx, secret, strlen(secret)))
        handle_errors();
    while ((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0)
    {
        // Returns 1 for success and 0 for failure.
        if (!EVP_DigestUpdate(ctx, buffer, n_read))
            handle_errors();
    }
    if (!EVP_DigestUpdate(ctx, secret, strlen(secret)))
        handle_errors();

    unsigned char md_value[EVP_MAX_MD_SIZE];
    int md_len;

    // int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
    if (!EVP_DigestFinal_ex(ctx, md_value, &md_len))
        handle_errors();

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
    EVP_MD_CTX_free(ctx);

    printf("CRYPTO25{");
    for (int i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("}");

    return 0;
}