#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bn.h>
#include <ctype.h>

int main()
{
    unsigned char hex1[] = "009eee82dc2cd4a00c4f5a7b8663b0c1ed0677fcebde1a235df4c3ff876a7dadc607faa835f6ae0503573e223676d50d574f99f958ad637ae745a6aafa023423b69d34157b1141b6b1cab91acd2955bd42f504abdf454a9d4eca4e01f9f8745967eeb6a9fb96b7c09400178a530eb6d831c968e66438d3633a04d7886bf0e1ad607f41bd857bd904e1975b1f9b05ceac2cc4553fb48b894d0a509a094e5e8f5b5f5569725f049b3a8a09b47f8db2ca520e5ebff4b0eec9badc934f6dd31f821ad9fc2ca73f18230dd744c728546784ee739265f01ce81e6d4d9565b4c84fb80462582bee3264a0a7dc99250e505376bc30db715e93d69f1f881c765d82c8593951";
    unsigned char hex2[] = "00d2c601326b4c4b855f527bb78ed68ae4c8767e6bc9249a3ecacd2fc9b875d4f97111e1cfbe62d32c5ff9fd9bfaed62f3df44c757fbee9bb232cb5449296c692e301d8c1ffab18ee44966c1fb927c82ca60c940a40ab2db50ecf6ff98a71623388d06d27ca9858ac22b4dd4e6f189e5b04254a05f3cddc764330511fbee8b2607";

    // forse è basato sulla generazione delle chiavi di RSA
    // n=pq. In questo caso abbiamo n e uno tra p e q.
    // facendo n/p=q. q dovrebbe essere la risposta alla ctf
    BIGNUM *hex1Bn = BN_new(), *hex2Bn = BN_new();
    BIGNUM *div = BN_new(), *rem = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_hex2bn(&hex1Bn, hex1);
    BN_hex2bn(&hex2Bn, hex2);
    BN_div(div, rem, hex1Bn, hex2Bn, ctx);
    // free(hex2Padded);
    char *bnHex = BN_bn2hex(div);
    printf("CRYPTO25{00:");
    for (int i = 0; i < strlen(bnHex); i += 2)
    {
        printf("%c%c", tolower(bnHex[i]), tolower(bnHex[i + 1]));
        if (i + 2 < strlen(bnHex))
            printf(":");
    }
    printf("}");
    // free(hex1Bin);
    // free(hex2Bin);
    return 0;
}