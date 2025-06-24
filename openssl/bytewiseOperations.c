#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main()
{
    unsigned char rand1InHex[] = "ed8a3be817683878f6b1773e73b3f797f300477654ee8d510a2f107917f8ead881836e0f0cb8495a77ef2d62b65ee21069d6ccd6a077a20ad3f79fa79ea7c908",
                  rand2InHex[] = "4c7582ca0207bd1d8d52f06c7ad6b7878395062fe0f7d424f8036897414c8529e50db0e43cee74dc188aaa26f04694e852914a438fddeabba8cf511479ec17c2";
    int rand1Len = strlen(rand1InHex) / 2, rand2Len = strlen(rand2InHex) / 2;
    unsigned char *rand1, *rand2;
    rand1= malloc(rand1Len);
    rand2= malloc(rand2Len);

    // convert from hex to binary
    for (int i = 0; i < rand1Len; i++)
        sscanf(&rand1InHex[2 * i], "%2hhx", &rand1[i]);
    for (int i = 0; i < rand2Len; i++)
        sscanf(&rand2InHex[2 * i], "%2hhx", &rand2[i]);

    unsigned char k1[rand1Len], k2[rand1Len], key[rand1Len];
    for (int i = 0; i < rand1Len; i++)
    {
        k1[i] = rand1[i] | rand2[i];
        k2[i] = rand1[i] & rand2[i];
        key[i] = k1[i] ^ k2[i];
    }
    printf("CRYPTO25{");
    for (int i = 0; i < rand1Len; i++)
    {
        if (i == ((rand1Len) - 1))
            printf("%02x", key[i]);
        else
            printf("%02x-", key[i]);
    }
    printf("}");
    free(rand1);
    free(rand2);
    return 0;
}