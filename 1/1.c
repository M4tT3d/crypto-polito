#include <openssl/rand.h>
#include <stdio.h>
// 16 byte = 128 bit
#define MAX 16

int main() {
   unsigned char string1[MAX], string2[MAX], string3[MAX];
   RAND_bytes(string1, MAX);
   RAND_bytes(string2, MAX);

   printf("%s", "Xored string: ");
   for (int i = 0; i < MAX; i++) {
      string3[i] = string1[i] ^ string2[i];
      printf("%02x", string3[i]);
   }
   printf("%s", "\n");
   return 0;
}