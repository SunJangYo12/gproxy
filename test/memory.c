
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    printf("=== TEST ALLOCATORS ===\n");

    // malloc
    char *a = malloc(0x40);
    if (!a) return 1;
    memcpy(a, "Hello malloc!", 20);

/*
    // calloc
    char *b = calloc(1, 0x30);
    strncpy(b, "This is calloc block", 20);

    // realloc
    a = realloc(a, 0x80);
    strncat(a, " zzz realloc", 20);

    // read() test
    printf("Input some text (up to 32 bytes): ");
    fflush(stdout);

    char *c = malloc(32);
    ssize_t n = read(0, c, 32);   // menulis ke heap

    printf("Read %zd bytes: %s\n", n, c);
*/
    // free
    free(a);
//    free(b);
//    free(c);

    return 0;
}


