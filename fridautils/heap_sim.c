
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void decode_payload(char *buf)
{
    printf("[decode_payload] %p\n", buf);

    if (buf[0] == 'A')
        printf("payload starts with A\n");
}

void parse_chunk(char *buf)
{
    printf("[parse_chunk] %p\n", buf);

    decode_payload(buf);
}

void parse_header(char *buf)
{
    printf("[parse_header] %p\n", buf);

    if (memcmp(buf, "MAGC", 4) == 0)
        printf("valid header\n");

    parse_chunk(buf);
}

void read_file(char *buf)
{
    printf("[read_file] %p\n", buf);

    parse_header(buf);
}

int main(void)
{
    char buffer[100];
    printf("Masukkan teks: ");
    fgets(buffer, sizeof(buffer), stdin);

    char *buf = malloc(1024);

    printf("[malloc] %p\n", buf);
    memcpy(buf, "MAGCAAAAAAAA", 12);
    read_file(buf);

    free(buf);
    return 0;
}

