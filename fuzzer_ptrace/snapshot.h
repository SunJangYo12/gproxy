#include <sys/types.h>

struct SNAPSHOT_MEMORY {
    long long unsigned maps_offset[50];
    long long unsigned snapshot_buf_offset[50];
    long long unsigned rdwr_length[50];
    long long unsigned heap_addr[5];
    int len;
};

unsigned char* create_snapshot(pid_t child_pid, struct SNAPSHOT_MEMORY *read_memory);

void restore_snapshot(unsigned char* snapshot_buf, pid_t child_pid, struct SNAPSHOT_MEMORY *read_memory);
