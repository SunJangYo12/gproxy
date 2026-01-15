#define _GNU_SOURCE
#include "snapshot.h"
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>


unsigned char* create_snapshot(pid_t child_pid, struct SNAPSHOT_MEMORY *read_memory) {

   int itotal = 0;
   FILE *fd;
   char buffer[200];
   char proc_maps[0x20] = { 0 };

   sprintf(proc_maps, "/proc/%d/maps", child_pid);
   fd = fopen(proc_maps, "r");

   while(fgets(buffer, sizeof(buffer), fd))
   {
       if (strstr(buffer, "rw"))
       {
           long long unsigned start = strtoull(buffer, NULL, 16);
           long long unsigned end = strtoull(strstr(buffer, "-")+1, NULL, 16);

           printf("[+] maps[%d]: %s", itotal, buffer);

           if (strstr(buffer, "[heap]")) {
               read_memory->heap_addr[0] = start;
               read_memory->heap_addr[1] = end;
               continue;
           }

           read_memory->maps_offset[itotal] = start;
           read_memory->rdwr_length[itotal] = end - start;

           if (itotal == 0)
               read_memory->snapshot_buf_offset[itotal] = 0x0;
           else
               read_memory->snapshot_buf_offset[itotal] = read_memory->snapshot_buf_offset[itotal-1] + read_memory->rdwr_length[itotal-1] + 0x800;

           itotal++;
       }
   }
   fclose(fd);
   read_memory->len = itotal;

   printf("%llx\n", read_memory->maps_offset[read_memory->len]);


    unsigned char* snapshot_buf = (unsigned char*)malloc(0x3D000);
 
    // this is just /proc/$pid/mem
    char proc_mem[0x20] = { 0 };
    sprintf(proc_mem, "/proc/%d/mem", child_pid);
 
    // open /proc/$pid/mem for reading
    // hardcoded offsets are from typical /proc/$pid/maps at main()
    int mem_fd = open(proc_mem, O_RDONLY);
    if (mem_fd == -1) {
        fprintf(stderr, "dragonfly> Error (%d) during ", errno);
        perror("open");
        exit(errno);
    }
 
    // this loop will:
    //  -- go to an offset within /proc/$pid/mem via lseek()
    //  -- read x-pages of memory from that offset into the snapshot buffer
    //  -- adjust the snapshot buffer offset so nothing is overwritten in it
    int lseek_result, bytes_read;

    for (int i=0; i<read_memory->len; i++)
    {
        printf("dragonfly> Reading from offset: %d %llx %llx %llx\n", i,
            read_memory->maps_offset[i],
            read_memory->snapshot_buf_offset[i],
            read_memory->rdwr_length[i]);

        lseek_result = lseek(mem_fd, read_memory->maps_offset[i], SEEK_SET);

        if (lseek_result == -1) {
            fprintf(stderr, "dragonfly> Error (%d) during ", errno);
            perror("lseek");
            exit(errno);
        }
 
        bytes_read = read(mem_fd,
            (unsigned char*)(snapshot_buf + read_memory->snapshot_buf_offset[i]),
            read_memory->rdwr_length[i]);

        if (bytes_read == -1) {
            fprintf(stderr, "dragonfly> Error (%d) during ", errno);
            perror("read");
            exit(errno);
        }
    }
 
    close(mem_fd);

    printf("%d\n", read_memory->len);

    return snapshot_buf;
}

void restore_snapshot(unsigned char* snapshot_buf, pid_t child_pid, struct SNAPSHOT_MEMORY *read_memory) {

    ssize_t bytes_written = 0;
    struct iovec local[read_memory->len];
    struct iovec remote[read_memory->len];

    // this struct is the local buffer we want to write from into the 
    // struct that is 'remote' (ie, the child process where we'll overwrite
    // all of the non-heap writable memory sections that we parsed from 
    // proc/$pid/memory)
    for (int i=0; i<read_memory->len; i++)
    {
        //printf("dragonfly> Reading from offset: %d\n", i);
        if (i == 0) {
            local[i].iov_base = snapshot_buf;
            local[i].iov_len = read_memory->rdwr_length[i];
        }
        else {
            local[i].iov_base = (unsigned char*)(snapshot_buf + read_memory->snapshot_buf_offset[i]);
            local[i].iov_len = read_memory->rdwr_length[i];
        }
    }

    // just hardcoding the base addresses that are writable memory
    // that we gleaned from /proc/pid/maps and their lengths
    for (int i=0; i<read_memory->len; i++)
    {
        remote[i].iov_base = (void*)read_memory->maps_offset[i];
        remote[i].iov_len = read_memory->rdwr_length[i];
    }

    bytes_written = process_vm_writev(child_pid, local, read_memory->len, remote, read_memory->len, 0);
    //printf("dragonfly> %d %ld bytes written\n", read_memory->len, bytes_written);
}
