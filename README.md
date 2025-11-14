mencocokan alamat gdb ke binaryninja
(gdb) b main
(gdb) run
(gdb) info proc mappings 
          Start Addr           End Addr       Size     Offset objfile
      0x555555554000 

binaryninja: file > rebase > 0x555555554000
