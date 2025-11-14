# Requirenment
binaryninja 2.0...
gdb 9


# Usage
1). copy this directory in binaryninja plugin path
2). gdb ./a.out
    (gdb) source /gproxy/gdbinit.py
3). start server in binaryninja: Tools > gproxy > start server

mencocokan alamat gdb ke binaryninja
(gdb) b main
(gdb) run
(gdb) info proc mappings 
          Start Addr           End Addr       Size     Offset objfile
      0x555555554000 

binaryninja: file > rebase > 0x555555554000

# Tips
start server setelah address di binaryninja di rebase
