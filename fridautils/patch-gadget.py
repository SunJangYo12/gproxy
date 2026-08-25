import lief

target = input("module: ")

libnative = lief.parse(target)
libnative.add_library("libgadget.so")
libnative.write(target)
