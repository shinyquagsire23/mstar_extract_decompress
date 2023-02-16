
#!/bin/zsh

#gcc -g -o decompress_mstar 7alloc.c lzmadec.c ms_decompress.c zlib.c main_decomp.c
gcc -g -o extract_mstar 7alloc.c lzmadec.c ms_decompress.c zlib.c main_extract.c
