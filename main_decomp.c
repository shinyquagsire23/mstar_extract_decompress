#include <stdio.h>
#include <stdlib.h>
//#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint8_t U8;
typedef uint32_t U32;
typedef bool BOOLEAN;

U8 MsDecompress(U8 *pSrc, U8 *pDst, U32 srclen, U32 dstlen, U32 *pDecompressionLength);
void MSDecompress_MemoryAllocatorInit(unsigned char *ptr, unsigned long nSize);

#include "ms_decompress.h"
#include "ms_decompress_priv.h"

int main(int argc, char** argv)
{
    if (argc < 3) {
        printf("Usage: %s file_in.bin file_out.bin\n");
        return -1;
    }
    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        printf("Could not find file `%s`!\n", argv[1]);
    }
    
    fseek(f, 0L, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0L, SEEK_SET);
    
    void* buf = malloc(sz+0x1000);
    void* buf_out = malloc(sz*4);
    void* tmpbuf = malloc(MEMORY_POOL_SIZE);
    
    fread(buf, 1, sz, f);
    fclose(f);
    
    uint32_t out_size = 0;
    //g_MsDecomp_u8Debug = 1;
    MSDecompress_MemoryAllocatorInit(tmpbuf, MEMORY_POOL_SIZE);
    MsDecompress(buf, buf_out, sz, sz*4, &out_size);
    
    /*ms_DecompressInit(buf_out);
    out_size = ms_Decompress(buf, sz);
    ms_DecompressDeInit();*/
    
    printf("%zx -> %x, %x\n", sz, out_size, *(uint32_t*)buf_out, *(uint32_t*)buf);
    //out_size = 0x5b847C;
    f = fopen(argv[2], "wb");
    fwrite(buf_out, 1, out_size, f);
    fclose(f);
    
    return 0;
}
