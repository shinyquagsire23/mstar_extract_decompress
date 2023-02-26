#include <stdio.h>
#include <stdlib.h>
//#include <malloc.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "endian.h"

typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef bool BOOLEAN;

U8 MsDecompress(U8 *pSrc, U8 *pDst, U32 srclen, U32 dstlen, U32 *pDecompressionLength);
void MSDecompress_MemoryAllocatorInit(unsigned char *ptr, unsigned long nSize);

#define IMG_TYPE_NONE   0x00
#define IMG_TYPE_BOOT   0x01
#define IMG_TYPE_APP    0x02
#define IMG_TYPE_MERGE  (IMG_TYPE_BOOT | IMG_TYPE_APP)

// Magic numbers. Don't change them! The numbers are also used externally.
#define MAGIC_BOOTLOADER        0x55AA1234  // Used by: (1) ISP tool. (2) CRC32 tool
#define MAGIC_APP               0x55AA5678  // Used by: (1) Bootloader for integrity check. (2) ISP tool. (3) CRC32 tool
#define MAGIC_IMAGE_END         0x55AAABCD  // At the end of a image (see packlist.txt and the file MagicNum55AAABCD.bin). Mainly for detection of programming failure.

#define CUSTOMER_SELBYTE_LEN    4 // It's customized
#define IMG_MODEL_NAME_LEN      19
#define IMG_PANEL_NAME_LEN      19

typedef struct
{
    U32     u32Magic;                   // Magic number

    U16     u16PackInfoFlashBankNo;     // Flash bank No of pack information
    U16     u16PackInfoFlashOffset;     // Flash offset of pack information

    //MS_MEMORY_INFO MCU8051Code;         // Memory information of MCU8051 code
    //MS_MEMORY_INFO AEONCode;            // Memory information of AEON code
    //MS_MEMORY_INFO Database;            // Memory information of database

    U32     u32Length;
    U32     u32OUI;                     // OUI or manufacturer id
    U8      au8Selector_Byte[CUSTOMER_SELBYTE_LEN]; // Selector Byte

    U16     u16HW_Model;                // HW Model
    U16     u16HW_Version;              // HW Version

    U16     u16SW_Model;                // SW Model
    U16     u16SW_Version;              // SW Version

    U16     u16BoardType;                // Board type
    U8      u8ModelName[IMG_MODEL_NAME_LEN+1];            // Model name
    U8      u8PanelName[IMG_PANEL_NAME_LEN+1];            // Panel name
    U8      u8PanelType;
	U8		CompressMagicNum[3];
	U32     u32CompressedLength;

    //U8      u8Reserved[32];             // Reserved for future use

    U32 u32MagicId_2; // This is for BLoader: 0x55AAABCD

#if( ENABLE_SBOOT_LOAD_BIN )
    void* pstJobaData;
#else
    U32 u32Reserved_1;
#endif

#if( ENABLE_FLASH_ON_DRAM)
    void* pstFODData;
#else
    U32 u32Reserved_2;
#endif

} MS_IMG_INFO;


#define BIN_PACKAGE_HEADER_ID0  0x54454C09
#define BIN_PACKAGE_HEADER_ID1  0x58336900


#define BIN_DISPLAY_HEADER_ID0  0x54454C09
#define BIN_DISPLAY_HEADER_ID1  0x31207341
#define BIN_DRAMMAP_HEADER_ID0  0x4D5354FA
#define BIN_DRAMMAP_HEADER_ID1  0x50417461
#define BIN_IRMAP_HEADER_ID     0x77554321
#define BIN_KEYPAD_HEADER_ID    0x4368656E

#define BIN_PACKAGE_HEADER_SIZE 0x0C
#define BIN_PACKAGE_NUMBER_SIZE 0x02
#define BIN_PACKAGE_BINFO_SIZE  0x0B

#define BIN_PACKAGE_HEADER_ADDR 0x00
#define BIN_PACKAGE_NUMBER_ADDR (BIN_PACKAGE_HEADER_ADDR+BIN_PACKAGE_HEADER_SIZE)
#define BIN_PACKAGE_BINFO_ADDR  (BIN_PACKAGE_NUMBER_ADDR+BIN_PACKAGE_NUMBER_SIZE)

//--------------------------------------------
// Reserved for Customer: Range 0xC000-0xCFFF
//--------------------------------------------
//#define BIN_ID_CUSTOMER_RESERVED_1    0xC000
//...
//#define BIN_ID_CUSTOMER_RESERVED_X    0xCFFF
typedef struct _BIN_INFO_
{
    U8 B_ID[2];                 //!< Unique ID
    U8 B_FAddr[4];              //!< Start address
    U8 B_Len[4];                //!< Length in bytes
    U8  B_IsComp;             //!< Is bin compressed
} BININFO;

typedef struct
{
    U8 magic_1[4];
    U8 magic_2[4];
    U8 unk[4];
    U8 some_num[2];
    BININFO aBinInfos[];
}   BININFO_HEADER;



#include "ms_decompress.h"
#include "ms_decompress_priv.h"

int main(int argc, char** argv)
{
    char tmp[256];
    if (argc < 2) {
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
    
    void* tmpbuf = malloc(MEMORY_POOL_SIZE);
    void* buf = malloc(sz+0x1000);
    fread(buf, 1, sz, f);
    fclose(f);

    uint32_t archive_start = 0;
    for (archive_start = 0; archive_start < sz; archive_start += 0x80)
    {
        if (getbe32((uint8_t*)((intptr_t)buf + archive_start)) == BIN_PACKAGE_HEADER_ID0) {
            break;
        }
    }

    uint32_t appimg_start = archive_start - 0x2000;
    
    BININFO_HEADER* pInfo = (BININFO_HEADER*)((intptr_t)buf + archive_start);

    if (getbe32(pInfo->magic_1) != BIN_PACKAGE_HEADER_ID0 || getbe32(pInfo->magic_2) != BIN_PACKAGE_HEADER_ID1)
    {
        printf("Invalid magic values at %08x: %08x %08x != %08x %08x\n", archive_start, getbe32(pInfo->magic_1), getbe32(pInfo->magic_2), BIN_PACKAGE_HEADER_ID0, BIN_PACKAGE_HEADER_ID1);
        return -1;
    }

    mkdir("extract", 0700);

    uint32_t earliest_addr = sz;

    for (int i = 0; i < getbe16(pInfo->some_num); i++)
    {
        uint16_t id = getbe16(pInfo->aBinInfos[i].B_ID);
        uint32_t f_addr = getbe32(pInfo->aBinInfos[i].B_FAddr);
        uint32_t f_len = getbe32(pInfo->aBinInfos[i].B_Len);
        uint8_t  comp_flags = pInfo->aBinInfos[i].B_IsComp;

        if (f_addr < earliest_addr) {
            earliest_addr = f_addr;
        }

        snprintf(tmp, sizeof(tmp), "extract/%02u_%04x_%08x.bin", i, id, f_addr);
        printf("ID %04x: addr=%08x len=%08x flags=%02x -> %s\n", id, f_addr, f_len, comp_flags, tmp);

        //printf("%08x\n", *(U32*)((intptr_t)buf + f_addr));

        uint32_t out_size = 0;

        if (comp_flags & 4)
        {
            void* buf_out = malloc(f_len*4);
            MSDecompress_MemoryAllocatorInit(tmpbuf, MEMORY_POOL_SIZE);
            MsDecompress((U8*)((intptr_t)buf + f_addr), buf_out, f_len, f_len*4, &out_size);

            f = fopen(tmp, "wb");
            fwrite(buf_out, 1, out_size, f);
            fclose(f);

            free(buf_out);
        }
        else {
            out_size = f_len;
            f = fopen(tmp, "wb");
            fwrite((void*)((intptr_t)buf + f_addr), 1, out_size, f);
            fclose(f);
        }
    }

    uint32_t out_size;
    uint32_t f_addr = archive_start+0x800;

    while (*(uint32_t*)(buf + f_addr) == 0) {
        f_addr += 0x80;
    }
    printf("And the main is at: 0x%x\n", f_addr);
    snprintf(tmp, sizeof(tmp), "extract/MAIN_%08x.bin", appimg_start);
    void* buf_out = malloc(sz*4);
    MSDecompress_MemoryAllocatorInit(tmpbuf, MEMORY_POOL_SIZE);
    MsDecompress((U8*)((intptr_t)buf + f_addr), buf_out, sz-f_addr, sz*4, &out_size);
    if (!out_size) {
        printf("This is a weird one maybe, trying again but 0x800 forward...\n");

        f_addr += 0x800;
        MSDecompress_MemoryAllocatorInit(tmpbuf, MEMORY_POOL_SIZE);
        MsDecompress((U8*)((intptr_t)buf + f_addr), buf_out, sz-f_addr, sz*4, &out_size);

        if (out_size) {
            printf("Yes! 0x%08x bytes.\n", out_size);
        }
    }

    if (!out_size) {
        f_addr = earliest_addr;
        printf("Maybe it's uncompressed idk.\n");
    }

    f = fopen(tmp, "wb");
    fwrite((void*)((intptr_t)buf + appimg_start), 1, f_addr-appimg_start, f);
    fwrite(buf_out, 1, out_size, f);
    fclose(f);

    free(buf_out);
    


#if 0
    
    //g_MsDecomp_u8Debug = 1;
    MSDecompress_MemoryAllocatorInit(tmpbuf, MEMORY_POOL_SIZE);
    MsDecompress(buf, buf_out, sz, sz*4, &out_size);
    
    /*ms_DecompressInit(buf_out);
    out_size = ms_Decompress(buf, sz);
    ms_DecompressDeInit();*/
    
    printf("%zx -> %x, %x\n", sz, out_size, *(uint32_t*)buf_out, *(uint32_t*)buf);
    //out_size = 0x5b847C;
    
#endif
    
    return 0;
}
