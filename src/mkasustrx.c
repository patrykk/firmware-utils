// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 *  Copyright (C) 2023 OpenWrt.org
 *  Copyright (C) 2023 remittor
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#ifdef _MSC_VER
#include <malloc.h>
#include <Winsock2.h>
#include "getopt.h"      /* https://github.com/libimobiledevice-win32/getopt */
#else
#include <netinet/in.h>
#include <unistd.h>
#endif


#define IH_MAGIC    0x27051956
#define IH_NMLEN    32
#define IH_PRODLEN  23     // ASUS product name length

#define IH_OS_LINUX         5

#define IH_ARCH_ARM         2
#define IH_ARCH_MIPS        5
#define IH_ARCH_ARM64       22

#define IH_TYPE_INVALID     0
#define IH_TYPE_STANDALONE  1
#define IH_TYPE_KERNEL      2
#define IH_TYPE_RAMDISK     3
#define IH_TYPE_MULTI       4
#define IH_TYPE_FIRMWARE    5
#define IH_TYPE_SCRIPT      6
#define IH_TYPE_FILESYSTEM  7

#define IH_COMP_NONE        0
#define IH_COMP_GZIP        1
#define IH_COMP_BZIP2       2
#define IH_COMP_LZMA        3
#define IH_COMP_XZ          5

#ifdef _MSC_VER
#pragma pack(push, 1)
#define _PACKED
#else
#define _PACKED  __attribute__ ((packed))
#endif

typedef struct {
    uint8_t major;
    uint8_t minor;
} _PACKED  version_t;

typedef struct {
    version_t   kernel_ver;
    version_t   fs_ver;
    uint8_t     prod_name[IH_PRODLEN];
    uint8_t     sub_fs;
    uint32_t    ih_ksz;   // kernel size
} _PACKED  trx_t;

typedef struct image_header {
    uint32_t    ih_magic;
    uint32_t    ih_hcrc;
    uint32_t    ih_time;
    uint32_t    ih_size;     // content size
    uint32_t    ih_load;     // load addr
    uint32_t    ih_ep;       // entry point
    uint32_t    ih_dcrc;     // content hash
    uint8_t     ih_os;       // os type
    uint8_t     ih_arch;     // kernel arch
    uint8_t     ih_type;
    uint8_t     ih_comp;
    union {
        char    ih_name[IH_NMLEN];
        trx_t   trx;
    } tail;
} _PACKED  image_header_t;


typedef struct {
    uint32_t    extendno;   // fw extended build no (example: 51234)
    uint16_t    buildno;    // fw build no (example: 388)
    uint16_t    r16;        // always 0 ???
    uint32_t    r32;        // always 0 ???
} _PACKED  tail_content_t;

#define DEF_ASUS_TAIL_MAGIC  0x2AFED414

typedef struct {
    uint8_t     flags: 4,   // always 0 ???
                type : 4;   // always 1 ???
    uint8_t     clen[3];    // content len (24bit BE)
    uint16_t    fcrc;       // crc for footer
    uint16_t    checksum;   // content hash
    uint32_t    magic;
} _PACKED  tail_footer_t;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

// =========================================================

char * g_progname = "";
int g_debug = 0;

#define DBG(...) do { if (g_debug) printf( __VA_ARGS__ ); } while(0)

#ifdef _MSC_VER
#define _attr_fmt_err_
#else
#define _attr_fmt_err_   __attribute__ ((format (printf, 1, 2)))
#endif

static _attr_fmt_err_
void fatal_error(const char * fmtstr, ...)
{
    va_list ap;
    fflush(0);
    fprintf(stderr, "%s: ERROR: ", g_progname);
    va_start(ap, fmtstr);
    vfprintf(stderr, fmtstr, ap);
    va_end (ap);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

#define ERR(fmtstr, ...) fatal_error(fmtstr, ## __VA_ARGS__)


uint32_t crc32(const void * data, size_t length, uint32_t initval)
{
    uint32_t crc = ~initval;
    uint8_t * current = (uint8_t *) data;
    uint32_t j;
    while (length--) {
        crc ^= *current++;
        for (j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((-(int32_t)(crc & 1)) & 0xEDB88320);
    }
    return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint16_t asus_hash16(const void * data, size_t length)
{
    uint16_t hash = 0;
    uint16_t * current = (uint16_t *) data;
    length = length / sizeof(uint16_t);
    while (length--) {
        hash ^= *current++;
    }
    return ~hash; // same as hash ^ 0xFFFF
}

void update_iheader_crc(image_header_t * hdr, const void * data, size_t data_size)
{
    if (data == NULL)
        data = (const void *)((char *)hdr + sizeof(image_header_t));

    // Calculate payload checksum
    hdr->ih_dcrc = htonl(crc32(data, data_size, 0));
    hdr->ih_size = htonl(data_size);

    // Calculate header checksum
    hdr->ih_hcrc = 0;
    hdr->ih_hcrc = htonl(crc32(hdr, sizeof(image_header_t), 0));
}


typedef struct {
    int         show_info;
    char *      imagefn;
    char *      outfn;
    char        prod_name[128];
    version_t   kernel_ver;
    version_t   fs_ver;
    uint8_t     sub_fs;
    uint32_t    kernel_size;
    uint32_t    magic;
    uint32_t    type;
    uint32_t    flags;
    uint32_t    extendno;
    uint32_t    buildno;
    uint32_t    r16;
    uint32_t    r32;
} trx_opt_t;

trx_opt_t   g_def = {0};
trx_opt_t   g_opt = {0};

static
void init_opt(void)
{
    memset(&g_def, 0, sizeof(g_def));
    g_def.show_info = 0;
    g_def.kernel_size = 0x3000;
    g_def.magic = DEF_ASUS_TAIL_MAGIC;
    g_def.type = 1;
    g_def.flags = 0;
    memcpy(&g_opt, &g_def, sizeof(g_def));
}

static
void usage(int status)
{
    FILE * fp = (status != EXIT_SUCCESS) ? stderr : stdout;

    fprintf(fp, "Usage: %s -i <image> [OPTIONS...]\n", g_progname);
    fprintf(fp, "\n");
    fprintf(fp, "Options:\n");
    fprintf(fp, "    -i <filename>  input image filename \n");
    fprintf(fp, "    -o <filename>  output image filename \n");
    fprintf(fp, "    -x             show only image info \n");
    fprintf(fp, "    -n <name>      product name \n");
    fprintf(fp, "    -K <#>.<#>     kernel version (def: \"%d.%d\") \n", g_def.kernel_ver.major, g_def.kernel_ver.minor);
    fprintf(fp, "    -F <#>.<#>     filesys version (def: \"%d.%d\") \n", g_def.fs_ver.major, g_def.fs_ver.minor);
    fprintf(fp, "    -k <number>    kernel size (def: 0x%08X) \n", g_def.kernel_size);
    fprintf(fp, "    -m <signature> tail HEX signature (def: %08X) \n", g_def.magic);
    fprintf(fp, "    -t <number>    tail type (def: %X) \n", g_def.type);
    fprintf(fp, "    -f <number>    tail flags (def: %X) \n", g_def.flags);
    fprintf(fp, "    -e <number>    tail ext no (def: %d) \n", g_def.extendno);
    fprintf(fp, "    -b <number>    tail build no (def: %d) \n", g_def.buildno);
    fprintf(fp, "    -h             show this screen \n");
    exit(status);
}

static
int parse_args(int argc, char ** argv)
{
    int opt;
    char * str;
    char * end;
    
    while ((opt = getopt(argc, argv, "Dxi:o:n:K:F:k:m:t:f:e:b:h?")) != -1) {
        switch (opt) {
        case 'i':
            g_opt.imagefn = optarg;
            break;
        case 'o':
            g_opt.outfn = optarg;
            break;
        case 'x':
            g_opt.show_info = 1;
            g_debug = 1;
            break;
        case 'D':
            g_debug = 1;
            break;
        case 'n':
            strncpy(g_opt.prod_name, optarg, IH_PRODLEN);
            break;
        case 'K':
            g_opt.kernel_ver.major = (uint8_t) strtoul(optarg, &end, 10);
            if (end == optarg || end[0] != '.')
                ERR("Incorrect -K argument!");
            str = end + 1;
            g_opt.kernel_ver.minor = (uint8_t) strtoul(str, &end, 10);
            if (end == str)
                ERR("Incorrect -K argument!");
            break;
        case 'F':
            g_opt.fs_ver.major = (uint8_t) strtoul(optarg, &end, 10);
            if (end == optarg || end[0] != '.')
                ERR("Incorrect -F argument!");
            str = end + 1;
            g_opt.fs_ver.minor = (uint8_t) strtoul(str, &end, 10);
            if (end == str)
                ERR("Incorrect -F argument!");
            break;
        case 'k':
            g_opt.kernel_size = strtoul(optarg, &end, 0);
            if (end == optarg)
                ERR("Incorrect -k argument!");
            break;
        case 'm':
            g_opt.magic = strtoul(optarg, &end, 16);
            if (end == optarg)
                ERR("Incorrect -m argument!");
            break;
        case 't':
            g_opt.type = strtoul(optarg, &end, 0);
            if (end == optarg)
                ERR("Incorrect -t argument!");
            break;
        case 'f':
            g_opt.flags = strtoul(optarg, &end, 0);
            if (end == optarg)
                ERR("Incorrect -f argument!");
            break;
        case 'e':
            g_opt.extendno = strtoul(optarg, &end, 0);
            if (end == optarg)
                ERR("Incorrect -e argument!");
            break;
        case 'b':
            g_opt.buildno = strtoul(optarg, &end, 0);
            if (end == optarg)
                ERR("Incorrect -b argument!");
            break;
        case 'h':
        default:
            usage(EXIT_FAILURE);
        }
    }
    if (g_opt.imagefn == NULL || g_opt.imagefn[0] == 0)
        usage(EXIT_FAILURE); // Required input image filename!

    if (g_opt.show_info == 0)
        if (g_opt.outfn == NULL || g_opt.outfn[0] == 0)
            usage(EXIT_FAILURE); // Required output image filename!

    return 0;
}

static
char * load_image(size_t pad_size, size_t * psize)
{
    FILE * fp = fopen(g_opt.imagefn, "rb");
    if (!fp)
        ERR("Can't open %s: %s", g_opt.imagefn, strerror(errno));

    rewind(fp);
    fseek(fp, 0, SEEK_END);
    uint32_t file_sz = ftell(fp);
    rewind(fp);

    if ((int32_t)file_sz <= 0) {
        fclose(fp);
        ERR("Error getting filesize: %s", g_opt.imagefn);
    }
    if (file_sz <= sizeof(image_header_t)) {
        fclose(fp);
        ERR("Bad size: \"%s\" is no valid image", g_opt.imagefn);
    }
    void * buf = malloc(file_sz + pad_size);
    if (!buf) {
        fclose(fp);
        ERR("Out of memory!");
    }
    memset(buf, 0, file_sz + pad_size);
    
    size_t readed = fread(buf, 1, file_sz, fp);
    fclose(fp);
    if (readed != (size_t)file_sz)
        ERR("Error reading file %s", g_opt.imagefn);

    *psize = file_sz;
    return (char *)buf;
}

static
uint32_t get_timestamp(void)
{
    char * env = getenv("SOURCE_DATE_EPOCH");
    char * endptr = env;
    time_t fixed_timestamp = -1;
    if (env && *env) {
        errno = 0;
        fixed_timestamp = (time_t) strtoull(env, &endptr, 10);
        if (errno || (endptr && *endptr != '\0')) {
            fprintf(stderr, "ERROR: Invalid SOURCE_DATE_EPOCH \n");
            fixed_timestamp = -1;
        }
    }
    if (fixed_timestamp == -1) {
        time(&fixed_timestamp);
    }
    DBG("timestamp: %d \n", (uint32_t)fixed_timestamp);
    return (uint32_t)fixed_timestamp;
}

#define FDT_MAGIC  0xD00DFEED

static
int process_image(void)
{
    size_t img_size = 0;
    char * img = load_image(1024, &img_size);
    if (!img)
        ERR("Can't load file %s", g_opt.imagefn);
    
    image_header_t * hdr = (image_header_t *)img;
    if (ntohl(hdr->ih_magic) != IH_MAGIC) {
        if (g_opt.show_info)
            ERR("Incorrect image: \"%s\" magic must be %08X", g_opt.imagefn, IH_MAGIC);
        //if (ntohl(hdr->ih_magic) != FDT_MAGIC)
        //    ERR("Incorrect input image: \"%s\"", g_opt.imagefn);
        memmove(img + sizeof(image_header_t), img, img_size);
        memset(hdr, 0, sizeof(image_header_t));
        hdr->ih_magic = htonl(IH_MAGIC);
        hdr->ih_time = htonl(get_timestamp());
        hdr->ih_size = htonl(img_size);
        hdr->ih_load = 0;
        hdr->ih_ep   = 0;
        hdr->ih_os   = IH_OS_LINUX;
        hdr->ih_arch = IH_ARCH_ARM64;
        hdr->ih_type = IH_TYPE_KERNEL;
        hdr->ih_comp = IH_COMP_NONE;
        img_size += sizeof(image_header_t);
        //update_iheader_crc(hdr, NULL, img_size);
    }
    uint32_t data_size = (uint32_t)ntohl(hdr->ih_size);
    DBG("data: size = 0x%08X  (%d) \n", data_size, data_size);
    if (data_size + sizeof(image_header_t) > img_size)
        ERR("Bad size: \"%s\" is no valid content size", g_opt.imagefn);

    uint32_t data_crc_c = crc32(img + sizeof(image_header_t), data_size, 0);
    DBG("data: crc = %08X  (%08X) \n", ntohl(hdr->ih_dcrc), data_crc_c);

    image_header_t orig_hdr = *hdr;
    char * img_end = img + sizeof(image_header_t) + data_size;

    if (g_opt.show_info) {
        tail_footer_t * foot = (tail_footer_t *)(img_end - sizeof(tail_footer_t));
        DBG("tail: footer size = 0x%X  (%d) \n", sizeof(tail_footer_t), sizeof(tail_footer_t));
        DBG("tail: footer magic: 0x%X \n", ntohl(foot->magic));

        uint32_t cont_len = foot->clen[0] << 24 | foot->clen[1] << 16 | foot->clen[2];
        DBG("tail: type = %X, flags = %X, content len = 0x%06X \n", foot->type, foot->flags, cont_len);

        uint16_t fcrc = foot->fcrc;
        foot->fcrc = 0;
        uint16_t fcrc_c = asus_hash16(foot, sizeof(*foot));
        DBG("tail: fcrc = %04X  (%04X) \n", ntohs(fcrc), fcrc_c);

        tail_content_t * cont = (tail_content_t *)((char *)foot - cont_len);
        uint16_t checksum_c = asus_hash16(cont, sizeof(*cont));
        DBG("cont: checksum = %04X  (%04X) \n", ntohs(foot->checksum), checksum_c);

        DBG("cont: buildno: %d, extendno: %d \n", ntohs(cont->buildno), ntohl(cont->extendno));
        DBG("cont: r16: 0x%08X, r32: 0x%08X \n", ntohs(cont->r16), ntohl(cont->r32));
        return 0;
    }

    memset(hdr->tail.ih_name, 0, sizeof(hdr->tail.ih_name));
    if (g_opt.prod_name[0]) {
        strncpy(hdr->tail.trx.prod_name, g_opt.prod_name, IH_PRODLEN);
    } else {
        strncpy(hdr->tail.trx.prod_name, orig_hdr.tail.ih_name, IH_PRODLEN);
    }
    hdr->tail.trx.kernel_ver = g_opt.kernel_ver;
    hdr->tail.trx.fs_ver = g_opt.fs_ver;
    hdr->tail.trx.sub_fs = g_opt.sub_fs;
    hdr->tail.trx.ih_ksz = htonl(g_opt.kernel_size);

    uint32_t cont_len = sizeof(tail_content_t);
    tail_content_t * cont = (tail_content_t *)img_end;
    cont->extendno = htonl(g_opt.extendno);
    cont->buildno = htons(g_opt.buildno);
    cont->r16 = htons(g_opt.r16);
    cont->r32 = htonl(g_opt.r32);

    tail_footer_t * foot = (tail_footer_t *)(img_end + cont_len);
    foot->checksum = htons(asus_hash16(cont, cont_len));

    foot->clen[0] = (cont_len >> 16) & 0xFF;  // 24bit BigEndian
    foot->clen[1] = (cont_len >> 8) & 0xFF;
    foot->clen[2] = cont_len & 0xFF;

    foot->magic = htonl(g_opt.magic);
    foot->type = g_opt.type;
    foot->flags = g_opt.flags;
    foot->fcrc = 0;
    foot->fcrc = htons(asus_hash16(foot, sizeof(*foot)));

    size_t new_img_size = (size_t)((char *)foot + sizeof(tail_footer_t) - img);
    size_t new_data_size = new_img_size - sizeof(image_header_t);
    update_iheader_crc(hdr, NULL, new_data_size);

    FILE * fp = fopen(g_opt.outfn, "wb");
    if (!fp)
        ERR("Can't open %s for writing: %s", g_opt.outfn, strerror(errno));

    img_size = sizeof(image_header_t) + data_size + cont_len + sizeof(tail_footer_t);
    size_t wlen = fwrite(img, img_size, 1, fp);
    fclose(fp);
    if (wlen != 1)
        ERR("Failed to write: %s", g_opt.outfn);

    DBG("New TRX-image file created: \"%s\"", g_opt.outfn);
    free(img);
    return 0; // OK
}

int main(int argc, char ** argv)
{
    g_progname = argv[0];
    init_opt();
    parse_args(argc, argv);
    int rc = process_image();
    return rc;
}

