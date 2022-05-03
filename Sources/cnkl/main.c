/* Requires C99 or C++14 or later */
/* Chunklist file format */
#include <stdint.h>
#define SHA256_DIGEST_LENGTH          32

/*
 * Chunklist file format
 */
#define CHUNKLIST_MAGIC                 0x4C4B4E43 // CNKL
#define CHUNKLIST_FILE_VERSION_10       1
#define CHUNKLIST_CHUNK_METHOD_10       1
#define CHUNKLIST_SIGNATURE_METHOD_REV1 1
#define CHUNKLIST_SIGNATURE_METHOD_REV2 3
#define CHUNKLIST_REV1_SIG_LEN          256
#define CHUNKLIST_REV2_SIG_LEN          808

struct chunklist_hdr {
    uint32_t cl_magic;
    uint32_t cl_header_size;
    uint8_t  cl_file_ver;
    uint8_t  cl_chunk_method;
    uint8_t  cl_sig_method;
    uint8_t  __unused1;
    uint64_t cl_chunk_count;
    uint64_t cl_chunk_offset;
    uint64_t cl_sig_offset;
} __attribute__((packed));

struct chunklist_chunk {
    uint32_t chunk_size;
    uint8_t  chunk_sha256[SHA256_DIGEST_LENGTH];
} __attribute__((packed));


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <getopt.h>
#include <unistd.h>

#define DEFAULT_CHUNK_SIZE 10485760L

#if __APPLE__
#include <CommonCrypto/CommonDigest.h>
#elif __linux__
#include <openssl/sha.h>
unsigned char *CC_SHA256(const void *data, uint32_t len, unsigned char *md)
{
    SHA256_CTX ctx;
    BYTE hash[SHA256_DIGEST_LENGTH];
    sha256_init(&ctx);
    sha256_update(&ctx, data, chunk.chunk_size);
    sha256_final(&ctx, md);
}
#endif

void usage()
{
    fprintf(stderr, "Usage: cnkl [-vcg] [-l <chunklist>] <file>\n");
    exit(EXIT_FAILURE);
}

int cnkl_check(const char *clpath, const char *filepath, int verbose)
{
    FILE * cl = fopen(clpath, "r");
    if (!cl) {
        fprintf(stderr, "Error: %s could not be opened.\n", clpath);
        return 2;
    }
    struct chunklist_hdr header;
    fread(&header, sizeof(struct chunklist_hdr), 1, cl);
    if (header.cl_magic != CHUNKLIST_MAGIC) {
        fprintf(stderr, "Error: %s is not a chunklist file.\n", clpath);
        return 3;
    }
    if (header.cl_file_ver != CHUNKLIST_FILE_VERSION_10 ||
        header.cl_chunk_method != CHUNKLIST_CHUNK_METHOD_10) {
        fprintf(stderr, "Error: %s is not supported.\n", clpath);
        return 4;
    }
    fseek(cl, (long int)header.cl_chunk_offset, SEEK_SET);
    FILE * fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Error: %s could not be opened.\n", filepath);
        return 2;
    }
    
    uint8_t hash[SHA256_DIGEST_LENGTH];
    uint8_t *buf = NULL;
    uint64_t buflen = -1;
    for (int i = 0; i < header.cl_chunk_count; i++) {
        struct chunklist_chunk chunk;
        fread(&chunk, sizeof(struct chunklist_chunk), 1, cl);
        if (verbose)
            fprintf(stderr, "checking chunk %d/%llu (size %u)...\r", i, header.cl_chunk_count, chunk.chunk_size);
        
        if (buflen > chunk.chunk_size) {
            if (buf) free(buf);
            buf = NULL;
        }
        
        if (!buf) {
            buflen = chunk.chunk_size;
            buf = malloc(buflen);
        }
        fread(buf, chunk.chunk_size, 1, fp);
        CC_SHA256(buf, chunk.chunk_size, hash);
        if (memcmp(chunk.chunk_sha256, hash, SHA256_DIGEST_LENGTH) != 0) {
            free(buf);
            if (verbose) fputc('\n', stderr);
            fprintf(stderr, "verify failed.\n");
            fclose(fp);
            fclose(cl);
            return 1;
        }
    }
    if (verbose) fputc('\n', stderr);
    free(buf);
    fclose(fp);
    fclose(cl);
    fprintf(stderr, "verify succeeded.\n");
    return 0;
}

int cnkl_gen(const char *clpath, const char *filepath, int verbose)
{
    struct chunklist_hdr header;
    FILE * fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Error: %s could not be opened.\n", filepath);
        return 2;
    }
    header.cl_magic = CHUNKLIST_MAGIC;
    header.cl_header_size = 36;
    header.cl_file_ver = CHUNKLIST_FILE_VERSION_10;
    header.cl_chunk_method = CHUNKLIST_CHUNK_METHOD_10;
    header.cl_sig_method = CHUNKLIST_SIGNATURE_METHOD_REV1;
    header.cl_chunk_offset = 36;
    fseek(fp, 0L, SEEK_END);
    uint64_t file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    header.cl_chunk_count = (uint64_t)ceil(file_size / DEFAULT_CHUNK_SIZE);
    struct chunklist_chunk *chunks = malloc(sizeof(struct chunklist_chunk)*header.cl_chunk_count);
    uint8_t *buf = NULL;
    uint64_t buflen = -1;
    for (int i = 0; i*DEFAULT_CHUNK_SIZE < file_size && !feof(fp) && i < header.cl_chunk_count; i++) {
        chunks[i].chunk_size = (i == header.cl_chunk_count - 1 ? file_size % DEFAULT_CHUNK_SIZE : DEFAULT_CHUNK_SIZE);
        if (verbose)
            fprintf(stderr, "creating chunk %d/%llu (size %u)...\r", i, header.cl_chunk_count, chunks[i].chunk_size);
        if (buflen > chunks[i].chunk_size) {
            if (buf) free(buf);
            buf = NULL;
        }
        
        if (!buf) {
            buflen = chunks[i].chunk_size;
            buf = malloc(buflen);
        }
        
        fread(buf, chunks[i].chunk_size, 1, fp);
        CC_SHA256(buf, chunks[i].chunk_size, chunks[i].chunk_sha256);
    }
    if (buf) free(buf);
    fclose(fp);
    FILE * cl = fopen(clpath, "w");
    fwrite(&header, sizeof(struct chunklist_hdr), 1, cl);
    fwrite(chunks, sizeof(struct chunklist_chunk)*header.cl_chunk_count, 1, cl);
    fclose(cl);
    free(chunks);
    if (verbose)
        fputc('\n', stderr);
    fprintf(stderr, "generated at: %s\n", clpath);
    return 0;
}

static inline const char *cnkl_path(char *dest, const char *filepath, const char *ext) {
    
    return dest;
}

int main(int argc, char * argv[]) {
    int verbose, gen, ch;
    const char *cnkl, *filepath;
    char cl_default[PATH_MAX];
    char *exts[] = {"chunklist", "integrityDataV1"};
    
    cnkl = NULL;
    verbose = 0;
    gen     = 0;
    while ((ch = getopt(argc, argv, "hvcgl:")) != -1 ) {
        switch (ch) {
            case 'v':
                verbose = 1;
                break;
            case 'c':
                gen = 0;
                break;
            case 'g':
                gen = 1;
                break;
            case 'l':
                cnkl = optarg;
                break;
            case 'h':
            default:
                usage();
        }
    }
    
    argc -= optind;
    argv += optind;
    
    if (argc != 1)
        usage();
    filepath = argv[0];
    if (gen) {
        if (!cnkl)  {
            sprintf(cl_default, "%s.%s", filepath, exts[0]);
            cnkl = cl_default;
        }
        return cnkl_gen(cnkl, filepath, verbose);
    }
    
    if (cnkl)
        return cnkl_check(cnkl, filepath, verbose);
    
    for (int i = 0; i < sizeof(exts)/sizeof(char *); i++) {
        sprintf(cl_default, "%s.%s", filepath, exts[i]);
        if (access(cl_default, F_OK) ==0) {
            if (verbose) fprintf(stderr, "find chunklist: %s", cl_default);
            return cnkl_check(cl_default, filepath, verbose);
        }
    }
    
    fprintf(stderr, "Error: failure to find matching chunklist file");
    return 5;
}
