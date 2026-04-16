#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <errno.h>

/* PROVIDED: converts raw 32-byte hash to 64-char hex string */
void hash_to_hex(const unsigned char *hash, char *hex) {
    for (int i = 0; i < 32; i++)
        sprintf(hex + i * 2, "%02x", hash[i]);
    hex[64] = '\0';
}

/*
 * object_write
 *
 * Stores data in the content-addressable object store.
 *
 * Steps:
 *  1. Build full_object = header + data
 *     header = "<type> <size>\0"   (null byte is PART of the header)
 *     full_object = header || data
 *  2. SHA-256 the full_object  → raw_hash (32 bytes)
 *  3. Convert raw_hash → hex string (64 chars)
 *  4. Build path: ".pes/objects/<hex[0..1]>/<hex[2..63]>"
 *  5. If file already exists at that path, we're done (deduplication)
 *  6. mkdir the two-char shard directory if needed
 *  7. Write to a temp file in that dir, fsync, then rename (atomic)
 *  8. Copy hex into out_hex and return 0 on success, -1 on error
 */
int object_write(const char *type, const unsigned char *data, size_t data_len,
                 char *out_hex) {
    /* Step 1: build header */
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type, data_len);
    /* +1 to include the null byte terminator as part of header */
    size_t full_len = header_len + 1 + data_len;

    unsigned char *full_object = malloc(full_len);
    if (!full_object) return -1;

    memcpy(full_object, header, header_len);
    full_object[header_len] = '\0';  /* null byte separator */
    memcpy(full_object + header_len + 1, data, data_len);

    /* Step 2: SHA-256 */
    unsigned char raw_hash[32];
    SHA256(full_object, full_len, raw_hash);

    /* Step 3: hex string */
    char hex[65];
    hash_to_hex(raw_hash, hex);
    if (out_hex) memcpy(out_hex, hex, 65);

    /* Step 4: build path */
    char dir_path[256], obj_path[256];
    snprintf(dir_path, sizeof(dir_path), ".pes/objects/%.2s", hex);
    snprintf(obj_path, sizeof(obj_path), ".pes/objects/%.2s/%s", hex, hex + 2);

    /* Step 5: deduplication */
    if (access(obj_path, F_OK) == 0) {
        free(full_object);
        return 0;
    }

    /* Step 6: mkdir shard dir */
    mkdir(dir_path, 0755);

    /* Step 7: write to temp file, fsync, rename */
    char tmp_path[300];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", obj_path);
    int fd = mkstemp(tmp_path);
    if (fd < 0) { free(full_object); return -1; }

    ssize_t written = write(fd, full_object, full_len);
    fsync(fd);
    close(fd);
    free(full_object);

    if (written != (ssize_t)full_len) {
        unlink(tmp_path);
        return -1;
    }

    if (rename(tmp_path, obj_path) < 0) {
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

/*
 * object_read
 *
 * Retrieves and verifies data from the object store.
 *
 * Steps:
 *  1. Build path from hex
 *  2. Read entire file into a buffer
 *  3. Recompute SHA-256 of the file contents → verify against hex (integrity)
 *  4. Parse header: find the '\0' byte, extract type string and size
 *  5. Verify the size in header matches actual data size
 *  6. Set *out_type, copy data into *out_data (malloc'd), set *out_len
 *  7. Return 0 on success, -1 on error
 */
int object_read(const char *hex, char *out_type, unsigned char **out_data,
                size_t *out_len) {
    /* Step 1: build path */
    char obj_path[256];
    snprintf(obj_path, sizeof(obj_path), ".pes/objects/%.2s/%s", hex, hex + 2);

    /* Step 2: read entire file */
    FILE *f = fopen(obj_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buf = malloc(file_size);
    if (!buf) { fclose(f); return -1; }
    fread(buf, 1, file_size, f);
    fclose(f);

    /* Step 3: integrity check */
    unsigned char raw_hash[32];
    SHA256(buf, file_size, raw_hash);
    char computed_hex[65];
    hash_to_hex(raw_hash, computed_hex);
    if (strcmp(computed_hex, hex) != 0) {
        free(buf);
        return -1;  /* corrupted */
    }

    /* Step 4: parse header — find null byte */
    unsigned char *null_ptr = memchr(buf, '\0', file_size);
    if (!null_ptr) { free(buf); return -1; }

    /* header is everything before the null byte */
    /* format: "type size" */
    char type_buf[32];
    size_t declared_size;
    if (sscanf((char *)buf, "%31s %zu", type_buf, &declared_size) != 2) {
        free(buf);
        return -1;
    }

    /* Step 5: data starts after null byte */
    unsigned char *data_start = null_ptr + 1;
    size_t data_len = file_size - (data_start - buf);

    if (data_len != declared_size) { free(buf); return -1; }

    /* Step 6: fill outputs */
    if (out_type) strcpy(out_type, type_buf);
    if (out_data) {
        *out_data = malloc(data_len);
        if (!*out_data) { free(buf); return -1; }
        memcpy(*out_data, data_start, data_len);
    }
    if (out_len) *out_len = data_len;

    free(buf);
    return 0;
}
