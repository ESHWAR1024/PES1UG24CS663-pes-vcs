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
 */
int object_write(const char *type, const unsigned char *data, size_t data_len,
                 char *out_hex) {

    /* Step 1: build header */
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type, data_len);

    size_t full_len = header_len + 1 + data_len;

    unsigned char *full_object = malloc(full_len);
    if (!full_object) return -1;

    memcpy(full_object, header, header_len);
    full_object[header_len] = '\0';
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

    /* Step 6: ensure directories exist */
    if (mkdir(".pes", 0755) < 0 && errno != EEXIST) {
        free(full_object);
        return -1;
    }

    if (mkdir(".pes/objects", 0755) < 0 && errno != EEXIST) {
        free(full_object);
        return -1;
    }

    if (mkdir(dir_path, 0755) < 0 && errno != EEXIST) {
        free(full_object);
        return -1;
    }

    /* Step 7: write temp file */
    char tmp_path[300];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", obj_path);

    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        free(full_object);
        return -1;
    }

    /* handle partial writes */
    ssize_t total = 0;
    while (total < (ssize_t)full_len) {
        ssize_t w = write(fd, full_object + total, full_len - total);
        if (w <= 0) {
            close(fd);
            unlink(tmp_path);
            free(full_object);
            return -1;
        }
        total += w;
    }

    fsync(fd);
    close(fd);
    free(full_object);

    if (rename(tmp_path, obj_path) < 0) {
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

/*
 * object_read
 */
int object_read(const char *hex, char *out_type, unsigned char **out_data,
                size_t *out_len) {

    /* Step 1: build path */
    char obj_path[256];
    snprintf(obj_path, sizeof(obj_path), ".pes/objects/%.2s/%s", hex, hex + 2);

    FILE *f = fopen(obj_path, "rb");
    if (!f) return -1;

    /* Step 2: get file size */
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }

    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        return -1;
    }

    rewind(f);

    unsigned char *buf = malloc(file_size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if (fread(buf, 1, file_size, f) != (size_t)file_size) {
        free(buf);
        fclose(f);
        return -1;
    }

    fclose(f);

    /* Step 3: integrity check */
    unsigned char raw_hash[32];
    SHA256(buf, file_size, raw_hash);

    char computed_hex[65];
    hash_to_hex(raw_hash, computed_hex);

    if (strcmp(computed_hex, hex) != 0) {
        free(buf);
        return -1;
    }

    /* Step 4: parse header */
    unsigned char *null_ptr = memchr(buf, '\0', file_size);
    if (!null_ptr) {
        free(buf);
        return -1;
    }

    char type_buf[32];
    size_t declared_size;

    if (sscanf((char *)buf, "%31s %zu", type_buf, &declared_size) != 2) {
        free(buf);
        return -1;
    }

    /* Step 5: extract data */
    unsigned char *data_start = null_ptr + 1;
    size_t data_len = file_size - (data_start - buf);

    if (data_len != declared_size) {
        free(buf);
        return -1;
    }

    /* Step 6: output */
    if (out_type) strcpy(out_type, type_buf);

    if (out_data) {
        *out_data = malloc(data_len);
        if (!*out_data) {
            free(buf);
            return -1;
        }
        memcpy(*out_data, data_start, data_len);
    }

    if (out_len) *out_len = data_len;

    free(buf);
    return 0;
}
