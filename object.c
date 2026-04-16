// object.c — Content-addressable object store

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <errno.h>

// ─── Utility Functions ───────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++)
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

// ─── Object Path Helpers ─────────────────────────────────────────────────────

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/objects/%.2s/%s", PES_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[300];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0 ? 1 : 0;
}

// ─── object_write ────────────────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // Step 1: determine type string
    const char *type_str;
    switch (type) {
        case OBJ_BLOB:   type_str = "blob";   break;
        case OBJ_TREE:   type_str = "tree";   break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // Step 2: build full object = "type size\0data"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);

    size_t full_len = (size_t)header_len + 1 + len;
    unsigned char *full_obj = malloc(full_len);
    if (!full_obj) return -1;

    memcpy(full_obj, header, header_len);
    full_obj[header_len] = '\0';
    memcpy(full_obj + header_len + 1, data, len);

    // Step 3: compute SHA-256
    ObjectID id;
    SHA256(full_obj, full_len, id.hash);

    // Step 4: fill id_out
    if (id_out) *id_out = id;

    // Step 5: build paths
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&id, hex);

    char dir_path[256], obj_path[300];
    snprintf(dir_path, sizeof(dir_path), "%s/objects/%.2s", PES_DIR, hex);
    snprintf(obj_path, sizeof(obj_path), "%s/objects/%.2s/%s", PES_DIR, hex, hex + 2);

    // Step 6: deduplication
    if (access(obj_path, F_OK) == 0) {
        free(full_obj);
        return 0;
    }

    // Step 7: ensure directories exist
    mkdir(PES_DIR, 0755);
    mkdir(OBJECTS_DIR, 0755);
    if (mkdir(dir_path, 0755) < 0 && errno != EEXIST) {
        free(full_obj);
        return -1;
    }

    // Step 8: write to temp file then rename atomically
    char tmp_path[320];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", obj_path);

    int fd = mkstemp(tmp_path);
    if (fd < 0) { free(full_obj); return -1; }

    ssize_t written = 0;
    while ((size_t)written < full_len) {
        ssize_t w = write(fd, full_obj + written, full_len - written);
        if (w <= 0) {
            close(fd); unlink(tmp_path); free(full_obj); return -1;
        }
        written += w;
    }

    fsync(fd);
    close(fd);
    free(full_obj);

    if (rename(tmp_path, obj_path) < 0) {
        unlink(tmp_path);
        return -1;
    }

    return 0;
}

// ─── object_read ─────────────────────────────────────────────────────────────

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // Step 1: build path
    char obj_path[300];
    object_path(id, obj_path, sizeof(obj_path));

    // Step 2: read entire file
    FILE *f = fopen(obj_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);
    if (file_size < 0) { fclose(f); return -1; }

    unsigned char *buf = malloc((size_t)file_size);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, (size_t)file_size, f) != (size_t)file_size) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);

    // Step 3: integrity check
    ObjectID computed;
    SHA256(buf, (size_t)file_size, computed.hash);

    char computed_hex[HASH_HEX_SIZE + 1];
    char expected_hex[HASH_HEX_SIZE + 1];
    hash_to_hex(&computed, computed_hex);
    hash_to_hex(id, expected_hex);

    if (strcmp(computed_hex, expected_hex) != 0) {
        free(buf); return -1;
    }

    // Step 4: find '\0' to split header from data
    unsigned char *null_ptr = memchr(buf, '\0', (size_t)file_size);
    if (!null_ptr) { free(buf); return -1; }

    char type_str[32];
    size_t declared_size;
    if (sscanf((char *)buf, "%31s %zu", type_str, &declared_size) != 2) {
        free(buf); return -1;
    }

    // Step 5: extract data portion
    unsigned char *data_start = null_ptr + 1;
    size_t data_len = (size_t)file_size - (size_t)(data_start - buf);
    if (data_len != declared_size) { free(buf); return -1; }

    // Step 6: fill outputs
    if (type_out) {
        if      (strcmp(type_str, "blob")   == 0) *type_out = OBJ_BLOB;
        else if (strcmp(type_str, "tree")   == 0) *type_out = OBJ_TREE;
        else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
        else { free(buf); return -1; }
    }

    if (data_out) {
        *data_out = malloc(data_len);
        if (!*data_out) { free(buf); return -1; }
        memcpy(*data_out, data_start, data_len);
    }

    if (len_out) *len_out = data_len;

    free(buf);
    return 0;
}
