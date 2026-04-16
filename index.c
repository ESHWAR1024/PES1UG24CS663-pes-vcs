#include "pes.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* all previous functions (same as above)... */

int index_load(Index *idx) {
    memset(idx, 0, sizeof(Index));

    FILE *f = fopen(".pes/index", "r");
    if (!f) {
        idx->count = 0;
        return 0;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (strlen(line) == 0) continue;

        if (idx->count >= MAX_INDEX_ENTRIES) break;

        IndexEntry *e = &idx->entries[idx->count];

        char mode[16], hash_hex[65];
        long mtime;
        size_t size;
        char path[512];

        int n = sscanf(line, "%15s %64s %ld %zu %511s",
                       mode, hash_hex, &mtime, &size, path);
        if (n != 5) continue;

        strcpy(e->mode, mode);
        strcpy(e->hash_hex, hash_hex);
        e->mtime = mtime;
        e->size = size;
        strcpy(e->path, path);
        idx->count++;
    }

    fclose(f);
    return 0;
}

/* Helper for qsort */
static int entry_path_cmp(const void *a, const void *b) {
    return strcmp(((IndexEntry *)a)->path, ((IndexEntry *)b)->path);
}

/*
 * index_save
 */
int index_save(Index *idx) {
    qsort(idx->entries, idx->count, sizeof(IndexEntry), entry_path_cmp);

    const char *tmp_path = ".pes/index.tmp";
    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    for (int i = 0; i < idx->count; i++) {
        IndexEntry *e = &idx->entries[i];
        fprintf(f, "%s %s %ld %zu %s\n",
                e->mode, e->hash_hex, e->mtime, e->size, e->path);
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (rename(tmp_path, ".pes/index") < 0) {
        unlink(tmp_path);
        return -1;
    }

    return 0;
}
