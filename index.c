#include "pes.h"
#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

/* PROVIDED: find an entry in the index by path, returns index or -1 */
int index_find(Index *idx, const char *path) {
    for (int i = 0; i < idx->count; i++) {
        if (strcmp(idx->entries[i].path, path) == 0)
            return i;
    }
    return -1;
}

/* PROVIDED: remove an entry from the index by path */
void index_remove(Index *idx, const char *path) {
    int pos = index_find(idx, path);
    if (pos < 0) return;
    /* shift remaining entries left */
    memmove(&idx->entries[pos], &idx->entries[pos + 1],
            (idx->count - pos - 1) * sizeof(IndexEntry));
    idx->count--;
}

/* PROVIDED: compare working file stat against index entry */
/* Returns 1 if file is modified vs index, 0 if same */
int index_status(Index *idx, const char *path) {
    int pos = index_find(idx, path);
    if (pos < 0) return 1;  /* not tracked = untracked/modified */

    struct stat st;
    if (stat(path, &st) < 0) return 1;  /* file deleted */

    IndexEntry *e = &idx->entries[pos];
    if ((long)st.st_mtime != e->mtime) return 1;
    if ((size_t)st.st_size != e->size) return 1;
    return 0;
}

/*
 * index_load
 */
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
