#ifndef MM_LIB_H
#define MM_LIB_H

#include <stddef.h>
#include <stdint.h>

#define MM_ALIGNMENT sizeof(void *)

#define ALIGN(size) (((size) + (MM_ALIGNMENT - 1)) & ~(MM_ALIGNMENT - 1))

typedef struct block_header
{
    size_t size;
    int is_free;
    int is_marked;
    struct block_header *next;
} block_header;

void mm_init();
void *mm_malloc(size_t size);
void mm_free(void *ptr);
void *mm_realloc(void *ptr, size_t size);

void mark();
void collect();

#endif
