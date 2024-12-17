#include "mm_lib.h"
#include "core_mem.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static block_header *free_list = NULL;

void mm_init()
{
    free_list = NULL;
}

void mark()
{
    void *stack_top = get_stack_top_ptr();
    void *stack_bottom = get_stack_btm_ptr();

    uintptr_t *ptr = (uintptr_t *)stack_top;
    uintptr_t *end = (uintptr_t *)stack_bottom;

    while (ptr >= end)
    {
        uintptr_t address = *ptr;

        block_header *current = free_list;
        while (current)
        {
            if (!current->is_free &&
                (uintptr_t)current <= address &&
                address < (uintptr_t)((char *)current + current->size + sizeof(block_header)))
            {
                current->is_marked = 1;
            }
            current = current->next;
        }
        ptr--;
    }
}

void collect()
{
    block_header *current = free_list;
    block_header *prev = NULL;

    while (current)
    {
        if (!current->is_marked && current->is_free == 0)
        {

            current->is_free = 1;

            if (prev && prev->is_free)
            {
                prev->size += sizeof(block_header) + current->size;
                prev->next = current->next;
            }
            else
            {
                prev = current;
            }
        }
        else
        {

            current->is_marked = 0;
            prev = current;
        }
        current = current->next;
    }
}

void split_block(block_header *block, size_t size)
{
    size_t total_size = ALIGN(size) + sizeof(block_header);
    if (block->size >= total_size + sizeof(block_header))
    {
        block_header *new_block = (block_header *)((char *)block + total_size);
        new_block->size = block->size - total_size;
        new_block->is_free = 1;
        new_block->next = block->next;

        block->size = size;
        block->next = new_block;
    }
}

void *mm_malloc(size_t size)
{
    char *garbage_string = getenv("GARBAGE_COLLECT");
    if (garbage_string)
    {
        mark();
        collect();
    }

    size = ALIGN(size);

    block_header *current = free_list;
    block_header *prev = NULL;
    block_header *best_block = NULL;
    block_header *best_prev = NULL;

    char *search_scheme = getenv("SEARCH_SCHEME");

    if (search_scheme && strcmp(search_scheme, "WORST_FIT") == 0)
    {

        size_t max_size = 0;
        while (current)
        {
            if (current->is_free && current->size >= size && current->size > max_size)
            {
                max_size = current->size;
                best_block = current;
                best_prev = prev;
            }
            prev = current;
            current = current->next;
        }
    }
    else if (search_scheme && strcmp(search_scheme, "BEST_FIT") == 0)
    {

        size_t min_size = SIZE_MAX;
        while (current)
        {
            if (current->is_free && current->size >= size && current->size < min_size)
            {
                min_size = current->size;
                best_block = current;
                best_prev = prev;
            }
            prev = current;
            current = current->next;
        }
    }
    else
    {

        while (current)
        {
            if (current->is_free && current->size >= size)
            {
                best_block = current;
                best_prev = prev;
                break;
            }
            prev = current;
            current = current->next;
        }
    }

    if (!best_block)
    {

        size_t total_size = size + sizeof(block_header);
        best_block = (block_header *)cm_sbrk(total_size);
        if (!best_block)
        {

            return NULL;
        }
        best_block->size = size;
        best_block->is_free = 0;
        best_block->next = NULL;

        return (void *)((char *)best_block + sizeof(block_header));
    }

    if (best_prev)
    {
        best_prev->next = best_block->next;
    }
    else
    {
        free_list = best_block->next;
    }

    best_block->is_free = 0;

    return (void *)((char *)best_block + sizeof(block_header));
}

void mm_free(void *ptr)
{
    if (!ptr)
        return;

    block_header *block = (block_header *)((char *)ptr - sizeof(block_header));
    block->is_free = 1;

    if (!free_list || block < free_list)
    {
        block->next = free_list;
        free_list = block;
    }
    else
    {
        block_header *current = free_list;
        while (current->next && current->next < block)
        {
            current = current->next;
        }
        block->next = current->next;
        current->next = block;
    }

    block_header *current = free_list;
    while (current && current->next)
    {
        if ((char *)current + sizeof(block_header) + current->size == (char *)current->next)
        {

            current->size += sizeof(block_header) + current->next->size;
            current->next = current->next->next;
        }
        else
        {
            current = current->next;
        }
    }
}

void *mm_realloc(void *ptr, size_t size)
{
    if (!ptr)
        return mm_malloc(size);
    if (size == 0)
    {
        mm_free(ptr);
        return NULL;
    }

    block_header *block = (block_header *)((char *)ptr - sizeof(block_header));
    if (block->size >= size)
        return ptr;

    void *new_ptr = mm_malloc(size);
    if (new_ptr)
    {
        memcpy(new_ptr, ptr, block->size);
        mm_free(ptr);
    }
    return new_ptr;
}
