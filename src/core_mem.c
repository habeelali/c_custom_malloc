#include "core_mem.h"
#include "utils.h"
#include "config.h"

#include <stdlib.h>

// STATIC GLOBALS TO KEEP TRACK OF MEMORY
static char *memory_start = NULL;
static char *memory_brk = NULL;
static char *memory_max_addr = NULL;
void *stack_btm = NULL;

void getMemoryStatus(void);

// FUNCTION DEFINITIONS
void cm_init_memory(void)
{
    if (memory_start)
    {
        LOG_ERROR("Memory already initialized. Multiple calls to cm_init_memory not allowed. Try removing any cm_init_memory call from your mm_lib sources. EXITING.\n.");
        exit(1);
    }

    if (!(memory_start = (char *)malloc(MAX_HEAP_SIZE)))
    {
        LOG_ERROR("Failed to allocate memory from the system.\n");
        exit(1);
    }

    memory_brk = memory_start;
    memory_max_addr = PTR_ADD(memory_start, MAX_HEAP_SIZE);
    stack_btm = get_stack_btm_ptr();

    LOG_DEBUG("System memory initialied.\n");
    getMemoryStatus();
}

void cm_free_memory(void)
{
    if (!memory_start)
        return;

    free(memory_start);
    memory_start = NULL;
    memory_brk = NULL;
    memory_max_addr = NULL;
}

void *cm_sbrk(size_t incr)
{
    char *old_brk = memory_brk;

    if (memory_start == NULL || memory_max_addr == NULL)
    {
        LOG_ERROR("System memory not initialized.\n");
        return NULL;
    }

    if (((memory_brk + incr) > memory_max_addr))
    {
        LOG_ERROR("Memory limit exceeded.\n");
        return NULL;
    }

    memory_brk += incr;
    return (void *)old_brk;
}

void cm_reset_heap(void)
{
    memory_brk = memory_start;
}

void *cm_heap_start(void)
{
    return (void *)memory_start;
}

void *cm_heap_end(void)
{
    return (void *)(memory_brk);
}

size_t cm_heap_size(void)
{
    return (size_t)(memory_brk - memory_start);
}

void *get_stack_btm_ptr()
{
    FILE *statfp;
    uintptr_t stack_bottom;
    statfp = fopen("/proc/self/stat", "r");
    fscanf(statfp,
           "%*d %*s %*c %*d %*d %*d %*d %*d %*u "
           "%*lu %*lu %*lu %*lu %*lu %*lu %*ld %*ld "
           "%*ld %*ld %*ld %*ld %*llu %*lu %*ld "
           "%*lu %*lu %*lu %lu",
           &stack_bottom);
    fclose(statfp);
    return (void *)stack_bottom;
}

void *get_stack_top_ptr()
{
    void *stack_top;
    asm volatile("movq %%rsp, %0" : "=r"(stack_top)); // For x86_64 architecture
    // asm volatile("mov \%0, sp" : "=r"(stack_top)); // For ARM architecture
    return stack_top;
}

// ----------------------------------------------
// debug stuff
void getMemoryStatus(void)
{
    LOG_DEBUG("Memory start: %p\n", memory_start);
    LOG_DEBUG("Memory brk : %p\n", memory_brk);
    LOG_DEBUG("Memory size : %lu\n", cm_heap_size());
}