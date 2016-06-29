//====================================================
/*
 * Debug NonPaged pool routines (helpers to find memory leaks and pool corruption)
 */

#if DBG

#include <ntddk.h>

#include "memtrack.h"

KSPIN_LOCK mem_lock;
ULONG count;

struct prefix {
	struct		prefix *next;
	struct		prefix *prev;
	ULONG		size;
	const char	*file;
	ULONG		line;
};

static struct prefix *first, *last;

void
memtrack_init()
{
	KeInitializeSpinLock(&mem_lock);
}

void
memtrack_free()
{
	KIRQL irql;
    struct prefix *p;
	ULONG total = 0;

	KeAcquireSpinLock(&mem_lock, &irql);
		
    for (p = first; p; p = p->next)
    {
        KdPrint(("!!! memtrack: memory leak detected! %s:%u (%u bytes)\n",
            p->file, p->line, p->size));

        total += p->size;
    }

	KeReleaseSpinLock(&mem_lock, irql);

	KdPrint(("memtrack: Total memory leakage: %u bytes (%u blocks)\n\n", total, count));

	if (total)
        __debugbreak();
}

void *
mt_malloc(ULONG size, const char *file, ULONG line)
{
	KIRQL irql;
	struct prefix *p;

	if (size == 0)
    {
		KdPrint(("memtrack: mt_malloc: size == 0!\n"));
		return NULL;
	}

	p = (struct prefix *)ExAllocatePool(
        NonPagedPool,
		sizeof(struct prefix) + size);

	if (p == NULL)
		return NULL;

    p->prev = NULL;
	p->next = NULL;
	p->size = size;
	p->file = file;
	p->line = line;

	KeAcquireSpinLock(&mem_lock, &irql);
	
	if (last)
    {
		last->next = p;
		p->prev = last;
		last = p;
	}
	else
    {
		first = last = p;
	}
	count++;

	KeReleaseSpinLock(&mem_lock, irql);

	return (char*)p + sizeof(struct prefix);
}

void
free(void *ptr)
{
	KIRQL irql;
    struct prefix *p = (struct prefix *)( (char*)ptr - sizeof(struct prefix) );

	KeAcquireSpinLock(&mem_lock, &irql);

    if (p->prev)
        p->prev->next = p->next;
    else
        first = p->next;

    if (p->next)
        p->next->prev = p->prev;
    else
        last = p->prev;

    count--;
	
	KeReleaseSpinLock(&mem_lock, irql);

    ExFreePool(p);
}

#endif /* DBG */
