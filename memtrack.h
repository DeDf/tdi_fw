//===================================

#ifndef _memtrack_h_
#define _memtrack_h_

#if DBG

void	memtrack_init(void);
void	memtrack_free(void);

void	*mt_malloc(ULONG size, const char *file, ULONG line);
#define malloc_np(size)	mt_malloc((size), __FILE__, __LINE__)	
void free(void *ptr);

#else /* DBG */

#define MEM_TAG 'DeDf'

#define memtrack_init()
#define memtrack_free()

#define malloc_np(size)	ExAllocatePoolWithTag(NonPagedPool, (size), MEM_TAG)
#define free(ptr)	ExFreePool(ptr)

#endif /* DBG */

#endif
