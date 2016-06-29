/*
 * Working with connection objects, address objects and links between them
 */
#include "tdi_fw.h"

struct _addr_entry **g_addr_list;
KSPIN_LOCK g_addr_list_lock;

struct _conn_entry **g_conn_list;
KSPIN_LOCK g_conn_list_lock;

//----------------------------------------------------------------------------

NTSTATUS
ot_init(void)
{
    // g_addr_list
	g_addr_list = (struct _addr_entry **)malloc_np(sizeof(*g_addr_list) * HASH_SIZE);
	if (g_addr_list == NULL) {
		KdPrint(("~!![tdi_fw] ot_init: malloc_np\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(g_addr_list, 0, sizeof(*g_addr_list) * HASH_SIZE);

	KeInitializeSpinLock(&g_addr_list_lock);

    // g_conn_list
	g_conn_list = (struct _conn_entry **)malloc_np(sizeof(*g_conn_list) * HASH_SIZE);
	if (g_conn_list == NULL) {
		KdPrint(("~!![tdi_fw] ot_init: malloc_np\n"));
		free(g_addr_list);
        g_addr_list = NULL;
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	memset(g_conn_list, 0, sizeof(*g_conn_list) * HASH_SIZE);

	KeInitializeSpinLock(&g_conn_list_lock);

	return STATUS_SUCCESS;
}

void
ot_free(void)
{
    KIRQL irql;
    int i;

    // cleanup g_conn_list
    if (g_conn_list)
    {
        KeAcquireSpinLock(&g_conn_list_lock, &irql);

        for (i = 0; i < HASH_SIZE; i++)
        {
            struct _conn_entry *ce = g_conn_list[i];
            struct _conn_entry *ce2;
            while (ce)
            {
                ce2 = ce->next;
                free(ce);
                ce = ce2;
            }
        }
        free(g_conn_list);
        g_conn_list = NULL;

        KeReleaseSpinLock(&g_conn_list_lock, irql);
    }

	// cleanup g_addr_list
    if (g_addr_list)
    {
        KeAcquireSpinLock(&g_addr_list_lock, &irql);

        for (i = 0; i < HASH_SIZE; i++)
        {
            struct _addr_entry *ae = g_addr_list[i];
            struct _addr_entry *ae2;
            while (ae)
            {
                ae2 = ae->next;
                free(ae);
                ae = ae2;
            }
        }
        free(g_addr_list);
        g_addr_list = NULL;

        KeReleaseSpinLock(&g_addr_list_lock, irql);
    }
}

//----------------------------------------------------------------------------

NTSTATUS
add_addrobj(PFILE_OBJECT addrobj,
               PDEVICE_OBJECT fltdevobj,
               PDEVICE_OBJECT olddevobj,
               int ipproto)
{
    NTSTATUS status = STATUS_SUCCESS;
    //
	ULONG hash = CALC_HASH(addrobj);
	KIRQL irql;
	struct _addr_entry *ae;

	if (addrobj == NULL)
		return STATUS_INVALID_PARAMETER_1;

	KeAcquireSpinLock(&g_addr_list_lock, &irql);
	
	for (ae = g_addr_list[hash]; ae != NULL; ae = ae->next)
		if (ae->addrobj == addrobj)
        {
            KdPrint(("~!![tdi_fw] add_addrobj: reuse addrobj 0x%x\n", addrobj));
            break;
        }

	if (ae == NULL)
    {
		ae = (struct _addr_entry *)malloc_np(sizeof(*ae));
		if (ae == NULL) {
            KdPrint(("~!![tdi_fw] ot_add_fileobj: malloc_np()!\n"));
			status = STATUS_INSUFFICIENT_RESOURCES;
			goto done;
		}
		memset(ae, 0, sizeof(*ae));

		ae->next = g_addr_list[hash];
		g_addr_list[hash] = ae;

		ae->addrobj = addrobj;
	}

	ae->pid    = (ULONG)PsGetCurrentProcessId();
    ae->tid    = (ULONG)PsGetCurrentThreadId();
	ae->fltdevobj = fltdevobj;
    ae->olddevobj = olddevobj;
	ae->ipproto = ipproto;

done:  // cleanup
	KeReleaseSpinLock(&g_addr_list_lock, irql);
	return status;
}

//------------------------------------------
// if fail, return NULL
// if return ote != NULL, need KeReleaseSpinLock(&g_ot_hash_lock, *irql);
//------------------------------------------
struct _addr_entry *
find_addr_entry(PFILE_OBJECT addrobj, KIRQL *irql)
{
	struct _addr_entry *ae;
    ULONG hash = CALC_HASH(addrobj);

	if (addrobj == NULL)
		return NULL;

	KeAcquireSpinLock(&g_addr_list_lock, irql);

	for (ae = g_addr_list[hash]; ae != NULL; ae = ae->next)
		if (ae->addrobj == addrobj)
			break;

	if (ae == NULL)
    {
		KdPrint(("~![tdi_fw] find_addr_entry: fileobj 0x%x not found!\n", addrobj));
		KeReleaseSpinLock(&g_addr_list_lock, *irql);
	}

	return ae;
}


VOID del_addr_entry(PFILE_OBJECT addrobj)
{
    ULONG hash = CALC_HASH(addrobj);
    KIRQL irql;
    struct _addr_entry *ae, *prev_ae = NULL;

    if (addrobj == NULL)
        return;

    KeAcquireSpinLock(&g_addr_list_lock, &irql);

    for (ae = g_addr_list[hash]; ae; ae = ae->next)
    {
        if (ae->addrobj == addrobj)
            break;
        prev_ae = ae;
    }

    if (ae)
    {
        if (prev_ae != NULL)
            prev_ae->next = ae->next;
        else
            g_addr_list[hash] = ae->next;

        free(ae);
    }

    KeReleaseSpinLock(&g_addr_list_lock, irql);
}
//----------------------------------------------------------------------------

NTSTATUS
add_connobj(PFILE_OBJECT connobj, CONNECTION_CONTEXT conn_ctx)
{
    NTSTATUS status = STATUS_SUCCESS;
    //
    ULONG hash = CALC_HASH(connobj);
    KIRQL irql;
    struct _conn_entry *ce;

    if (connobj == NULL)
        return STATUS_INVALID_PARAMETER_1;

    KeAcquireSpinLock(&g_conn_list_lock, &irql);

    for (ce = g_conn_list[hash]; ce != NULL; ce = ce->next)
        if ( ce->connobj == connobj )  // && ce->conn_ctx == conn_ctx
        {
            KdPrint(("~!![tdi_fw] add_connobj: reuse connobj 0x%x\n", connobj));
            break;
        }

    if (ce == NULL)
    {
        ce = (struct _conn_entry *)malloc_np(sizeof(*ce));
        if (ce == NULL) {
            KdPrint(("~!![tdi_fw] add_connobj: malloc_np()!\n"));
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto done;
        }
        memset(ce, 0, sizeof(*ce));

        ce->next = g_conn_list[hash];
        g_conn_list[hash] = ce;

        ce->connobj  = connobj;
    }

    ce->conn_ctx = conn_ctx;

done:  // cleanup
    KeReleaseSpinLock(&g_conn_list_lock, irql);
    return status;
}

struct _conn_entry *
    find_conn_entry(PFILE_OBJECT connobj, KIRQL *irql)  // !if no delete -- g_conn_list_lock
{
    struct _conn_entry *ce;
    ULONG hash = CALC_HASH(connobj);

    if (connobj == NULL)
        return NULL;

    KeAcquireSpinLock(&g_conn_list_lock, irql);

    for (ce = g_conn_list[hash]; ce != NULL; ce = ce->next)
        if (ce->connobj == connobj)
            break;

    if (ce == NULL)
    {
        KdPrint(("~![tdi_fw] find_conn_entry: connobj 0x%x not found!\n", connobj));
        KeReleaseSpinLock(&g_conn_list_lock, *irql);
    }

    return ce;
}

VOID del_conn_entry(PFILE_OBJECT connobj)
{
    struct _conn_entry *ce;
    struct _conn_entry *prev_ce = NULL;
    ULONG hash = CALC_HASH(connobj);
    KIRQL irql;

    if (connobj == NULL)
        return;

    KeAcquireSpinLock(&g_conn_list_lock, &irql);

    for (ce = g_conn_list[hash]; ce != NULL; ce = ce->next)
    {
        if (ce->connobj == connobj)
            break;
        prev_ce = ce;
    }

    if (ce)
    {
        if (prev_ce != NULL)
            prev_ce->next = ce->next;
        else
            g_conn_list[hash] = ce->next;

        free(ce);
    }

    KeReleaseSpinLock(&g_conn_list_lock, irql);
}