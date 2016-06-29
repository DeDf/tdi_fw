/*
 * Filtering related routines
 */
#include "tdi_fw.h"

/* rules chains (main (first entry) and process-related) */
static struct _G_RULES{
	struct {
		struct		_flt_rule *head;
		struct		_flt_rule *tail;
		char		*pname;				// name of process
		BOOLEAN		active;				// filter chain is active
	} chain[MAX_CHAINS_COUNT];
	KSPIN_LOCK	lock;
} g_rules;

// init
NTSTATUS
filter_init(void)
{
	NTSTATUS status;
	int i;

	/* rules chain */
	
	KeInitializeSpinLock(&g_rules.lock);

	for (i = 0; i < MAX_CHAINS_COUNT; i++) {
		g_rules.chain[i].head = g_rules.chain[i].tail = NULL;
		g_rules.chain[i].pname = NULL;
		g_rules.chain[i].active = FALSE;
	}

	return STATUS_SUCCESS;
}

// free
void
filter_free(void)
{
	int i;

	// clear all chains
	for (i = 0; i < MAX_CHAINS_COUNT; i++)
		clear_flt_chain(i);
}

// quick filter (I mean "synchronous" (can work at DISPATCH_LEVEL))
int
quick_filter(flt_request *request, OUT struct _flt_rule *rule)
{
    int result = FILTER_DENY;
    //
	struct _flt_rule *r;
    const struct sockaddr_in *from = (const struct sockaddr_in *)&request->addr.from;
    const struct sockaddr_in *to   = (const struct sockaddr_in *)&request->addr.to;

    if (g_NET_DENY)
        return FILTER_DENY;

    if (g_FltEnable == FALSE)
        return FILTER_ALLOW;
    
	// not IP
    if (request->addr.from.sa_family != AF_INET ||
        request->addr.to.sa_family   != AF_INET)
    {
		KdPrint(("~![tdi_fw] quick_filter: not ip addr!\n"));
        return result;
    } 

	// go through rules
	for (r = g_rules.chain->head; r != NULL; r = r->next)
		// Can anybody understand it?
		if ( (r->proto == IPPROTO_ANY || r->proto == request->proto) &&
			 (r->direction == DIRECTION_ANY || r->direction == request->direction) &&
             ( (request->direction == DIRECTION_IN  && from->sin_port == r->port_from) ||
               (request->direction == DIRECTION_OUT && to->sin_addr.s_addr == r->addr_to) ) )
		{
			result = r->result;
			KdPrint(("[tdi_fw] quick_filter: found rule with result: %d\n", result));
			
			if (rule != NULL)
				memcpy(rule, r, sizeof(*rule));

			break;
		}

	request->flt_result = result;
	return result;
}

// add rule to rules chain
NTSTATUS
add_flt_rule(int chain, const struct _flt_rule *rule)
{
	NTSTATUS status;
	struct _flt_rule *new_rule;
	KIRQL irql;

	// sanity check
	if (chain < 0 || chain >= MAX_CHAINS_COUNT)
		return STATUS_INVALID_PARAMETER_1;
	
	KeAcquireSpinLock(&g_rules.lock, &irql);

	new_rule = (struct _flt_rule *)malloc_np(sizeof(struct _flt_rule));
	if (new_rule == NULL) {
		KdPrint(("[tdi_fw] add_flt_rule: malloc_np\n"));
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	memcpy(new_rule, rule, sizeof(*new_rule));

	// append
	new_rule->next = NULL;

	if (g_rules.chain[chain].tail == NULL) {
		g_rules.chain[chain].head = new_rule;
		g_rules.chain[chain].tail = new_rule;
	} else {
		g_rules.chain[chain].tail->next = new_rule;
		g_rules.chain[chain].tail = new_rule;
	}

	status = STATUS_SUCCESS;

done:
	KeReleaseSpinLock(&g_rules.lock, irql);
	return status;
}

// clear rules chain
NTSTATUS
clear_flt_chain(int chain)
{
	struct _flt_rule *rule;
	KIRQL irql;

	// sanity check
	if (chain < 0 || chain >= MAX_CHAINS_COUNT)
		return STATUS_INVALID_PARAMETER_1;
	
	/* rules chain */
	KeAcquireSpinLock(&g_rules.lock, &irql);

	for (rule = g_rules.chain[chain].head; rule != NULL;) {
		struct _flt_rule *rule2 = rule->next;
		free(rule);
		rule = rule2;
	}

	g_rules.chain[chain].head = NULL;
	g_rules.chain[chain].tail = NULL;

	if (g_rules.chain[chain].pname != NULL) {
		free(g_rules.chain[chain].pname);
		g_rules.chain[chain].pname = NULL;
	}

	// deactivate chain
	g_rules.chain[chain].active = FALSE;

	KeReleaseSpinLock(&g_rules.lock, irql);
	return STATUS_SUCCESS;
}

// set process name for chain
NTSTATUS
set_chain_pname(int chain, char *pname)
{
	KIRQL irql;
	NTSTATUS status;

	// sanity check
	if (chain < 0 || chain >= MAX_CHAINS_COUNT)
		return STATUS_INVALID_PARAMETER_1;

	KdPrint(("[tdi_fw] set_chain_pname: setting name %s for chain %d\n", pname, chain));

	KeAcquireSpinLock(&g_rules.lock, &irql);

	if (g_rules.chain[chain].pname != NULL)
		free(g_rules.chain[chain].pname);

	g_rules.chain[chain].pname = (char *)malloc_np(strlen(pname) + 1);
	if (g_rules.chain[chain].pname != NULL) {
		// copy pname
		strcpy(g_rules.chain[chain].pname, pname);
		status = STATUS_SUCCESS;
	} else
		status = STATUS_INSUFFICIENT_RESOURCES;

	KeReleaseSpinLock(&g_rules.lock, irql);
	return status;
}

// set result of process name by pid resolving
NTSTATUS
set_pid_pname(ULONG pid, char *pname)
{
	KIRQL irql;
	int i, chain = 0;

	KdPrint(("[tdi_fw] set_pid_pname: setting pname %s for pid %u\n", pname, pid));
	
	KeAcquireSpinLock(&g_rules.lock, &irql);
	for (i = 0; i < MAX_CHAINS_COUNT; i++)
		if (g_rules.chain[i].pname != NULL &&
			_stricmp(pname, g_rules.chain[i].pname) == 0) {
	
			KdPrint(("[tdi_fw] set_pid_pname: found chain %d\n", i));
			chain = i;

			break;
		}
	KeReleaseSpinLock(&g_rules.lock, irql);

	return STATUS_SUCCESS;
}

// activate rules chain
NTSTATUS
activate_flt_chain(int chain)
{
	// sanity check
	if (chain < 0 || chain >= MAX_CHAINS_COUNT)
		return STATUS_INVALID_PARAMETER_1;

	g_rules.chain[chain].active = TRUE;

	return STATUS_SUCCESS;
}

VOID
InsertRequestList(flt_request *r)
{
    //KdPrint(("[tdi_fw] InsertRequestList request: 0x%x\n", r));

    ExInterlockedInsertTailList(
        &request_list_head,
        (PLIST_ENTRY)r,
        &request_list_lock
        );

    if ( InterlockedIncrement(&g_request_count) == 1000 )
    {
        flt_request *request;
        do
        {
            ULONG i = 100;

            while (i--)
            {
                request = 
                    (flt_request *)ExInterlockedRemoveHeadList(&request_list_head, &request_list_lock);

                if (request)
                    free(request);
                else
                    break;
            }

            if ( InterlockedExchangeAdd(&g_request_count, i - 100) < 1100 - i )
                break;

        } while (1);
    }

    KeSetEvent(&g_request_event, 0, FALSE);
}