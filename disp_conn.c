/*
 * This file contains TDI_CONNECT & TDI_DISCONNECT handlers
 */
#include "tdi_fw.h"

struct _connobj_request_localaddr {
	PFILE_OBJECT	connobj;
    flt_request     *pRequest;
	char			address[];
};

void update_conn_info(PDEVICE_OBJECT devobj, PFILE_OBJECT connobj, flt_request *pRequest);
NTSTATUS	update_conn_info_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);
NTSTATUS	tdi_connect_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);
NTSTATUS    set_tcp_conn_localaddr(PFILE_OBJECT connobj, TA_ADDRESS *local);

//----------------------------------------------------------------------------
/*
 * TDI_CONNECT handler
 */

int
tdi_connect(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
    int result = FILTER_DENY;
    //
	PTDI_REQUEST_KERNEL_CONNECT param = (PTDI_REQUEST_KERNEL_CONNECT)(&irps->Parameters);
	TA_ADDRESS *remote_addr = ((TRANSPORT_ADDRESS *)(param->RequestConnectionInformation->RemoteAddress))->Address;
    TA_ADDRESS *local_addr;
	//
    struct _conn_entry *ce;
	struct _addr_entry *ae = NULL;
    //
    int ipproto;
	KIRQL irql;
	flt_request *r;
	struct _flt_rule rule;

    get_original_devobj(irps->DeviceObject, &ipproto);
	
	if (ipproto == IPPROTO_TCP)
    {
        ce = find_conn_entry(irps->FileObject, &irql);
        if (ce == NULL) {
            KdPrint(("~![tdi_fw] tdi_connect: find_conn_entry(0x%x)!\n", irps->FileObject));
            return FILTER_ALLOW;
        }

        ae = ce->addr_entry;
        KeReleaseSpinLockFromDpcLevel(&g_conn_list_lock);
        KeAcquireSpinLockAtDpcLevel(&g_addr_list_lock);

        //----------·ÅÐÐ----------
        if (ae == NULL)
        {
            KeReleaseSpinLock(&g_addr_list_lock, irql);
            return FILTER_ALLOW;
        }
        //------------------------
	}
    else if (ipproto == IPPROTO_UDP)  // For UDP: connobj and addrobj are the same
    {
        ae = find_addr_entry(irps->FileObject, &irql);
	}
    else
        KdPrint(("~![tdi_fw] tdi_connect: unsupport proto: %d!\n", ipproto));

    if (ae == NULL)
        return FILTER_ALLOW;

	local_addr = (TA_ADDRESS *)(ae->local_addr);

	// sanity check
	if (local_addr->AddressLength != remote_addr->AddressLength) {
		KdPrint(("~![tdi_fw] tdi_connect: different addr lengths! (%u != %u)\n",
			local_addr->AddressLength, remote_addr->AddressLength));

        irp->IoStatus.Status = STATUS_REMOTE_NOT_LISTENING;
		goto done;
	}

    KdPrint(("[tdi_fw] tdi_connect: (pid:%u/%u) FileObj 0x%x: %x:%u -> %x:%u (ipproto = %d)\n",
		ae->pid, PsGetCurrentProcessId(),
        irps->FileObject,
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port), ipproto));
	
	//* Call quick_filter
	r = malloc_np(sizeof(flt_request));
    if (r == NULL) {
        KdPrint(("~!![tdi_fw] tdi_connect: malloc_np\n"));
        goto done;
    }
    memset(r, 0, sizeof(flt_request));

	r->tcp_conn_state = TYPE_CONNECT;
	r->direction = DIRECTION_OUT;
	r->proto = ipproto;
	// don't use ote_conn->pid because one process can create connection object but another one can connect
	r->pid = (ULONG)PsGetCurrentProcessId();
	r->tid = (ULONG)PsGetCurrentThreadId();
	memcpy(&r->addr.from, &local_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&r->addr.to,  &remote_addr->AddressType, sizeof(struct sockaddr));

    KeReleaseSpinLock(&g_addr_list_lock, irql);
    ae = NULL;

	result = quick_filter(r, &rule);	

	if (g_LogEnable)
    {
        if ( ipproto != IPPROTO_TCP || result != FILTER_ALLOW )
        {
            InsertRequestList(r);
        }
        else
        {
            // set completion to add connection info to connection table
            completion->routine = tdi_connect_complete;
            completion->context = r;
        }
    }
    else
        free(r);

done:
    if (ae)
        KeReleaseSpinLock(&g_addr_list_lock, irql);
    if (result != FILTER_ALLOW)
		irp->IoStatus.Status = STATUS_REMOTE_NOT_LISTENING;	 // set fake status

	return result;
}

NTSTATUS
tdi_connect_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	NTSTATUS status;
    PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	flt_request *r = (flt_request *)Context;

	if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        struct _get_localaddr_workitem_param *param =
            (struct _get_localaddr_workitem_param *)malloc_np(sizeof(*param));

        if (param != NULL)
        {
            memset(param, 0, sizeof(*param));

            param->devobj  = DeviceObject;
            param->fileobj = irps->FileObject;
            param->pRequest = r;

            KdPrint(("[tdi_fw] tdi_connect_complete: connobj 0x%x\n", irps->FileObject));

            ExInitializeWorkItem(&param->WorkItem, get_localaddr_workitem, param);
            ExQueueWorkItem(&param->WorkItem, DelayedWorkQueue);	// DelayedWorkQueue a good value?

        }
        else  // so we'll live without known local address :-(
        {
            KdPrint(("~!![tdi_fw] tdi_connect_complete: malloc_np!\n"));
            if (r)
                free(r);
        }
	}
    else
    {
        KdPrint(("~![tdi_fw] tdi_connect_complete: status 0x%x\n", Irp->IoStatus.Status));

		if (r != NULL)
        {
			switch (Irp->IoStatus.Status)
            {		// are status codes correct?
			case STATUS_CONNECTION_REFUSED:
			case STATUS_CONNECTION_RESET:
				r->tcp_conn_state = TYPE_CONNECT_RESET;
				break;
			case STATUS_CONNECTION_ABORTED:
			case STATUS_CANCELLED:
				r->tcp_conn_state = TYPE_CONNECT_CANCELED;
				break;
			case STATUS_IO_TIMEOUT:
				r->tcp_conn_state = TYPE_CONNECT_TIMEOUT;
				break;
			case STATUS_NETWORK_UNREACHABLE:
			case STATUS_HOST_UNREACHABLE:
			case STATUS_PROTOCOL_UNREACHABLE:
			case STATUS_PORT_UNREACHABLE:
				r->tcp_conn_state = TYPE_CONNECT_UNREACH;
				break;
			default:
				r->tcp_conn_state = TYPE_CONNECT_ERROR;
			}

            InsertRequestList(r);
		}

		del_conn_entry(irps->FileObject);
	}

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    return STATUS_SUCCESS;
}

void
get_localaddr_workitem(PVOID p)
{
	struct _get_localaddr_workitem_param *param = (struct _get_localaddr_workitem_param *)p;

	update_conn_info(param->devobj, param->fileobj, param->pRequest);
	
	free(param);
}

/* query local address and port for connection */
void
update_conn_info(PDEVICE_OBJECT devobj, PFILE_OBJECT connobj, flt_request *pRequest)
{
	PIRP query_irp;
	PMDL mdl = NULL;
	struct _connobj_request_localaddr *param = NULL;

	query_irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, devobj, connobj, NULL, NULL);
	if (query_irp == NULL) {
		KdPrint(("~![tdi_fw] update_conn_info: TdiBuildInternalDeviceControlIrp!\n"));
		goto done;
	}

	param = (struct _connobj_request_localaddr *)malloc_np(sizeof(*param) + TDI_ADDRESS_INFO_MAX);
	if (param == NULL) {
		KdPrint(("~![tdi_fw] update_conn_info: malloc_np!\n"));
		goto done;
	}

	memset(param, 0, sizeof(*param) + TDI_ADDRESS_INFO_MAX);
	param->connobj = connobj;
    param->pRequest = pRequest;

	mdl = IoAllocateMdl(param->address, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		KdPrint(("~![tdi_fw] update_conn_info: IoAllocateMdl!\n"));
		goto done;
	}
	MmBuildMdlForNonPagedPool(mdl);

	TdiBuildQueryInformation(query_irp, devobj, connobj,
		update_conn_info_complete, param,
		TDI_QUERY_ADDRESS_INFO, mdl);

	IoCallDriver(devobj, query_irp);

	query_irp = NULL;
	mdl = NULL;
	param = NULL;

done:  // cleanup

    if (param)
    {
        if (param->pRequest)
            free(pRequest);
    }
	
	if (mdl != NULL)
		IoFreeMdl(mdl);
	if (param != NULL)
		ExFreePool(param);
	if (query_irp != NULL)
		IoCompleteRequest(query_irp, IO_NO_INCREMENT);
}

NTSTATUS
update_conn_info_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
    NTSTATUS status;
	struct _connobj_request_localaddr *param = (struct _connobj_request_localaddr *)Context;
	TA_ADDRESS *addr = ((TDI_ADDRESS_INFO *)(param->address))->Address.Address;

	status = set_tcp_conn_localaddr(param->connobj, addr);
	if (status != STATUS_SUCCESS)
		KdPrint(("~![tdi_fw] update_conn_info_complete: set_tcp_conn_local: 0x%x!\n", status));
    else
        if (param->pRequest)
        {
            ((struct sockaddr_in*)&param->pRequest->addr.from)->sin_addr.s_addr
                = ((TDI_ADDRESS_IP *)(addr->Address))->in_addr;
            ((struct sockaddr_in*)&param->pRequest->addr.from)->sin_port
                = ((TDI_ADDRESS_IP *)(addr->Address))->sin_port;

            InsertRequestList(param->pRequest);
        }

	// cleanup MDL to avoid unlocking pages from NonPaged pool
	if (Irp->MdlAddress != NULL)
    {
		IoFreeMdl(Irp->MdlAddress);
		Irp->MdlAddress = NULL;
	}

	free(param);
	return STATUS_SUCCESS;
}

//----------------------------------------------------------------------------
/*
 * TDI_DISCONNECT handler
 */

int
tdi_disconnect(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
	TDI_REQUEST_KERNEL_DISCONNECT *param = (TDI_REQUEST_KERNEL_DISCONNECT *)(&irps->Parameters);

	KdPrint(("[tdi_fw] tdi_disconnect: connobj 0x%x (flags: 0x%x)\n",
		irps->FileObject,
        param->RequestFlags));

	return FILTER_ALLOW;
}

NTSTATUS
set_tcp_conn_localaddr(PFILE_OBJECT connobj, TA_ADDRESS *local)
{
    NTSTATUS status;
    //
    struct _conn_entry *ce;
    struct _addr_entry *ae = NULL;
    TA_ADDRESS *local_addr;
    KIRQL irql;

    ce = find_conn_entry(connobj, &irql);
    if (ce == NULL) {
        KdPrint(("~![tdi_fw] set_tcp_conn_localaddr: find_conn_entry(0x%x)!\n", connobj));
        status = STATUS_OBJECT_NAME_NOT_FOUND;
        goto done;
    }

    ae = ce->addr_entry;
    KeReleaseSpinLockFromDpcLevel(&g_conn_list_lock);
    KeAcquireSpinLockAtDpcLevel(&g_addr_list_lock);
    
    if (ae == NULL)
    {
        KeReleaseSpinLock(&g_addr_list_lock, irql);
        return STATUS_UNSUCCESSFUL;
    }

    local_addr  = (TA_ADDRESS *)(ae->local_addr);
    ((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr  = ((TDI_ADDRESS_IP *)(local->Address))->in_addr;
    ((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port = ((TDI_ADDRESS_IP *)(local->Address))->sin_port;

    KdPrint(("[tdi_fw] set_tcp_conn_localaddr: got CONNECT LOCAL %x:%u\n",
        ((TDI_ADDRESS_IP *)(local->Address))->in_addr,
        ntohs(((TDI_ADDRESS_IP *)(local->Address))->sin_port)));

    status = STATUS_SUCCESS;

done:
    if (ae)
        KeReleaseSpinLock(&g_addr_list_lock, irql);

    return status;
}