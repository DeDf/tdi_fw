/*
 * This file contains TDI_SEND_DATAGRAM, TDI_RECEIVE_DATAGRAM and TDI_EVENT_RECEIVE_DATAGRAM handlers
 */
#include "tdi_fw.h"

NTSTATUS tdi_receive_datagram_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

//----------------------------------------------------------------------------
/*
 * TDI_SEND_DATAGRAM handler
 */

int
tdi_send_datagram(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
    int result = FILTER_DENY;
    //
    TDI_REQUEST_KERNEL_SENDDG *param = (TDI_REQUEST_KERNEL_SENDDG *)(&irps->Parameters);
    TA_ADDRESS *local_addr, *remote_addr;
    struct _addr_entry *ae;
    KIRQL irql;
    int ipproto;
    flt_request *r;
    struct _flt_rule rule;

    // check device object: UDP or RawIP
    if (get_original_devobj(irps->DeviceObject, &ipproto) == NULL ||
        (ipproto != IPPROTO_UDP && ipproto != IPPROTO_IP)) {
            // unknown device object!
            KdPrint(("~![tdi_fw] tdi_send_datagram: unknown DeviceObject 0x%x!\n",
                irps->DeviceObject));
            return result;
    }

    // get local address of address object
    ae = find_addr_entry(irps->FileObject, &irql);
    if (ae == NULL) {
        KdPrint(("~![tdi_fw] tdi_send_datagram: ot_find_fileobj(0x%x)!\n", irps->FileObject));
#if DBG
        // address object was created before driver was started
        result = FILTER_ALLOW;
#endif
        goto done;
    }

    local_addr  = (TA_ADDRESS *)(ae->local_addr);
    remote_addr = ((TRANSPORT_ADDRESS *)(param->SendDatagramInformation->RemoteAddress))->Address;

    KdPrint(("[tdi_fw] tdi_send_datagram(pid:%u/%u): addrobj 0x%x (size: %u) %x:%u -> %x:%u\n",
        ae->pid, PsGetCurrentProcessId(),
        irps->FileObject,
        param->SendLength,
        ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
        ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
        ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
        ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port)));

    //* Call quick_filter
    r = malloc_np(sizeof(flt_request));
    if (r == NULL) {
        KdPrint(("~!![tdi_fw] tdi_send_datagram: malloc_np\n"));
        goto done;
    }
    memset(r, 0, sizeof(flt_request));
    r->direction = DIRECTION_OUT;
    r->proto = ipproto;
    // don't use ae->pid because one process can create address object
    // but another one can send datagram on it
    r->pid = (ULONG)PsGetCurrentProcessId();
    r->tid = (ULONG)PsGetCurrentThreadId();
    
    if (r->pid == 0)  // some NetBT datagrams are sent in context of idle process: avoid it
        r->pid = ae->pid;

    memcpy(&r->addr.from, &local_addr->AddressType, sizeof(struct sockaddr));
    memcpy(&r->addr.to,  &remote_addr->AddressType, sizeof(struct sockaddr));
    r->log_bytes_out = param->SendLength;

    KeReleaseSpinLock(&g_addr_list_lock, irql);
    ae = NULL;

    result = quick_filter(r, &rule);

    if (result == FILTER_ALLOW)
    {
        KeAcquireSpinLock(&g_traffic_lock, &irql);

        g_traffic_out += param->SendLength;

        KeReleaseSpinLock(&g_traffic_lock, irql);
    }

    if (g_LogEnable)
        InsertRequestList(r);
    else
        free(r);

done:
    // cleanup
    if (ae != NULL)
        KeReleaseSpinLock(&g_addr_list_lock, irql);

    if (result == FILTER_DENY)
        irp->IoStatus.Status = STATUS_INVALID_ADDRESS;	// set fake status

    return result;
}

//----------------------------------------------------------------------------
/*
 * TDI_RECEIVE_DATAGRAM handler
 */

int
tdi_receive_datagram(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
	KdPrint(("[tdi_fw] tdi_receive_datagram: addrobj 0x%x\n", irps->FileObject));

	completion->routine = tdi_receive_datagram_complete;

	return FILTER_ALLOW;
}

NTSTATUS
tdi_receive_datagram_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
    int result = FILTER_DENY;
    //
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	TDI_REQUEST_KERNEL_RECEIVEDG *param = (TDI_REQUEST_KERNEL_RECEIVEDG *)(&irps->Parameters);
	PFILE_OBJECT addrobj = irps->FileObject;
	struct _addr_entry *ae = NULL;
	KIRQL irql;
	int ipproto;
	flt_request *r;
	struct _flt_rule rule;
	TA_ADDRESS *local_addr, *remote_addr;

	// check device object: UDP or RawIP
	if (get_original_devobj(DeviceObject, &ipproto) == NULL ||
		(ipproto != IPPROTO_UDP && ipproto != IPPROTO_IP))  // unknown device object!
    {
		KdPrint(("~![tdi_fw] tdi_receive_datagram_complete: unknown DeviceObject 0x%x!\n",
			DeviceObject));
		goto done;
	}

	KdPrint(("[tdi_fw] tdi_receive_datagram_complete: addrobj 0x%x; status 0x%x; information %u\n",
		addrobj, Irp->IoStatus.Status, Irp->IoStatus.Information));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		KdPrint(("~![tdi_fw] tdi_receive_datagram_complete: status 0x%x\n",
			Irp->IoStatus.Status));
		goto done;
	}

	ae = find_addr_entry(addrobj, &irql);
	if (ae == NULL) {
		KdPrint(("~![tdi_fw] tdi_receive_datagram_complete: ot_find_fileobj(0x%x)!\n",
			addrobj));
		goto done;
	}

    //* Call quick_filter
    r = malloc_np(sizeof(flt_request));
    if (r == NULL) {
        KdPrint(("~!![tdi_fw] tdi_receive_datagram_complete: malloc_np\n"));
        goto done;
    }
    memset(r, 0, sizeof(flt_request));
	r->direction = DIRECTION_IN;
	r->proto = ipproto;
	r->pid = ae->pid;

	local_addr  = (TA_ADDRESS *)(ae->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)(param->ReceiveDatagramInformation->RemoteAddress))->Address;

	KdPrint(("[tdi_fw] tdi_receive_datagram_complete(pid:%u): %x:%u -> %x:%u\n",
		ae->pid,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port)));

	memcpy(&r->addr.from, &remote_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&r->addr.to,    &local_addr->AddressType, sizeof(struct sockaddr));

    r->log_bytes_in = Irp->IoStatus.Information;

    KeReleaseSpinLockFromDpcLevel(&g_addr_list_lock);
    ae = NULL;

    KeAcquireSpinLockAtDpcLevel(&g_traffic_lock);

    g_traffic_in += Irp->IoStatus.Information;

    KeReleaseSpinLock(&g_traffic_lock, irql);

	result = quick_filter(r, &rule);

    if (g_LogEnable)
        InsertRequestList(r);
    else
        free(r);

done:
    // cleanup
    if (ae != NULL)
        KeReleaseSpinLock(&g_addr_list_lock, irql);

	if (result == FILTER_DENY)
    {
		if (Irp->IoStatus.Status == STATUS_SUCCESS)
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
	}
	
    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    return STATUS_SUCCESS;
}


//----------------------------------------------------------------------------
/*
 *                   TDI_EVENT_RECEIVE_DATAGRAM handler
 */

NTSTATUS tdi_event_receive_datagram(
    IN PVOID TdiEventContext,
    IN LONG SourceAddressLength,
    IN PVOID SourceAddress,
    IN LONG OptionsLength,
    IN PVOID Options,
    IN ULONG ReceiveDatagramFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket)
{
    NTSTATUS status;
    int result = FILTER_DENY;
    //
	struct _addr_entry *ae = (struct _addr_entry *)TdiEventContext;
	KIRQL irql;
	TA_ADDRESS *remote_addr, *local_addr;
	int ipproto;
	flt_request *r;
	struct _flt_rule rule;
    PVOID handler;
    PVOID context;

    KeAcquireSpinLock(&g_addr_list_lock, &irql);

    // check device object: UDP or RawIP
    if (get_original_devobj(ae->fltdevobj, &ipproto) == NULL ||
        (ipproto != IPPROTO_UDP && ipproto != IPPROTO_IP))
    {
        // unknown device object!
        KdPrint(("[tdi_fw] tdi_event_receive_datagram: unknown DeviceObject 0x%x!\n",
            ae));

        status = STATUS_DATA_NOT_ACCEPTED;
        goto done;
    }

	// get local address of address object

	local_addr  = (TA_ADDRESS *)(ae->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)SourceAddress)->Address;

	KdPrint(("[tdi_fw] tdi_event_receive_datagram(pid:%u) addrobj 0x%x: %x:%u -> %x:%u\n",
		ae->pid,
        ae->addrobj,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port)));

	// call quick filter for datagram
    r = malloc_np(sizeof(flt_request));
    if (r == NULL) {
        KdPrint(("~!![tdi_fw] tdi_event_receive_datagram: malloc_np\n"));
        goto done;
    }
    memset(r, 0, sizeof(flt_request));

	r->direction = DIRECTION_IN;
	r->proto = ipproto;
	r->pid = ae->pid;
	
	memcpy(&r->addr.from, &remote_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&r->addr.to,    &local_addr->AddressType, sizeof(struct sockaddr));

    r->log_bytes_in = BytesAvailable;

    KeAcquireSpinLockAtDpcLevel(&g_traffic_lock);

    g_traffic_in += BytesAvailable;

    KeReleaseSpinLockFromDpcLevel(&g_traffic_lock);

    handler = ae->tdi_event_context[TDI_EVENT_RECEIVE_DATAGRAM].routine;
    context = ae->tdi_event_context[TDI_EVENT_RECEIVE_DATAGRAM].context;
    KeReleaseSpinLock(&g_addr_list_lock, irql);
    ae = NULL;

	result = quick_filter(r, &rule);

    if (g_LogEnable)
        InsertRequestList(r);
    else
        free(r);

	if (result == FILTER_ALLOW)
    {
		status = ((PTDI_IND_RECEIVE_DATAGRAM)handler)
			(context, SourceAddressLength, SourceAddress, OptionsLength,
			Options, ReceiveDatagramFlags, BytesIndicated, BytesAvailable, BytesTaken,
			Tsdu, IoRequestPacket);
	}
    else
		status = STATUS_DATA_NOT_ACCEPTED;

done:
    if (ae)
        KeReleaseSpinLock(&g_addr_list_lock, irql);
    return status;
}