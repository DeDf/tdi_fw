/*
 * This file contain TDI_EVENT_CONNECT & TDI_EVENT_DISCONNECT handlers
 */
#include "tdi_fw.h"

NTSTATUS	tdi_evconn_accept_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

//----------------------------------------------------------------------------
/*
 * TDI_EVENT_CONNECT handler
 */

NTSTATUS
tdi_event_connect(
    IN PVOID TdiEventContext,
    IN LONG RemoteAddressLength,
    IN PVOID RemoteAddress,
    IN LONG UserDataLength,
    IN PVOID UserData,
    IN LONG OptionsLength,
    IN PVOID Options,
    OUT CONNECTION_CONTEXT *ConnectionContext,
    OUT PIRP *AcceptIrp) // done!
{
    NTSTATUS status;
    int result = FILTER_DENY;
    //
    PIO_STACK_LOCATION irps  = NULL;
	struct _addr_entry *ae = (struct _addr_entry *)TdiEventContext;
	TA_ADDRESS *local_addr, *remote_addr = ((TRANSPORT_ADDRESS *)RemoteAddress)->Address;
	struct _tdi_irp_ctx *ctx = NULL;
    PVOID handler;
    PVOID context;
    //
    flt_request *r;
    struct _flt_rule rule;
    KIRQL irql;

    KeAcquireSpinLock(&g_addr_list_lock, &irql);

	KdPrint(("[tdi_fw] tdi_event_connect: addrobj 0x%x\n", ae->addrobj));

	local_addr = (TA_ADDRESS *)(ae->local_addr);
    handler = ae->tdi_event_context[TDI_EVENT_CONNECT].routine;
    context = ae->tdi_event_context[TDI_EVENT_CONNECT].context;

	KdPrint(("[tdi_fw] tdi_event_connect(pid:%u): %x:%u -> %x:%u\n",
		ae->pid,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port)));

    r = malloc_np(sizeof(flt_request));
    if (r == NULL) {
        KdPrint(("~!![tdi_fw] tdi_event_connect: malloc_np\n"));
        KeReleaseSpinLock(&g_addr_list_lock, irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(r, 0, sizeof(flt_request));

	r->tcp_conn_state = TYPE_CONNECT;
	r->direction      = DIRECTION_IN;
	r->proto          = IPPROTO_TCP;
	r->pid            = ae->pid;
	
	memcpy(&r->addr.from, &remote_addr->AddressType, sizeof(struct sockaddr));
	memcpy(&r->addr.to,    &local_addr->AddressType, sizeof(struct sockaddr));

    KeReleaseSpinLock(&g_addr_list_lock, irql);

    //========================================================
    
	result = quick_filter(r, &rule);

	if (result == FILTER_DENY)
		goto done;

	status = ((PTDI_IND_CONNECT)handler)
		(context, RemoteAddressLength, RemoteAddress,
		UserDataLength, UserData, OptionsLength, Options, ConnectionContext,
		AcceptIrp);

    if (status != STATUS_MORE_PROCESSING_REQUIRED || *AcceptIrp == NULL)
    {
        KdPrint(("~![tdi_fw] tdi_event_connect: status from original handler: 0x%x\n", status));
		goto done;
    }

    //===========================================================

	irps = IoGetCurrentIrpStackLocation(*AcceptIrp);
	KdPrint(("[tdi_fw] tdi_event_connect: connobj 0x%x\n", irps->FileObject));

    

	// patch *AcceptIrp to change completion routine
	ctx = (struct _tdi_irp_ctx *)malloc_np(sizeof(*ctx));
	if (ctx == NULL) {
		KdPrint(("[tdi_fw] tdi_event_connect: malloc_np!\n"));
		goto done;
	}

    ctx->addr_entry  = ae;
    ctx->connobj     = irps->FileObject;
	ctx->old_cr      = irps->CompletionRoutine;
	ctx->old_context = irps->Context;
	ctx->old_control = irps->Control;

	// can't use IoSetCompletionRoutine because it uses next not current stack location
	irps->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
	irps->CompletionRoutine = tdi_evconn_accept_complete;
	irps->Context = ctx;
	ctx = NULL;

    //====================================================

    KeAcquireSpinLock(&g_addr_list_lock, &irql);
    //
    // clear bytes count
    ae->bytes_receive = ae->bytes_send = 0;

	// sanity check
	if (local_addr->AddressLength != remote_addr->AddressLength) {
		KdPrint(("[tdi_fw] tdi_event_connect: different addr lengths! (%u != %u)\n",
			local_addr->AddressLength,
			remote_addr->AddressLength));
        status = STATUS_INFO_LENGTH_MISMATCH;
        KeReleaseSpinLock(&g_addr_list_lock, irql);
		goto done;
	}

	// associate remote address with connobj
	if (remote_addr->AddressLength > sizeof(ae->remote_addr)) {
		KdPrint(("[tdi_fw] tdi_event_connect: address too long! (%u)\n",
			remote_addr->AddressLength));
        status = STATUS_BUFFER_TOO_SMALL;
        KeReleaseSpinLock(&g_addr_list_lock, irql);
		goto done;
	}
	memcpy(ae->remote_addr, remote_addr, remote_addr->AddressLength);

	// associate local address with connobj

	if (local_addr->AddressLength > sizeof(ae->local_addr)) {
		KdPrint(("[tdi_fw] tdi_event_connect: address too long! (%u)\n",
			local_addr->AddressLength));
        status = STATUS_BUFFER_TOO_SMALL;
        KeReleaseSpinLock(&g_addr_list_lock, irql);
		goto done;
	}
	memcpy(ae->local_addr, local_addr, local_addr->AddressLength);
    //
    KeReleaseSpinLock(&g_addr_list_lock, irql);

done:
	
    if (result != FILTER_ALLOW)
    {
        KdPrint(("[tdi_fw] tdi_event_connect: deny on reason 0x%x\n", status));
        r->tcp_conn_state = TYPE_CONNECT_ERROR;

        if (irps != NULL)
        {
            // delete connection
            if (ae != NULL && ae->connobj != NULL)
            {
                del_conn_entry(ae->connobj);
                ae->connobj = NULL;
            }

            // destroy accepted IRP
            (*AcceptIrp)->IoStatus.Status = STATUS_UNSUCCESSFUL;
            IoCompleteRequest(*AcceptIrp, IO_NO_INCREMENT);
        }

        *AcceptIrp = NULL;
        status = STATUS_CONNECTION_REFUSED;
    }
    else
        status = STATUS_MORE_PROCESSING_REQUIRED;

    if (g_LogEnable)
    {
        if (r)
            InsertRequestList(r);
    }
    else
    {
        if (r)
            free(r);
    }

	if (ctx != NULL)
		free(ctx);

	return status;
}

NTSTATUS
tdi_evconn_accept_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
    NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irps  = IoGetNextIrpStackLocation(Irp);
	struct _tdi_irp_ctx *ctx = (struct _tdi_irp_ctx *)Context;
    // call old completion (see the old control)
    BOOLEAN b_call = FALSE;

	KdPrint(("[tdi_fw] tdi_evconn_accept_complete: status 0x%x\n", Irp->IoStatus.Status));

    if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        
        // query & update connection local_addr
        struct _get_localaddr_workitem_param *ucn_param =
            (struct _get_localaddr_workitem_param *)malloc_np(sizeof(*ucn_param));

        if (ucn_param != NULL)
        {
            memset(ucn_param, 0, sizeof(*ucn_param));

            ucn_param->devobj  = irps->DeviceObject;
            ucn_param->fileobj = ctx->connobj;

            KdPrint(("[tdi_fw] tdi_evconn_accept_complete: connobj 0x%x\n", ctx->connobj));

            ExInitializeWorkItem(&ucn_param->WorkItem, get_localaddr_workitem, ucn_param);
            ExQueueWorkItem(&ucn_param->WorkItem, DelayedWorkQueue);	// DelayedWorkQueue a good value?

        } else {
            KdPrint(("~!![tdi_fw] tdi_evconn_accept_complete: malloc_np!\n"));
            // so we'll live without known local address :-(
        }
    }
    else
        del_conn_entry(irps->FileObject);

	// restore routine and context (and even control!)
	irps->CompletionRoutine = ctx->old_cr;
	irps->Context           = ctx->old_context;
	irps->Control           = ctx->old_control;	

    if (Irp->Cancel)
    {
        // cancel
        if (ctx->old_control & SL_INVOKE_ON_CANCEL)
            b_call = TRUE;
    } else {
        if (Irp->IoStatus.Status >= STATUS_SUCCESS)
        {
            // success
            if (ctx->old_control & SL_INVOKE_ON_SUCCESS)
                b_call = TRUE;
        } else {
            // error
            if (ctx->old_control & SL_INVOKE_ON_ERROR)
                b_call = TRUE;
        }
    }

    if (b_call)
        status = ctx->old_cr(DeviceObject, Irp, ctx->old_context);

	free(ctx);
	return status;
}

//----------------------------------------------------------------------------
/*
 * TDI_EVENT_DISCONNECT handler
 */

NTSTATUS
tdi_event_disconnect(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN LONG DisconnectDataLength,
    IN PVOID DisconnectData,
    IN LONG DisconnectInformationLength,
    IN PVOID DisconnectInformation,
    IN ULONG DisconnectFlags)
{
    NTSTATUS status;
	struct _addr_entry *ae = (struct _addr_entry *)TdiEventContext;
    KIRQL irql;
    PVOID handler;
    PVOID context;

	KdPrint(("[tdi_fw] tdi_event_disconnect: (flags: 0x%x)\n",
        DisconnectFlags));

    KeAcquireSpinLock(&g_addr_list_lock, &irql);

    handler = ae->tdi_event_context[TDI_EVENT_DISCONNECT].routine;
    context = ae->tdi_event_context[TDI_EVENT_DISCONNECT].context;

    if (!(DisconnectFlags & TDI_DISCONNECT_RELEASE))
    {
        del_conn_entry(ae->connobj);
        ae->connobj = NULL;
    }

    KeReleaseSpinLock(&g_addr_list_lock, irql);

	return ((PTDI_IND_DISCONNECT)handler)(
        context, 
        ConnectionContext,
		DisconnectDataLength,
        DisconnectData,
        DisconnectInformationLength,
		DisconnectInformation,
        DisconnectFlags);
}
