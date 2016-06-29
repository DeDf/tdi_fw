/*
 * This file contains TDI_EVENT_RECEIVE and TDI_EVENT_CHAINED_RECEIVE handlers
 */
#include "tdi_fw.h"

NTSTATUS		tdi_client_irp_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

//----------------------------------------------------------------------------
/*
 * TDI_EVENT_RECEIVE handler
 */

NTSTATUS
tdi_event_receive(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket)
{
    NTSTATUS status;
    struct _addr_entry *ae = (struct _addr_entry *)TdiEventContext;
    KIRQL irql;
    PVOID handler;
    PVOID context;

    KeAcquireSpinLock(&g_addr_list_lock, &irql);

	KdPrint(("[tdi_fw] tdi_event_receive: addrobj 0x%x; %u/%u; flags: 0x%x\n",
		ae->addrobj, BytesIndicated, BytesAvailable, ReceiveFlags));

    handler = ae->tdi_event_context[TDI_EVENT_RECEIVE].routine;
    context = ae->tdi_event_context[TDI_EVENT_RECEIVE].context;

    KeReleaseSpinLock(&g_addr_list_lock, irql);

	status = ((PTDI_IND_RECEIVE)handler)
		(context, ConnectionContext, ReceiveFlags, BytesIndicated,
		BytesAvailable, BytesTaken, Tsdu, IoRequestPacket);

	KdPrint(("[tdi_fw] tdi_event_receive: status 0x%x; BytesTaken: %u; Irp: 0x%x\n",
		status, *BytesTaken, *IoRequestPacket));
    
	if (*BytesTaken != 0)
    {
        KeAcquireSpinLock(&g_addr_list_lock, &irql);
        ae->bytes_receive += *BytesTaken;
        KeReleaseSpinLockFromDpcLevel(&g_addr_list_lock);

        // traffic stats
        KeAcquireSpinLockAtDpcLevel(&g_traffic_lock);
        g_traffic_in += *BytesTaken;
        KeReleaseSpinLock(&g_traffic_lock, irql);
	}

    if (ReceiveFlags | TDI_RECEIVE_ENTIRE_MESSAGE)
        return status;

    if (status != STATUS_SUCCESS && status != STATUS_MORE_PROCESSING_REQUIRED)
        return status;

	if (*IoRequestPacket != NULL)  // got IRP. replace completion.
    {
		PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(*IoRequestPacket);

        if (irps->CompletionRoutine != NULL)
        {
            struct _tdi_irp_ctx *new_ctx = (struct _tdi_irp_ctx *)malloc_np(sizeof(*new_ctx));

            if (new_ctx != NULL)
            {
                new_ctx->addr_entry  = ae;
                new_ctx->old_cr      = irps->CompletionRoutine;
                new_ctx->old_context = irps->Context;
                new_ctx->old_control = irps->Control;

                irps->CompletionRoutine = tdi_client_irp_complete;
                irps->Context = new_ctx;
                irps->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
            }
        }
    }

	return status;
}

NTSTATUS
tdi_client_irp_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
    NTSTATUS status = STATUS_SUCCESS;
	struct _tdi_irp_ctx *ctx = (struct _tdi_irp_ctx *)Context;
    KIRQL irql;
    // call old completion (see the old control)
    BOOLEAN b_call = FALSE;

	KdPrint(("[tdi_fw] tdi_client_irp_complete: status: 0x%x; len: %u\n",
		Irp->IoStatus.Status, Irp->IoStatus.Information));

	if (Irp->IoStatus.Status == STATUS_SUCCESS)
    {
        KeAcquireSpinLock(&g_addr_list_lock, &irql);
        ctx->addr_entry->bytes_receive += Irp->IoStatus.Information;
        KeReleaseSpinLockFromDpcLevel(&g_addr_list_lock);

        // traffic stats
        KeAcquireSpinLockAtDpcLevel(&g_traffic_lock);

        g_traffic_in += Irp->IoStatus.Information;

        KeReleaseSpinLock(&g_traffic_lock, irql);
	}

    if (Irp->Cancel)  // cancel
    {
        if (ctx->old_control & SL_INVOKE_ON_CANCEL)
            b_call = TRUE;
    } else {
        if (Irp->IoStatus.Status >= STATUS_SUCCESS)  // success
        {
            if (ctx->old_control & SL_INVOKE_ON_SUCCESS)
                b_call = TRUE;
        } else {
            // error
            if (ctx->old_control & SL_INVOKE_ON_ERROR)
                b_call = TRUE;
        }
    }

    if (b_call)
    {
        status = (ctx->old_cr)(DeviceObject, Irp, ctx->old_context);

        KdPrint(("[tdi_fw] tdi_client_irp_complete: original handler: 0x%x; status: 0x%x\n",
            ctx->old_cr, status));
    }

	free(ctx);
	return status;
}
  
//----------------------------------------------------------------------------
/*
 * TDI_EVENT_CHAINED_RECEIVE handler
 */

NTSTATUS
tdi_event_chained_receive(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG ReceiveLength,
    IN ULONG StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID TsduDescriptor)
{
    NTSTATUS status;
	struct _addr_entry *ae = (struct _addr_entry *)TdiEventContext;
    PVOID handler;
    PVOID context;
    KIRQL irql;

    KeAcquireSpinLock(&g_addr_list_lock, &irql);

    handler = ae->tdi_event_context[TDI_EVENT_CHAINED_RECEIVE].routine;
    context = ae->tdi_event_context[TDI_EVENT_CHAINED_RECEIVE].context;

    KeReleaseSpinLock(&g_addr_list_lock, irql);

	status = ((PTDI_IND_CHAINED_RECEIVE)handler)
		(context, ConnectionContext, ReceiveFlags, ReceiveLength,
		StartingOffset, Tsdu, TsduDescriptor);

    KdPrint(("[tdi_fw] tdi_event_chained_receive: connobj 0x%x; %4u; flags: 0x%x; status 0x%x\n",
        ae->connobj,
        ReceiveLength,
        ReceiveFlags,
        status));

	if (status == STATUS_SUCCESS || status == STATUS_PENDING)
    {
        KeAcquireSpinLock(&g_addr_list_lock, &irql);
        ae->bytes_receive += ReceiveLength;
        KeReleaseSpinLockFromDpcLevel(&g_addr_list_lock);

        // traffic stats
        KeAcquireSpinLockAtDpcLevel(&g_traffic_lock);
        g_traffic_in += ReceiveLength;
        KeReleaseSpinLock(&g_traffic_lock, irql); 
	}

	return status;
}
