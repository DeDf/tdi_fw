/*
 * This file contains TDI_SEND and TDI_RECEIVE handlers
 */
#include "tdi_fw.h"

NTSTATUS tdi_receive_complete(
	IN PDEVICE_OBJECT DeviceObject,
    IN PIRP Irp,
    IN PVOID Context);

//----------------------------------------------------------------------------
/*
 * TDI_SEND handler
 */

int
tdi_send(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
	TDI_REQUEST_KERNEL_SEND *param = (TDI_REQUEST_KERNEL_SEND *)(&irps->Parameters);
    struct _conn_entry *ce;
	struct _addr_entry *ae;
	KIRQL irql;
    int ipproto;

	KdPrint(("[tdi_fw] tdi_send: FileObj: 0x%x; SendLength: %u; SendFlags: 0x%x\n",
		irps->FileObject,
        param->SendLength,
        param->SendFlags));

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

	if (ae != NULL)
    {
		ae->bytes_send += param->SendLength;
		KeReleaseSpinLockFromDpcLevel(&g_addr_list_lock);
        KeAcquireSpinLockAtDpcLevel(&g_traffic_lock);
	}
    else
        KeAcquireSpinLock(&g_traffic_lock, &irql);
    
    g_traffic_out += param->SendLength;

    KeReleaseSpinLock(&g_traffic_lock, irql);
    
	// TODO: process TDI_SEND_AND_DISCONNECT flag (used by IIS for example)

	return FILTER_ALLOW;
}

//----------------------------------------------------------------------------

/*
 * TDI_RECEIVE handler
 */

int
tdi_receive(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
	TDI_REQUEST_KERNEL_RECEIVE *param = (TDI_REQUEST_KERNEL_RECEIVE *)(&irps->Parameters);

	KdPrint(("[tdi_fw] tdi_receive: connobj: 0x%x; ReceiveLength: %u; ReceiveFlags: 0x%x\n",
		irps->FileObject, param->ReceiveLength, param->ReceiveFlags));

	if (!(param->ReceiveFlags & TDI_RECEIVE_PEEK))
    {
		completion->routine = tdi_receive_complete;
	}

	return FILTER_ALLOW;
}

NTSTATUS
tdi_receive_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
    struct _conn_entry *ce;
	struct _addr_entry *ae;
	KIRQL irql;

	KdPrint(("[tdi_fw] tdi_receive_complete: connobj: 0x%x; status: 0x%x; received: %u\n",
		irps->FileObject,
        Irp->IoStatus.Status,
        Irp->IoStatus.Information));

    ce = find_conn_entry(irps->FileObject, &irql);
    if (ce == NULL) {
        KdPrint(("~![tdi_fw] tdi_connect: find_conn_entry(0x%x)!\n", irps->FileObject));
        return FILTER_ALLOW;
    }
    ae = ce->addr_entry;
    KeReleaseSpinLockFromDpcLevel(&g_conn_list_lock);

    KeAcquireSpinLockAtDpcLevel(&g_addr_list_lock);
    if (ae)
        ae->bytes_receive += Irp->IoStatus.Information;
    KeReleaseSpinLockFromDpcLevel(&g_addr_list_lock);

    // traffic stats
    KeAcquireSpinLockAtDpcLevel(&g_traffic_lock);
    g_traffic_in += Irp->IoStatus.Information;
    KeReleaseSpinLock(&g_traffic_lock, irql);

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    return STATUS_SUCCESS;
}
