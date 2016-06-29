/*
 * This file contains TDI_CREATE, TDI_ASSOCIATE_ADDRESS, TDI_DISASSOCIATE_ADDRESS handlers
 */
#include "tdi_fw.h"

typedef struct _TDI_CREATE_ADDROBJ_CTX {
    PFILE_OBJECT		addrobj;	/* FileObject from IO_STACK_LOCATION */
    TDI_ADDRESS_INFO	*tai;		/* address info -- result of TDI_QUERY_ADDRESS_INFO */
} TDI_CREATE_ADDROBJ_CTX;

NTSTATUS tdi_create_addrobj_complete(
	IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

NTSTATUS tdi_query_addr_complete(
    IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

//----------------------------------------------------------------------------
/*
 * TDI_CREATE handler
 */

int
tdi_create(PIRP irp, PIO_STACK_LOCATION irps, PDEVICE_OBJECT old_devobj, int ipproto, OUT struct _completion *completion)
{
	NTSTATUS status;
	FILE_FULL_EA_INFORMATION *ea = (FILE_FULL_EA_INFORMATION *)irp->AssociatedIrp.SystemBuffer;

    if (ea == NULL)
        return FILTER_ALLOW;

    // NOTE: for RawIp you can extract protocol number from irps->FileObject->FileName

    if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH &&  // This is creation of address object
        memcmp(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == 0)
    {
        KdPrint(("[tdi_fw]\n[tdi_fw] tdi_create: [addrobj]       fltdevobj: 0x%x; FileObj 0x%x\n",
            irps->DeviceObject,
            irps->FileObject));

        status = add_addrobj(irps->FileObject,
            irps->DeviceObject,
            old_devobj,
            ipproto);
        if (status != STATUS_SUCCESS) {
            KdPrint(("~![tdi_fw] tdi_create: ot_add_fileobj: 0x%x\n", status));
            return FILTER_DENY;
        }

        // while we're on PASSIVE_LEVEL build control IRP for completion
        completion->context = TdiBuildInternalDeviceControlIrp(
            TDI_QUERY_INFORMATION,
            old_devobj,
            irps->FileObject,
            NULL,
            NULL);
        if (completion->context == NULL) {
            KdPrint(("~![tdi_fw] tdi_create: TdiBuildInternalDeviceControlIrp\n"));
            return FILTER_DENY;
        }
        completion->routine = tdi_create_addrobj_complete;

    } else if (ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH &&  // This is creation of connection object
        memcmp(ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH) == 0)
    {
        CONNECTION_CONTEXT conn_ctx = *(CONNECTION_CONTEXT *)(ea->EaName + ea->EaNameLength + 1);

        KdPrint(("[tdi_fw]\n[tdi_fw] tdi_create: [connobj]       fltdevobj: 0x%x; connobj 0x%x; conn_ctx 0x%x\n",
            irps->DeviceObject,
            irps->FileObject,
            conn_ctx));

        status = add_connobj(irps->FileObject, conn_ctx);

        if (status != STATUS_SUCCESS) {
            KdPrint(("~![tdi_fw] tdi_create: ot_add_fileobj: 0x%x\n", status));
            return FILTER_DENY;
        }
    }

	return FILTER_ALLOW;
}

/* this completion routine queries address and port from address object */
NTSTATUS
tdi_create_addrobj_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	NTSTATUS status = Irp->IoStatus.Status;
    //
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	PIRP query_irp = (PIRP)Context;
	PDEVICE_OBJECT old_devobj;
	TDI_CREATE_ADDROBJ_CTX *ctx = NULL;
	PMDL mdl = NULL;

    KdPrint(("[tdi_fw] tdi_create_addrobj_complete:fltdevobj: 0x%x; FileObj 0x%x\n",
		DeviceObject,
        irps->FileObject));

	if (status) {
		KdPrint(("~![tdi_fw] tdi_create_addrobj_complete: status 0x%x\n", status));
		goto done;
	}

	// query addrobj address:port

	ctx = (TDI_CREATE_ADDROBJ_CTX *)malloc_np(sizeof(TDI_CREATE_ADDROBJ_CTX));
	if (ctx == NULL) {
		KdPrint(("~!![tdi_fw] tdi_create_addrobj_complete: malloc_np!\n"));
		
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	ctx->addrobj = irps->FileObject;

	ctx->tai = (TDI_ADDRESS_INFO *)malloc_np(TDI_ADDRESS_INFO_MAX);
	if (ctx->tai == NULL) {
		KdPrint(("~![tdi_fw] tdi_create_addrobj_complete: malloc_np!\n"));

		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}

	mdl = IoAllocateMdl(ctx->tai, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		KdPrint(("~![tdi_fw] tdi_create_addrobj_complete: IoAllocateMdl!\n"));
		
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto done;
	}
	MmBuildMdlForNonPagedPool(mdl);

	old_devobj = get_original_devobj(DeviceObject, NULL);	// use original devobj!
	if (old_devobj == NULL) {
		KdPrint(("[tdi_fw] tdi_create_addrobj_complete: get_original_devobj!\n"));

		status = STATUS_INVALID_PARAMETER;
		goto done;
	}

	TdiBuildQueryInformation(query_irp, old_devobj, irps->FileObject,
		tdi_query_addr_complete, ctx,
		TDI_QUERY_ADDRESS_INFO, mdl);

	status = IoCallDriver(old_devobj, query_irp);
	query_irp = NULL;
	mdl = NULL;
	ctx = NULL;

	if (status != STATUS_SUCCESS)
    {
        if (status != STATUS_PENDING)
        {
            KdPrint(("~![tdi_fw] tdi_create_addrobj_complete: IoCallDriver: 0x%x\n", status));
            del_addr_entry(irps->FileObject);
        }
    }

done:
	// cleanup
	if (mdl != NULL)
		IoFreeMdl(mdl);
	
	if (ctx != NULL)
    {
		if (ctx->tai != NULL)
			free(ctx->tai);
		free(ctx);
	}
	
	if (query_irp != NULL)
		IoCompleteRequest(query_irp, IO_NO_INCREMENT);

	Irp->IoStatus.Status = status;

    if (Irp->PendingReturned)
        IoMarkIrpPending(Irp);

    return STATUS_SUCCESS;
}

/* this completion routine gets address and port from reply to TDI_QUERY_ADDRESS_INFO */
NTSTATUS
tdi_query_addr_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	NTSTATUS status;
	TDI_CREATE_ADDROBJ_CTX *ctx = (TDI_CREATE_ADDROBJ_CTX *)Context;
	TA_ADDRESS *addr = ctx->tai->Address.Address;
	struct _addr_entry *ae;
	KIRQL irql;

	// save address
	ae = find_addr_entry(ctx->addrobj, &irql);
	if (ae == NULL) {
		KdPrint(("~![tdi_fw] tdi_query_addr_complete: ot_find_fileobj(0x%x)\n",
			ctx->addrobj));
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (addr->AddressLength > sizeof(ae->local_addr)) {
		KdPrint(("~![tdi_fw] tdi_query_addr_complete: address too long! (%u)\n",
			addr->AddressLength));
		status = STATUS_BUFFER_OVERFLOW;
		goto done;
	}
	memcpy(ae->local_addr, addr, addr->AddressLength);

    KdPrint(("[tdi_fw] tdi_query_addr_complete: address: %x:%u, proto: %d\n", 
        ntohl(((TDI_ADDRESS_IP *)(addr->Address))->in_addr),
        ntohs(((TDI_ADDRESS_IP *)(addr->Address))->sin_port),
        ae->ipproto));

done:
	if (ae != NULL)
		KeReleaseSpinLock(&g_addr_list_lock, irql);

	// cleanup MDL to avoid unlocking pages from NonPaged pool
	if (Irp->MdlAddress != NULL)
    {
		IoFreeMdl(Irp->MdlAddress);
		Irp->MdlAddress = NULL;
	}

	free(ctx->tai);
	free(ctx);
	
	return STATUS_SUCCESS;  // success anyway
}

//----------------------------------------------------------------------------
/*
 * TDI_ASSOCIATE_ADDRESS handler
 */
int
tdi_associate_address(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
    int result = FILTER_DENY;
    //
	HANDLE addr_handle = ((TDI_REQUEST_KERNEL_ASSOCIATE *)(&irps->Parameters))->AddressHandle;
	PFILE_OBJECT addrobj;
    struct _addr_entry *ae = NULL;
	struct _conn_entry *ce = NULL;
	KIRQL irql, irql1;

	if ( ObReferenceObjectByHandle(addr_handle, GENERIC_READ, NULL, KernelMode, &addrobj, NULL) )
    {
		KdPrint(("~![tdi_fw] tdi_associate_address: ObReferenceObjectByHandle!\n"));
		goto done;
	}

    KdPrint(("[tdi_fw] tdi_associate_address:      fltdevobj: 0x%x; connobj 0x%x ---> addrobj = 0x%x\n",
        irps->DeviceObject,
		irps->FileObject,
        addrobj));

	// associate addrobj with connobj

	ce = find_conn_entry(irps->FileObject, &irql);
	if (ce == NULL) {
		KdPrint(("~![tdi_fw] tdi_associate_address: find_conn_entry(0x%x)\n", irps->FileObject));
		goto done;
	}

    ae = find_addr_entry(addrobj, &irql1);
    if (ae)
    {
        ce->addr_entry = ae;
        ce->connobj    = irps->FileObject;
        KeReleaseSpinLockFromDpcLevel(&g_addr_list_lock);
    }

	result = FILTER_ALLOW;

done:
	if (addrobj != NULL)
		ObDereferenceObject(addrobj);

	// cleanup
	if (ce != NULL)
		KeReleaseSpinLock(&g_conn_list_lock, irql);

	return result;
}

//----------------------------------------------------------------------------
/*
 * TDI_DISASSOCIATE_ADDRESS handler
 */
int
tdi_disassociate_address(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
	KdPrint(("[tdi_fw] tdi_disassociate_address: connobj 0x%x\n", irps->FileObject));

	del_conn_entry(irps->FileObject);

	return FILTER_ALLOW;
}
