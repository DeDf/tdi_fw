//===========================================================
#include "tdi_fw.h"

PDEVICE_OBJECT g_tcpoldobj, g_udpoldobj, g_ipoldobj;
PDEVICE_OBJECT g_tcpfltobj, g_udpfltobj, g_ipfltobj;

PDEVICE_OBJECT g_dev_control, g_dev_nfo;

BOOLEAN g_NET_DENY;           // 阻止网络
BOOLEAN g_FltEnable;          // 过滤开关
BOOLEAN g_LogEnable = TRUE;   // 日志开关

/* for IOCTL_TDI_QUERY_DIRECT_SEND_HANDLER */
typedef NTSTATUS  TCPSendData_t(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp);
TCPSendData_t *g_old_TCPSendData;
TCPSendData_t g_new_TCPSendData;

/* global traffic stats */
KSPIN_LOCK g_traffic_lock;
unsigned __int64 g_traffic_in;
unsigned __int64 g_traffic_out;

// request_list
LIST_ENTRY  request_list_head;
KSPIN_LOCK	request_list_lock;
KEVENT      g_request_event;
ULONG       g_request_count;

PVOID g_tdi_ioctls[] = {
    NULL,
    /*TDI_ASSOCIATE_ADDRESS,*/	    tdi_associate_address,
    /*TDI_DISASSOCIATE_ADDRESS,*/	tdi_disassociate_address,
    /*TDI_CONNECT,*/				tdi_connect,		
    /*TDI_LISTEN,*/				    tdi_deny_stub,  // for now only deny stubs for security reasons
    /*TDI_ACCEPT,*/				    tdi_deny_stub,  // for now only deny stubs for security reasons
    /*TDI_DISCONNECT,*/			    tdi_disconnect,
    /*TDI_SEND,*/					tdi_send,
    /*TDI_RECEIVE,*/				tdi_receive,
    /*TDI_SEND_DATAGRAM,*/		    tdi_send_datagram,
    /*TDI_RECEIVE_DATAGRAM,*/		tdi_receive_datagram,
    /*TDI_SET_EVENT_HANDLER,*/	    tdi_set_event_handler
};

PVOID tdi_event_handler[] = {
    /*TDI_EVENT_CONNECT,*/						tdi_event_connect,
    /*TDI_EVENT_DISCONNECT,*/					tdi_event_disconnect,
    /*TDI_EVENT_ERROR,*/                        NULL,
    /*TDI_EVENT_RECEIVE,*/		     			tdi_event_receive,
    /*TDI_EVENT_RECEIVE_DATAGRAM,*/	     	    tdi_event_receive_datagram,
    /*TDI_EVENT_RECEIVE_EXPEDITED,*/			tdi_event_receive,
    /*TDI_EVENT_SEND_POSSIBLE,*/                NULL,
    /*TDI_EVENT_CHAINED_RECEIVE,*/				tdi_event_chained_receive,
    /*TDI_EVENT_CHAINED_RECEIVE_DATAGRAM,*/	    NULL,
    /*TDI_EVENT_CHAINED_RECEIVE_EXPEDITED,*/	tdi_event_chained_receive,
    /*TDI_EVENT_ERROR_EX,*/                     NULL
};

/* ------------------prototypes--------------------- */

NTSTATUS
c_n_a_device(IN PDRIVER_OBJECT DriverObject,
             OUT PDEVICE_OBJECT *ppFltDevObj,
             OUT PDEVICE_OBJECT *ppOldDevObj,
             IN wchar_t *pwch_devname);

void
d_n_d_device(PDRIVER_OBJECT DriverObject,
             PDEVICE_OBJECT oldobj,
			 PDEVICE_OBJECT fltobj);

int
tdi_create(PIRP irp, PIO_STACK_LOCATION irps, PDEVICE_OBJECT old_devobj, int ipproto, OUT struct _completion *completion);

NTSTATUS
tdi_dispatch_complete(PDEVICE_OBJECT fltdevobj,
                      PDEVICE_OBJECT old_devobj,
                      PIRP irp,
                      int filter,
                      PIO_COMPLETION_ROUTINE CompletionRoutine,
                      PVOID context);

NTSTATUS
process_request(ULONG ctl_code, char *buf, OUT ULONG *out_len, ULONG buf_size);

NTSTATUS    DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID		OnUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS	DeviceDispatch(PDEVICE_OBJECT DeviceObject, PIRP irp);

//===========================================================

PDEVICE_OBJECT
get_original_devobj(PDEVICE_OBJECT flt_devobj, OPTIONAL OUT int *proto)
{
    PDEVICE_OBJECT p = NULL;

    if (flt_devobj == g_tcpfltobj)
    {
        p = g_tcpoldobj;
        if (proto)
            *proto = IPPROTO_TCP;
    }
    else if (flt_devobj == g_udpfltobj)
    {
        p = g_udpoldobj;
        if (proto)
            *proto = IPPROTO_UDP;
    }
    else if (flt_devobj == g_ipfltobj)
    {
        p = g_ipoldobj;
        if (proto)
            *proto = IPPROTO_IP;
    }
//     else
//     {
//         KdPrint(("~![tdi_fw] get_original_devobj: Unknown DeviceObject 0x%x!\n", flt_devobj));
//     }

    return p;
}

/* create & attach device */
NTSTATUS
c_n_a_device(IN PDRIVER_OBJECT DriverObject,
             OUT PDEVICE_OBJECT *ppFltDevObj,
             OUT PDEVICE_OBJECT *ppOldDevObj,
             IN WCHAR *pwch_devname)
{
    NTSTATUS status;
    UNICODE_STRING us_DevName;

    status = IoCreateDevice(DriverObject,
        0,
        NULL,
        FILE_DEVICE_UNKNOWN,
        0,
        TRUE,
        ppFltDevObj);
    if (status != STATUS_SUCCESS)
    {
        KdPrint(("~![tdi_fw] c_n_a_device fail: IoCreateDevice(%S): 0x%x\n", pwch_devname, status));
        return status;
    }
    (*ppFltDevObj)->Flags |= DO_DIRECT_IO;

    RtlInitUnicodeString(&us_DevName, pwch_devname);

    status = IoAttachDevice(*ppFltDevObj, &us_DevName, ppOldDevObj);
    if (status != STATUS_SUCCESS)
    {
        KdPrint(("~![tdi_fw] c_n_a_device fail: IoAttachDevice(%S): 0x%x\n", pwch_devname, status));
        return status;
    }

    KdPrint(("[tdi_fw] c_n_a_device: %-13S fltdevobj: 0x%x\n", pwch_devname, *ppFltDevObj));

    return STATUS_SUCCESS;
}

/* detach & delete device */
void d_n_d_device(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT oldobj, PDEVICE_OBJECT fltobj)
{
    if (oldobj != NULL)
        IoDetachDevice(oldobj);

    if (fltobj != NULL)
    {
        IoDeleteDevice(fltobj);
        fltobj = NULL;
    }
}

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject,
            IN PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
	UNICODE_STRING us_DevName, us_SymbollinkName;
    int i;

    KdPrint(("*******************tdi_fw*******************\n"));
    //__debugbreak();
	memtrack_init();

	KeInitializeSpinLock(&g_traffic_lock);  // 统计总流量用

    InitializeListHead(&request_list_head);
    KeInitializeSpinLock(&request_list_lock);
    KeInitializeEvent(&g_request_event, NotificationEvent, FALSE);
    KdPrint(("[tdi_fw] &g_request_event: %x\n", &g_request_event));

	status = ot_init();
	if (status)
    {
		KdPrint(("~![tdi_fw] DriverEntry: ot_init: 0x%x\n", status));
		goto done;
	}

	status = filter_init();
	if (status)
    {
		KdPrint(("~![tdi_fw] DriverEntry: filter_init: 0x%x\n", status));
		goto done;
	}
	
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DeviceDispatch;

#if DBG
	DriverObject->DriverUnload = OnUnload;
#endif

	/* create control device and symbolic link */
	RtlInitUnicodeString(&us_DevName, L"\\Device\\tdifw");

	status = IoCreateDevice(DriverObject,
							0,
							&us_DevName,
							0,
							0,
							TRUE,		// exclusive!
							&g_dev_control);
	if (status)
    {
		KdPrint(("~![tdi_fw] DriverEntry: IoCreateDevice(control): 0x%x!\n", status));
		goto done;
	}

	RtlInitUnicodeString(&us_SymbollinkName, L"\\??\\tdifw");

	status = IoCreateSymbolicLink(&us_SymbollinkName, &us_DevName);
	if (status)
    {
		KdPrint(("~![tdi_fw] DriverEntry: IoCreateSymbolicLink: 0x%x!\n", status));
		goto done;
	}

	RtlInitUnicodeString(&us_DevName, L"\\Device\\tdifw_nfo");

	status = IoCreateDevice(DriverObject,
							0,
							&us_DevName,
							0,
							0,
							FALSE,		// not exclusive!
							&g_dev_nfo);
	if (status != STATUS_SUCCESS)
    {
		KdPrint(("~![tdi_fw] DriverEntry: IoCreateDevice(nfo): 0x%x!\n", status));
		goto done;
	}

	RtlInitUnicodeString(&us_SymbollinkName, L"\\??\\tdifw_nfo");

	status = IoCreateSymbolicLink(&us_SymbollinkName, &us_DevName);
	if (status != STATUS_SUCCESS) {
		KdPrint(("~![tdi_fw] DriverEntry: IoCreateSymbolicLink: 0x%x!\n", status));
		goto done;
	}

	status |= c_n_a_device(DriverObject, &g_tcpfltobj, &g_tcpoldobj, L"\\Device\\Tcp");
	status |= c_n_a_device(DriverObject, &g_udpfltobj, &g_udpoldobj, L"\\Device\\Udp");
	status |= c_n_a_device(DriverObject, &g_ipfltobj,  &g_ipoldobj,  L"\\Device\\RawIp");

    KdPrint(("*******************************************************************************\n"));

done:
	if (status)
		OnUnload(DriverObject);  // cleanup

    return status;
}

VOID
OnUnload(IN PDRIVER_OBJECT DriverObject)
{
    flt_request *request;

	d_n_d_device(DriverObject, g_tcpoldobj, g_tcpfltobj);
	d_n_d_device(DriverObject, g_udpoldobj, g_udpfltobj);
	d_n_d_device(DriverObject, g_ipoldobj,  g_ipfltobj);

	if (g_dev_control != NULL)
    {
		UNICODE_STRING linkname;
		
		RtlInitUnicodeString(&linkname, L"\\??\\tdifw");
		IoDeleteSymbolicLink(&linkname);

		IoDeleteDevice(g_dev_control);
	}

	if (g_dev_nfo != NULL)
    {
		UNICODE_STRING linkname;
		
		RtlInitUnicodeString(&linkname, L"\\??\\tdifw_nfo");
		IoDeleteSymbolicLink(&linkname);

		IoDeleteDevice(g_dev_nfo);
	}

	filter_free();
	ot_free();

    do 
    {
        request = 
            (flt_request *)ExInterlockedRemoveHeadList(&request_list_head, &request_list_lock);

        if (request)
            free(request);

    } while (request);

	memtrack_free();
}

NTSTATUS
DeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    //
	PIO_STACK_LOCATION irpsp;
    PDEVICE_OBJECT old_devobj;
    int ProtocolType;
	
	if (irp == NULL)  // sanity check
    {
		KdPrint(("~![tdi_fw] DeviceDispatch: irp == null!\n"));
		return STATUS_UNSUCCESSFUL;
	}
    irpsp = IoGetCurrentIrpStackLocation(irp);

    old_devobj = get_original_devobj(DeviceObject, &ProtocolType);

    //-------------------------过滤设备--------------------------
	if (old_devobj)
    {
		int result;
        struct _completion completion = {0};

		switch (irpsp->MajorFunction)
        {
        case IRP_MJ_CREATE:		/* create fileobject */
            {
                result = tdi_create(irp, irpsp, old_devobj, ProtocolType, &completion);

                status = tdi_dispatch_complete(
                    DeviceObject,
                    old_devobj,
                    irp,
                    result,
                    completion.routine,
                    completion.context);

                break;
            }
		case IRP_MJ_DEVICE_CONTROL:
			
//             KdPrint(("[tdi_fw] DeviceDispatch: IRP_MJ_DEVICE_CONTROL, CtlCode 0x%x, FileObject: 0x%08X\n",
// 				irpsp->Parameters.DeviceIoControl.IoControlCode,
//                 irpsp->FileObject));

			if (KeGetCurrentIrql() == PASSIVE_LEVEL)                   // works on PASSIVE_LEVEL only!
				status = TdiMapUserRequest(DeviceObject, irp, irpsp);  // try to convert it to IRP_MJ_INTERNAL_DEVICE_CONTROL
			else
				status = STATUS_NOT_IMPLEMENTED; // set fake status

			if (status != STATUS_SUCCESS)
            {
				void *buf = (irpsp->Parameters.DeviceIoControl.IoControlCode == IOCTL_TDI_QUERY_DIRECT_SEND_HANDLER) ?
					irpsp->Parameters.DeviceIoControl.Type3InputBuffer : NULL;

				// send IRP to original driver
				IoSkipCurrentIrpStackLocation(irp);
                status = IoCallDriver(old_devobj, irp);

				if (buf != NULL && status == STATUS_SUCCESS)
                {
					g_old_TCPSendData = *(TCPSendData_t **)buf;

					KdPrint(("[tdi_fw] DeviceDispatch: IOCTL_TDI_QUERY_DIRECT_SEND_HANDLER: TCPSendData = 0x%x\n",
						g_old_TCPSendData));

					*(TCPSendData_t **)buf = g_new_TCPSendData;
				}

				break;
			}

			// don't break! go to internal device control!
		
        case IRP_MJ_INTERNAL_DEVICE_CONTROL:
            {
                if (irpsp->MinorFunction && irpsp->MinorFunction <= 0xb)
                {
//                     KdPrint(("[tdi_fw] DeviceDispatch: MinorFunction: 0x%x, FileObject: 0x%x\n",
//                         irpsp->MinorFunction,
//                         irpsp->FileObject));

                    // call dispatch function
                    result = ((tdi_ioctl_fn_t*)(g_tdi_ioctls[irpsp->MinorFunction]))(irp, irpsp, &completion);

                    // complete request
                    status = tdi_dispatch_complete(
                        DeviceObject,
                        old_devobj,
                        irp,
                        result,
                        completion.routine,
                        completion.context);
                }
                else
                {
                    IoSkipCurrentIrpStackLocation(irp);
                    status = IoCallDriver(old_devobj, irp);
                }

                break;
            }

        case IRP_MJ_CLEANUP:		/* cleanup fileobject */
            del_addr_entry(irpsp->FileObject);

		default:

            IoSkipCurrentIrpStackLocation(irp);
            status = IoCallDriver(old_devobj, irp);
		}
	}
    //--------------------control device----------------------------
    else if (DeviceObject == g_dev_control)
    {
		if (irpsp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
        {
			ULONG ctl_code  = irpsp->Parameters.DeviceIoControl.IoControlCode,
				  out_len   = irpsp->Parameters.DeviceIoControl.InputBufferLength,
				  buf_size  = irpsp->Parameters.DeviceIoControl.OutputBufferLength;
			char *out_buf;

			if ((ctl_code & METHOD_NEITHER) == METHOD_NEITHER)	// this type of transfer unsupported
				out_buf = NULL;
			else
				out_buf = (char *)irp->AssociatedIrp.SystemBuffer;

			// process control request
			status = process_request(ctl_code, out_buf, &out_len, buf_size);

			irp->IoStatus.Information = out_len;
		}

		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
    //--------------------------information device-----------------------------
    else if (DeviceObject == g_dev_nfo)  
    {
        if (irpsp->MajorFunction == IRP_MJ_DEVICE_CONTROL)
            {
                ULONG ioctl = irpsp->Parameters.DeviceIoControl.IoControlCode,
                    len  = irpsp->Parameters.DeviceIoControl.InputBufferLength,
                    size = irpsp->Parameters.DeviceIoControl.OutputBufferLength;
                char *out_buf;

                status = STATUS_UNSUCCESSFUL;

                if ((ioctl & METHOD_NEITHER) == METHOD_NEITHER)  // this type of transfer unsupported
                    out_buf = NULL;
                else
                    out_buf = (char *)irp->AssociatedIrp.SystemBuffer;

                if (out_buf)
                {
                    if (size >= sizeof(flt_request))
                    {
                        flt_request *request;
                        //KdPrint(("[tdi_fw]  -- Flink:%x, Blink:%x\n", request_list_head.Flink, request_list_head.Blink));

  next:                 request = (flt_request *)ExInterlockedRemoveHeadList(&request_list_head, &request_list_lock);
                          
                        if (request)
                        {
                            InterlockedDecrement(&g_request_count);
                            memcpy(out_buf, request, sizeof(flt_request));
                            irp->IoStatus.Information = sizeof(flt_request);
                            free(request);
                            
                            status = STATUS_SUCCESS;
                        }
                        else
                        {
                            KeResetEvent(&g_request_event);
                            
                            KeWaitForSingleObject(&g_request_event,
                                Executive,KernelMode,FALSE,0);

                            goto next;
                        }
                    }
                }
            }

		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
    else  //---------------------other--------------------------
    {
		KdPrint(("~![tdi_fw] DeviceDispatch: ioctl for unknown DeviceObject 0x%x\n", DeviceObject));

		status = irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	return status;
}

/*
 * Dispatch routines call this function to complete their processing.
 */
NTSTATUS
tdi_dispatch_complete(PDEVICE_OBJECT fltdevobj,
                      PDEVICE_OBJECT old_devobj,
                      PIRP irp,
                      int filter,
					  PIO_COMPLETION_ROUTINE CompletionRoutine,
                      PVOID context)
{
    NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp);

	if (filter == FILTER_DENY)        // DENY: complete request with status "Access violation"
    {
		KdPrint(("[tdi_fw] tdi_dispatch_complete: [DROP!]"
            "fltdevobj: 0x%x, FileObj 0x%x : major 0x%x, minor 0x%x.\n",
			fltdevobj,
			irps->FileObject,
            irps->MajorFunction,
            irps->MinorFunction));

		if (irp->IoStatus.Status == STATUS_SUCCESS)
			status = irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        else
			status = irp->IoStatus.Status;

		IoCompleteRequest (irp, IO_NO_INCREMENT);	
	}
    else if (filter == FILTER_ALLOW)  // ALLOW: pass IRP to the next driver
    {
        if (CompletionRoutine)
        {
            PIO_STACK_LOCATION next_irps = IoGetNextIrpStackLocation(irp);

            KdPrint(("[tdi_fw] tdi_dispatch_complete[ALLOW]"
                "fltdevobj: 0x%x; FileObj 0x%x : major 0x%x, minor 0x%x.\n",
                fltdevobj,
                irps->FileObject,
                irps->MajorFunction,
                irps->MinorFunction));

            ASSERT( irp->CurrentLocation > 1 );

            memcpy(next_irps, irps, sizeof(*irps));
            IoSetCompletionRoutineEx(fltdevobj, irp, CompletionRoutine, context, TRUE, TRUE, TRUE);
        }
        else
            IoSkipCurrentIrpStackLocation(irp);

		status = IoCallDriver(old_devobj, irp);
	}
    else	/* FILTER_UNKNOWN : just complete the request */
    {
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest (irp, IO_NO_INCREMENT);
	}

	return status;
}

// for IOCTL_TDI_QUERY_DIRECT_SEND_HANDLER
NTSTATUS
g_new_TCPSendData(IN PIRP Irp, IN PIO_STACK_LOCATION IrpSp)
{
    PDEVICE_OBJECT old_devobj = get_original_devobj(IrpSp->DeviceObject, NULL);

	KdPrint(("[tdi_fw] new_TCPSendData ~\n"));

	tdi_send(Irp, IrpSp, NULL);

	// complete request
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(old_devobj, Irp);
}

/*
 * deny stub for dispatch table
 */
int
tdi_deny_stub(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
	KdPrint(("~![tdi_fw] tdi_deny_stub!\n"));
	return FILTER_DENY;
}

NTSTATUS
process_request(ULONG ctl_code, char *buf, OUT ULONG *out_len, ULONG buf_size)
{
    NTSTATUS status;
    ULONG len = *out_len;
    *out_len = 0;

    if (buf == NULL)
    {
        KdPrint(("~![tdi_fw] process_request() buf == NULL!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    switch (ctl_code)
    {
    case IOCTL_CMD_ENUM_LISTEN:
        // enum listening endpoints

//         if (buf_size < sizeof(struct listen_nfo))
//         {
//             status = STATUS_INFO_LENGTH_MISMATCH;
//             break;
//         }

        //status = enum_listen((struct listen_nfo *)buf, out_len, buf_size);
        break;

    case IOCTL_CMD_ENUM_TCP_CONN:
        // enum TCP connections

//         if (buf_size < sizeof(struct tcp_conn_nfo))
//         {
//             status = STATUS_INFO_LENGTH_MISMATCH;
//             break;
//         }

        //status = enum_tcp_conn((struct tcp_conn_nfo *)buf, out_len, buf_size);
        break;

    case IOCTL_CMD_GETREQUEST:
        // get data for logging

        if (buf_size < sizeof(flt_request) || buf == NULL) {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }

        status = STATUS_SUCCESS;
        break;

    case IOCTL_CMD_CLEARCHAIN:
        // clear rules chain #i

        if (len != sizeof(int) || buf == NULL) {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }

        status = clear_flt_chain(*(int *)buf);
        break;

    case IOCTL_CMD_APPENDRULE:
        // append rule to chain #i

        if (len != sizeof(struct _flt_rule) || buf == NULL) {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }

        //status = add_flt_rule(((struct _flt_rule *)buf)->chain, (struct _flt_rule *)buf);
        break;

    case IOCTL_CMD_SETCHAINPNAME:
        // set chain #i process name

        if (len < sizeof(int) + sizeof(char) || buf == NULL) {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        if (buf[len - 1] != '\0') {
            status = STATUS_INVALID_PARAMETER;	// string must be zero-terminated
            break;
        }

        status = set_chain_pname(*(int *)buf, buf + sizeof(int));
        break;

    case IOCTL_CMD_SETPNAME:
        // set process name for pid

        if (len < sizeof(ULONG) + sizeof(char) || buf == NULL) {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }
        if (buf[len - 1] != '\0') {
            status = STATUS_INVALID_PARAMETER;	// string must be zero-terminated
            break;
        }

        status = set_pid_pname(*(ULONG *)buf, buf + sizeof(ULONG));
        break;

    case IOCTL_CMD_ACTIVATECHAIN:
        // active rules chain #i

        if (len != sizeof(int) || buf == NULL) {
            status = STATUS_INFO_LENGTH_MISMATCH;
            break;
        }

        status = activate_flt_chain(*(int *)buf);
        break;

    case IOCTL_GET_TRAFFIC_COUNTERS: 
        {
            KIRQL irql;

            if (buf_size < 16) {
                status = STATUS_INFO_LENGTH_MISMATCH;
                break;
            }

            KeAcquireSpinLock(&g_traffic_lock, &irql);
            *  (unsigned __int64 *)buf       = g_traffic_in;
            *( (unsigned __int64 *)buf + 1 ) = g_traffic_out;
            KeReleaseSpinLock(&g_traffic_lock, irql);

            *out_len = 16;
            status = STATUS_SUCCESS;
            break;
        }

    default:
        status = STATUS_NOT_SUPPORTED;
    }

    return status;
}

int
tdi_set_event_handler(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion)
{
    int result = FILTER_ALLOW;
    PTDI_REQUEST_KERNEL_SET_EVENT r_set_event = (PTDI_REQUEST_KERNEL_SET_EVENT)&irps->Parameters;
    struct _addr_entry *ae = NULL;
    KIRQL irql;

    if (r_set_event->EventType < 0 || r_set_event->EventType > MAX_EVENT) {
        KdPrint(("[tdi_fw] tdi_set_event_handler: unknown EventType %d!\n", r_set_event->EventType));
        return result;
    }
    
    if (r_set_event->EventHandler != NULL)
    {
        if (tdi_event_handler[r_set_event->EventType] != NULL)
        {
            KdPrint(("[tdi_fw] tdi_set_event_handler[%s]: fltdevobj: 0x%x; FileObj 0x%x; EventType: %d\n",
                "(+)",
                irps->DeviceObject,
                irps->FileObject,
                r_set_event->EventType));

            KdPrint(("[tdi_fw]  -tdi_set_event_handler: old_handler 0x%x; old_context 0x%x\n",
                r_set_event->EventHandler, r_set_event->EventContext));

            ae = find_addr_entry(irps->FileObject, &irql);
            if (ae == NULL)
                return result;

            ae->tdi_event_context[r_set_event->EventType].routine = r_set_event->EventHandler;
            ae->tdi_event_context[r_set_event->EventType].context = r_set_event->EventContext;

            r_set_event->EventHandler = tdi_event_handler[r_set_event->EventType];
            r_set_event->EventContext = ae;

            KeReleaseSpinLock(&g_addr_list_lock, irql);
        }
    }

    if (!g_LogEnable)
        return result;

    // change LISTEN state
    if (r_set_event->EventType == TDI_EVENT_CONNECT)
    {
        TA_ADDRESS *local_addr;

        if (ae == NULL)
        {
            ae = find_addr_entry(irps->FileObject, &irql);
            if (ae == NULL) {
                KdPrint(("~![tdi_fw] tdi_set_event_handler: find_addr_entry(0x%x)!\n", irps->FileObject));
                return result;
            }
        }
        else
            KeAcquireSpinLock(&g_addr_list_lock, &irql);

        // log it if address is not 127.0.0.1
        local_addr = (TA_ADDRESS *)(ae->local_addr);
        if ( ((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr != 0x100007f )
        {
            flt_request *r;

            r = malloc_np(sizeof(flt_request));
            if (r == NULL) {
                KdPrint(("~!![tdi_fw] tdi_set_event_handler: malloc_np\n"));
                goto done;
            }
            memset(r, 0, sizeof(flt_request));

            r->tcp_conn_state = (r_set_event->EventHandler != NULL) ? TYPE_LISTEN : TYPE_NOT_LISTEN;
            r->proto = IPPROTO_TCP;
            r->pid = (ULONG)PsGetCurrentProcessId();
            memcpy(&r->addr.from, &local_addr->AddressType, sizeof(struct sockaddr));

            KeReleaseSpinLock(&g_addr_list_lock, irql);
            ae = NULL;

            InsertRequestList(r);
        }
done:
        if (ae)
            KeReleaseSpinLock(&g_addr_list_lock, irql);
    }
    
    return result;
}
