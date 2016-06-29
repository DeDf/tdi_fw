//===========================================================
#pragma once

#include <ntddk.h>
#include <tdikrnl.h>

#include "sock.h"
#include "memtrack.h"
#include "struct.h"
#include "ipc.h"

extern PVOID g_tdi_ioctls[];
extern PVOID tdi_event_handler[];

extern PDEVICE_OBJECT g_tcpoldobj, g_udpoldobj, g_ipoldobj;
extern PDEVICE_OBJECT g_tcpfltobj, g_udpfltobj, g_ipfltobj;

extern BOOLEAN g_NET_DENY;
extern BOOLEAN g_FltEnable;
extern BOOLEAN g_LogEnable;

// traffic counters
extern KSPIN_LOCK g_traffic_lock;
extern unsigned __int64 g_traffic_in;
extern unsigned __int64 g_traffic_out;

// request_list
extern LIST_ENTRY  request_list_head;
extern KSPIN_LOCK  request_list_lock;
extern KEVENT      g_request_event;
extern ULONG       g_request_count;

struct _get_localaddr_workitem_param {
    WORK_QUEUE_ITEM	WorkItem;
    PDEVICE_OBJECT	devobj;
    PFILE_OBJECT	fileobj;
    flt_request* pRequest;
};

typedef int tdi_ioctl_fn_t(PIRP irp, PIO_STACK_LOCATION irps, struct _completion *completion);

tdi_ioctl_fn_t
tdi_associate_address,
tdi_connect,
tdi_disassociate_address,
tdi_set_event_handler,
tdi_send_datagram,
tdi_receive_datagram,
tdi_disconnect,
tdi_send,
tdi_receive,
tdi_deny_stub;

//======================Native API===========================

extern POBJECT_TYPE	IoDriverObjectType;

NTSTATUS
NTAPI
ZwWaitForSingleObject(
                      IN HANDLE hObject,
                      IN BOOLEAN bAlertable,
                      IN PLARGE_INTEGER Timeout
                      );

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName	(
	IN PUNICODE_STRING	ObjectName,
	IN ULONG			Attributes,
	IN PACCESS_STATE	PassedAccessState OPTIONAL,
	IN ACCESS_MASK		DesiredAccess OPTIONAL,
	IN POBJECT_TYPE		ObjectType OPTIONAL,
	IN KPROCESSOR_MODE	AccessMode,
	IN OUT PVOID		ParseContext OPTIONAL,
	OUT	PVOID			*Object
);

NTSTATUS
NTAPI
ZwCreateEvent (
	OUT	PHANDLE				EventHandle,
	IN ACCESS_MASK			DesiredAccess,
	IN POBJECT_ATTRIBUTES	ObjectAttributes OPTIONAL,
	IN EVENT_TYPE			EventType,
	IN BOOLEAN				InitialState
);

NTSTATUS
NTAPI
ZwOpenThreadToken (
	IN HANDLE		ThreadHandle,
	IN ACCESS_MASK	DesiredAccess,
	IN BOOLEAN		OpenAsSelf,
	OUT	PHANDLE		TokenHandle
);

NTSTATUS
NTAPI
ZwOpenProcessToken (
	IN HANDLE       ProcessHandle,
	IN ACCESS_MASK  DesiredAccess,
	OUT PHANDLE     TokenHandle
);

typedef	enum _TOKEN_INFORMATION_CLASS {
	TokenUser =	1,
	TokenGroups,
	TokenPrivileges,
	TokenOwner,
	TokenPrimaryGroup,
	TokenDefaultDacl,
	TokenSource,
	TokenType,
	TokenImpersonationLevel,
	TokenStatistics,
	TokenRestrictedSids
} TOKEN_INFORMATION_CLASS;

NTSTATUS
NTAPI
ZwQueryInformationToken	(
	IN HANDLE					TokenHandle,
	IN TOKEN_INFORMATION_CLASS	TokenInformationClass,
	OUT	PVOID					TokenInformation,
	IN ULONG					Length,
	OUT	PULONG					ResultLength
);

//===========================================================

PDEVICE_OBJECT
get_original_devobj(PDEVICE_OBJECT flt_devobj, OPTIONAL OUT int *proto);

//===========================event=============================

NTSTATUS tdi_event_connect(
                           IN PVOID TdiEventContext,
                           IN LONG RemoteAddressLength,
                           IN PVOID RemoteAddress,
                           IN LONG UserDataLength,
                           IN PVOID UserData,
                           IN LONG OptionsLength,
                           IN PVOID Options,
                           OUT CONNECTION_CONTEXT *ConnectionContext,
                           OUT PIRP *AcceptIrp);

NTSTATUS tdi_event_disconnect(
                              IN PVOID TdiEventContext,
                              IN CONNECTION_CONTEXT ConnectionContext,
                              IN LONG DisconnectDataLength,
                              IN PVOID DisconnectData,
                              IN LONG DisconnectInformationLength,
                              IN PVOID DisconnectInformation,
                              IN ULONG DisconnectFlags);

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
                                    OUT PIRP *IoRequestPacket);

NTSTATUS tdi_event_receive(
                           IN PVOID TdiEventContext,
                           IN CONNECTION_CONTEXT ConnectionContext,
                           IN ULONG ReceiveFlags,
                           IN ULONG BytesIndicated,
                           IN ULONG BytesAvailable,
                           OUT ULONG *BytesTaken,
                           IN PVOID Tsdu,
                           OUT PIRP *IoRequestPacket);

NTSTATUS tdi_event_chained_receive(
                                   IN PVOID TdiEventContext,
                                   IN CONNECTION_CONTEXT ConnectionContext,
                                   IN ULONG ReceiveFlags,
                                   IN ULONG ReceiveLength,
                                   IN ULONG StartingOffset,
                                   IN PMDL  Tsdu,
                                   IN PVOID TsduDescriptor);

//========================filter============================

NTSTATUS	filter_init(void);
void		filter_free(void);

NTSTATUS	add_flt_rule(int chain, const struct _flt_rule *rule);
NTSTATUS	clear_flt_chain(int chain);
NTSTATUS	activate_flt_chain(int chain);
NTSTATUS	set_chain_pname(int chain, char *pname);
NTSTATUS	set_pid_pname(ULONG pid, char *pname);

int			quick_filter(flt_request *request, struct _flt_rule *rule);
VOID        InsertRequestList(flt_request *r);

//============================================================
void		get_localaddr_workitem(PVOID p);
//============================================================