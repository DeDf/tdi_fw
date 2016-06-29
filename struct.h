//=======================================
#ifndef _struct_h_
#define _struct_h_

#define HASH_SIZE	0x1000
#define CALC_HASH(addrobj)  (((ULONG)(addrobj) >> 5) % HASH_SIZE)

extern struct _addr_entry **g_addr_list;
extern KSPIN_LOCK g_addr_list_lock;

extern struct _conn_entry **g_conn_list;
extern KSPIN_LOCK g_conn_list_lock;

struct _completion {
    PIO_COMPLETION_ROUTINE	routine;
    PVOID					context;
};

struct _addr_entry {
	struct _addr_entry	*next;
	//
	ULONG				pid;
    ULONG               tid;
	//
    PFILE_OBJECT		addrobj;
    PFILE_OBJECT		connobj;	// for ass-connection object
	PDEVICE_OBJECT		fltdevobj;
    PDEVICE_OBJECT		olddevobj;
    int					ipproto;
	//
    struct _completion  tdi_event_context[MAX_EVENT + 1];
	UCHAR				local_addr [TA_ADDRESS_MAX];
	UCHAR				remote_addr[TA_ADDRESS_MAX];

	// traffic count for connection object
	ULONG				bytes_send;
	ULONG				bytes_receive;
};

struct _conn_entry {
    struct _conn_entry *next;

    PFILE_OBJECT	   connobj;
    struct _addr_entry *addr_entry;  // // for ass-_addr_entry
    CONNECTION_CONTEXT conn_ctx;
};

struct _tdi_irp_ctx {
    struct _addr_entry      *addr_entry;
    PFILE_OBJECT            connobj;
    PIO_COMPLETION_ROUTINE	old_cr;
    PVOID					old_context;
    UCHAR					old_control;
};

//=================================================

NTSTATUS	ot_init(void);
void		ot_free(void);

NTSTATUS
add_addrobj(PFILE_OBJECT addrobj,
            PDEVICE_OBJECT fltdevobj,
            PDEVICE_OBJECT olddevobj,
            int ipproto);

struct _addr_entry *
    find_addr_entry(PFILE_OBJECT fileobj, KIRQL *irql);

VOID del_addr_entry(PFILE_OBJECT addrobj);

NTSTATUS
add_connobj(PFILE_OBJECT connobj, CONNECTION_CONTEXT conn_ctx);

struct _conn_entry *
    find_conn_entry(PFILE_OBJECT connobj, KIRQL *irql);

VOID del_conn_entry(PFILE_OBJECT connobj);

#endif
