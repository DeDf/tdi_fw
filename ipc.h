// Copyright (c) 2002-2005 Vladislav Goncharov.

#ifndef _ipc_h_
#define _ipc_h_

/* ioctls */

#define FILE_DEVICE_TDI_FW		0x8e86

#define IOCTL_CMD_GETREQUEST	    CTL_CODE(FILE_DEVICE_TDI_FW, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CMD_CLEARCHAIN	    CTL_CODE(FILE_DEVICE_TDI_FW, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CMD_APPENDRULE	    CTL_CODE(FILE_DEVICE_TDI_FW, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CMD_SETCHAINPNAME 	CTL_CODE(FILE_DEVICE_TDI_FW, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CMD_SETPNAME		    CTL_CODE(FILE_DEVICE_TDI_FW, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CMD_ACTIVATECHAIN 	CTL_CODE(FILE_DEVICE_TDI_FW, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CMD_SET_SIDS		    CTL_CODE(FILE_DEVICE_TDI_FW, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CMD_ENUM_LISTEN	    CTL_CODE(FILE_DEVICE_TDI_FW, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CMD_ENUM_TCP_CONN	    CTL_CODE(FILE_DEVICE_TDI_FW, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_TRAFFIC_COUNTERS	CTL_CODE(FILE_DEVICE_TDI_FW, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*
 * direction type
 */
#define DIRECTION_IN	1  // TCP - accept connections; UDP - receive datagram;
#define DIRECTION_OUT	0  // TCP - connect           ; UDP - send    datagram;
#define DIRECTION_ANY	-1

#define FILTER_ALLOW 1
#define FILTER_DENY  0

#define IPPROTO_ANY		-1

/* types of request */
enum _tcp_conn_state {
	TYPE_CONNECT = 1,
	TYPE_CONNECT_ERROR,
	TYPE_LISTEN,
	TYPE_NOT_LISTEN,
	TYPE_CONNECT_CANCELED,
	TYPE_CONNECT_RESET,
	TYPE_CONNECT_TIMEOUT,
	TYPE_CONNECT_UNREACH
};

#pragma pack(1)

/*
 * request for filter
 */
typedef struct _flt_request {
    LIST_ENTRY list_entry;

    ULONG	pid;
    ULONG	tid;

    int		proto;			/* see IPPROTO_xxx */
    int		direction;		/* see DIRECTION_xxx */
	int		tcp_conn_state;	/* see TCP_CONNECT_STATE */
	int		flt_result;		/* FILTER_ALLOW or FILTER_DENY */

	struct {
		struct	sockaddr from;
		struct	sockaddr to;
	} addr;

	/* info from packet filter (valid for FILTER_PACKET_LOG) */
	struct {
		int		is_broadcast;	// 0 or 1 (for now unused)
		UCHAR	tcp_flags;
		UCHAR	icmp_type;
		UCHAR	icmp_code;
		int		tcp_state;		// see TCP_STATE_xxx
	} packet;
	
	/* info for logging */
	ULONG	log_bytes_in;
	ULONG	log_bytes_out;

	/* for internal use (like private:) */
	//char	*pname;
} flt_request;

// I think 128 is a good number :-) (better than 256 :))
#define MAX_CHAINS_COUNT	128

/*
 * IP rule for quick filter (addr & port are in network order)
 */
struct _flt_rule
{
	struct	_flt_rule *next;		// for internal use

	int		result;
	int		proto;
	int		direction;

	ULONG	addr_from;
	USHORT	port_from;

	ULONG	addr_to;
	USHORT	port_to;

	int		log;			/* see RULE_LOG_xxx */
};

/*
 * TCP states
 */
enum _TCP_STATE {
	TCP_STATE_NONE,
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RCVD,
	TCP_STATE_ESTABLISHED_IN,
	TCP_STATE_ESTABLISHED_OUT,
	TCP_STATE_FIN_WAIT1,
	TCP_STATE_FIN_WAIT2,
	TCP_STATE_TIME_WAIT,
	TCP_STATE_CLOSE_WAIT,
	TCP_STATE_LAST_ACK,
	TCP_STATE_CLOSED,
	
	TCP_STATE_MAX
};

#pragma pack()

#endif
