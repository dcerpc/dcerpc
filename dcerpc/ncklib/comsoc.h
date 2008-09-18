/*
 * 
 * (c) Copyright 1989 OPEN SOFTWARE FOUNDATION, INC.
 * (c) Copyright 1989 HEWLETT-PACKARD COMPANY
 * (c) Copyright 1989 DIGITAL EQUIPMENT CORPORATION
 * To anyone who acknowledges that this file is provided "AS IS"
 * without any express or implied warranty:
 *                 permission to use, copy, modify, and distribute this
 * file for any purpose is hereby granted without fee, provided that
 * the above copyright notices and this notice appears in all source
 * code copies, and that none of the names of Open Software
 * Foundation, Inc., Hewlett-Packard Company, or Digital Equipment
 * Corporation be used in advertising or publicity pertaining to
 * distribution of the software without specific, written prior
 * permission.  Neither Open Software Foundation, Inc., Hewlett-
 * Packard Company, nor Digital Equipment Corporation makes any
 * representations about the suitability of this software for any
 * purpose.
 * 
 */
/*
 */
#ifndef _COMSOC_H
#define _COMSOC_H	1
/*
**
**  NAME:
**
**      comsoc.h
**
**  FACILITY:
**
**      Remote Procedure Call (RPC) 
**
**  ABSTRACT:
**
**  The internal network "socket" object interface.  A very thin veneer
**  over the BSD socket abstraction interfaces.  This makes life a little
**  easier when porting to different environments.
**  
**  All operations return a standard error value of type
**  rpc_socket_error_t, operate on socket handles of type rpc_socket_t
**  and socket addresses of type rpc_socket_addr_t.  These are the types
**  that one should use when coding.
**  
**  Note that there is a distinction between local runtime internal
**  representations of socket addresses and architected (on-the-wire)
**  representations used by location services.  This interface specifies
**  the local runtime internal representation.
**  
**  Operations that return an error value always set the value
**  appropriately.  A value other than rpc_c_socket_ok indicates failure;
**  the values of additional output parameters are undefined.  Other
**  error values are system dependent.
**
**
*/


/*
 * Include platform-specific socket definitions
 */

#ifndef _DCE_PROTOTYPE_
#include <dce/dce.h>
#endif




/*
 * Changing anything below will affect other portions of the runtime.
 */

/* a BSD UNIX iovec */
/*typedef struct {  
    byte_p_t base;
    int len;
}*/
typedef struct iovec rpc_socket_iovec_t;
typedef struct iovec *rpc_socket_iovec_p_t;

#include <comsoc_sys.h>
#include <comnaf.h>
#include <ipnaf.h>
#include <cnp.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * R P C _ _ S O C K E T _ O P E N
 *
 * Create a new socket for the specified Protocol Sequence.
 * The new socket has blocking IO semantics.
 *
 * (see BSD UNIX socket(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_open _DCE_PROTOTYPE_((
        rpc_protseq_id_t pseq_id,
        rpc_socket_t * /*sock*/
    ));


/*
 * R P C _ _ S O C K E T _ O P E N _ B A S I C
 *
 * A special version of socket_open that is used *only* by 
 * the low level initialization code when it is trying to 
 * determine what network services are supported by the host OS.
 */

PRIVATE rpc_socket_error_t rpc__socket_open_basic _DCE_PROTOTYPE_((
        rpc_naf_id_t  /*naf*/,
        rpc_network_if_id_t  /*net_if*/,
        rpc_network_protocol_id_t  /*net_prot*/,
        rpc_socket_t * /*sock*/
    ));


/*
 * R P C _ _ S O C K E T _ C L O S E
 *
 * Close (destroy) a socket.
 *
 * (see BSD UNIX close(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_close _DCE_PROTOTYPE_((
        rpc_socket_t /*sock*/
    ));


/*
 * R P C _ _ S O C K E T _ B I N D
 *
 * Bind a socket to a specified local address.
 *
 * (see BSD UNIX bind(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_bind _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/,
        rpc_addr_p_t /*addr*/
    ));


/*
 * R P C _ _ S O C K E T _ C O N N E C T
 *
 * Connect a socket to a specified peer's address.
 * This is used only by Connection oriented Protocol Services.
 *
 * (see BSD UNIX connect(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_connect _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/,
        rpc_addr_p_t /*addr*/,
	rpc_cn_assoc_t* /*assoc*/
    ));


/*
 * R P C _ _ S O C K E T _ A C C E P T
 *
 * Accept a connection on a socket, creating a new socket for the new
 * connection.  A rpc_addr_t appropriate for the NAF corresponding to
 * this socket must be provided.  addr.len must set to the actual size
 * of addr.sa.  This operation fills in addr.sa and sets addr.len to
 * the new size of the field.  This is used only by Connection oriented
 * Protocol Services.
 * 
 * (see BSD UNIX accept(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_accept _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/,
        rpc_addr_p_t  /*addr*/,
        rpc_socket_t * /*newsock*/
    ));


/*
 * R P C _ _ S O C K E T _ L I S T E N
 *
 * Listen for a connection on a socket.
 * This is used only by Connection oriented Protocol Services.
 *
 * (see BSD UNIX listen(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_listen _DCE_PROTOTYPE_((
        rpc_socket_t /*sock*/,
        int /*backlog*/
    ));


/*
 * R P C _ _ S O C K E T _ S E N D M S G
 *
 * Send a message over a given socket.  An error code as well as the
 * actual number of bytes sent are returned.
 *
 * (see BSD UNIX sendmsg(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_sendmsg _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/,
        rpc_socket_iovec_p_t  /*iov*/,   /* array of bufs of data to send */
        int  /*iov_len*/,        /* number of bufs */
        rpc_addr_p_t  /*addr*/,  /* addr of receiver */
        int * /*cc*/             /* returned number of bytes actually sent */
    ));


/*
 * R P C _ _ S O C K E T _ R E C V F R O M
 *
 * Recieve the next buffer worth of information from a socket.  A
 * rpc_addr_t appropriate for the NAF corresponding to this socket must
 * be provided.  addr.len must set to the actual size of addr.sa.  This
 * operation fills in addr.sa and sets addr.len to the new size of the
 * field.  An error status as well as the actual number of bytes received
 * are also returned.
 * 
 * (see BSD UNIX recvfrom(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_recvfrom _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/,
        byte_p_t  /*buf*/,       /* buf for rcvd data */
        int  /*len*/,            /* len of above buf */
        rpc_addr_p_t  /*from*/,  /* addr of sender */
        int * /*cc*/             /* returned number of bytes actually rcvd */
    ));


/*
 * R P C _ _ S O C K E T _ R E C V M S G
 *
 * Receive a message over a given socket.  A rpc_addr_t appropriate for
 * the NAF corresponding to this socket must be provided.  addr.len must
 * set to the actual size of addr.sa.  This operation fills in addr.sa
 * and sets addr.len to the new size of the field.  An error code as
 * well as the actual number of bytes received are also returned.
 * 
 * (see BSD UNIX recvmsg(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_recvmsg _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/,
        rpc_socket_iovec_p_t  /*iov*/,   /* array of bufs for rcvd data */
        int  /*iov_len*/,        /* number of bufs */
        rpc_addr_p_t  /*addr*/,  /* addr of sender */
        int * /*cc*/             /* returned number of bytes actually rcvd */
    ));


/*
 * R P C _ _ S O C K E T _ I N Q _ A D D R
 *
 * Return the local address associated with a socket.  A rpc_addr_t
 * appropriate for the NAF corresponding to this socket must be provided.
 * addr.len must set to the actual size of addr.sa.  This operation fills
 * in addr.sa and sets addr.len to the new size of the field.
 *
 * !!! NOTE: You should use rpc__naf_desc_inq_addr() !!!
 *
 * This routine is indended for use only by the internal routine:
 * rpc__naf_desc_inq_addr().  rpc__socket_inq_endpoint() only has the
 * functionality of BSD UNIX getsockname() which doesn't (at least not
 * on all systems) return the local network portion of a socket's address.
 * rpc__naf_desc_inq_addr() returns the complete address for a socket.
 *
 * (see BSD UNIX getsockname(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_inq_endpoint _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/,
        rpc_addr_p_t /*addr*/
    ));


/*
 * R P C _ _ S O C K E T _ S E T _ B R O A D C A S T
 *
 * Enable broadcasting for the socket (as best it can).
 * Used only by Datagram based Protocol Services.
 */

PRIVATE rpc_socket_error_t rpc__socket_set_broadcast _DCE_PROTOTYPE_((
        rpc_socket_t /*sock*/
    ));


/*
 * R P C _ _ S O C K E T _ S E T _ B U F S
 *
 * Set the socket's send and receive buffer sizes and return the new
 * values.
 * 
 * (similar to BSD UNIX setsockopt()).
 */

PRIVATE rpc_socket_error_t rpc__socket_set_bufs _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/, 
        unsigned32  /*txsize*/, 
        unsigned32  /*rxsize*/, 
        unsigned32 * /*ntxsize*/, 
        unsigned32 * /*nrxsize*/
    ));


/*
 * R P C _ _ S O C K E T _ S E T _ N B I O
 *
 * Set a socket to non-blocking mode.
 *
 * (see BSD UNIX fcntl(sock, F_SETFL, O_NDELAY))
 */

PRIVATE rpc_socket_error_t rpc__socket_set_nbio _DCE_PROTOTYPE_((
        rpc_socket_t /*sock*/
    ));


/*
 * R P C _ _ S O C K E T _ S E T _ C L O S E _ O N _ E X E C
 *
 * Set a socket to a mode whereby it is not inherited by a spawned process
 * executing some new image. This is possibly a no-op on some systems.
 *
 * (see BSD UNIX fcntl(sock, F_SETFD, 1))
 */

PRIVATE rpc_socket_error_t rpc__socket_set_close_on_exec _DCE_PROTOTYPE_((
        rpc_socket_t /*sock*/
    ));

/*
 * R P C _ _ S O C K E T _ G E T P E E R N A M E
 *
 * Get name of connected peer.
 * This is used only by Connection oriented Protocol Services.
 *
 * (see BSD UNIX getpeername(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_getpeername _DCE_PROTOTYPE_ ((
        rpc_socket_t  /*sock*/,
        rpc_addr_p_t /*addr*/
    ));

/*
 * R P C _ _ S O C K E T _ G E T _ I F _ I D
 *
 * Get socket network interface id (socket type).
 *
 * (see BSD UNIX getsockopt(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_get_if_id _DCE_PROTOTYPE_ ((
        rpc_socket_t         /*sock*/,
        rpc_network_if_id_t * /*network_if_id*/
    ));

/*
 * R P C _ _ S O C K E T _ S E T _ K E E P A L I V E.
 *
 * Set keepalive option for connection.
 * Used only by Connection based Protocol Services.
 *
 * (see BSD UNIX setsockopt(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_set_keepalive _DCE_PROTOTYPE_ ((
        rpc_socket_t        /*sock*/
    ));

/*
 * R P C _ _ S O C K E T _ N O W R I T E B L O C K _ W A I T
 *
 * Wait until the a write on the socket should succede without
 * blocking.  If tmo is NULL, the wait is unbounded, otherwise
 * tmo specifies the max time to wait. rpc_c_socket_etimedout
 * if a timeout occurs.  This operation in not cancellable.
 */

PRIVATE rpc_socket_error_t rpc__socket_nowriteblock_wait _DCE_PROTOTYPE_((
        rpc_socket_t  /*sock*/,
        struct timeval * /*tmo*/
    ));

/*
 * R P C _ _ S O C K E T _ S E T _ R C V T I M E O
 *
 * Set receive timeout option for connection.
 * Used only by Connection based Protocol Services.
 *
 * (see BSD UNIX setsockopt(2)).
 */

PRIVATE rpc_socket_error_t rpc__socket_set_rcvtimeo _DCE_PROTOTYPE_ ((
        rpc_socket_t,       /*sock*/
        struct timeval *    /*tmo*/
    ));

/*
 * R P C _ _ S O C K E T _ G E T P E E R E I D
 *
 * Get UNIX domain socket peer credentials
 */

PRIVATE rpc_socket_error_t rpc__socket_getpeereid _DCE_PROTOTYPE_ ((
	rpc_socket_t,	    /*sock*/
	uid_t *,
	gid_t *
    ));

#endif /* _COMSOC_H */
