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
#ifndef _COMSOC_BSD_H
#define _COMSOC_BSD_H	1
/*
**
**  NAME:
**
**      comsoc_bsd.h
**
**  FACILITY:
**
**      Remote Procedure Call (RPC) 
**
**  ABSTRACT:
**
**  The platform-specific portion of the internal network "socket" object
**  interface.  See abstract in "comsoc.h" for details.
**
**  For BSD 4.3 & 4.4 systems.  
**
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef _DCE_PROTOTYPE_
#include <dce/dce.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/*
 * A handle to a socket.  The implementation of this type is considered
 * to be private to this package.
 */

typedef int rpc_socket_t;                       /* a UNIX socket handle */

/*
 * A public function for comparing two socket handles.
 */

#define RPC_SOCKET_IS_EQUAL(s1, s2)             (s1 == s2)


/*
 * This package's error type and values.  The implementation of this
 * type is considered to be private to this package.
 */

typedef int rpc_socket_error_t;                 /* a UNIX errno */

#include <comnaf.h>
#include <commonp.h>
#include <ipnaf.h>

/*
 * The maximum number of iov elements which can be sent through
 * sendmsg is MSG_IOVLEN-1.
 */
#define RPC_C_MAX_IOVEC_LEN ( MSG_MAXIOVLEN - 1)

/*
 * The maximum number of connections which can be queued on a socket.
 */
#define RPC_C_LISTEN_BACKLOG SOMAXCONN

/*
 * Public error constants and functions for comparing errors.
 * The _ETOI_ (error-to-int) function converts a socket error to a simple
 * integer value that can be used in error mesages.
 */

#define RPC_C_SOCKET_OK           0             /* a successful error value */
#define RPC_C_SOCKET_EWOULDBLOCK  EWOULDBLOCK   /* operation would block */
#define RPC_C_SOCKET_EINTR        EINTR         /* operation was interrupted */
#define RPC_C_SOCKET_EIO          EIO           /* I/O error */
#define RPC_C_SOCKET_EADDRINUSE   EADDRINUSE    /* address was in use (see bind) */
#define RPC_C_SOCKET_ECONNRESET   ECONNRESET    /* connection reset by peer */
#define RPC_C_SOCKET_ETIMEDOUT    ETIMEDOUT     /* connection request timed out*/
#define RPC_C_SOCKET_ECONNREFUSED ECONNREFUSED  /* connection request refused */
#define RPC_C_SOCKET_ENOTSOCK     ENOTSOCK      /* descriptor was not a socket */
#define RPC_C_SOCKET_ENETUNREACH  ENETUNREACH   /* network is unreachable*/
#define RPC_C_SOCKET_ENOSPC       ENOSPC        /* no local or remote resources */
#define RPC_C_SOCKET_ENETDOWN     ENETDOWN      /* network is down */
#define RPC_C_SOCKET_ETOOMANYREFS ETOOMANYREFS  /* too many remote connections */
#define RPC_C_SOCKET_ESRCH        ESRCH         /* remote endpoint not found */
#define RPC_C_SOCKET_EHOSTDOWN    EHOSTDOWN     /* remote host is down */
#define RPC_C_SOCKET_EHOSTUNREACH EHOSTUNREACH  /* remote host is unreachable */
#define RPC_C_SOCKET_ECONNABORTED ECONNABORTED  /* local host aborted connect */
#define RPC_C_SOCKET_ECONNRESET   ECONNRESET    /* remote host reset connection */
#define RPC_C_SOCKET_ENETRESET    ENETRESET     /* remote host crashed */
#define RPC_C_SOCKET_ENOEXEC      ENOEXEC       /* invalid endpoint format for remote */
#define RPC_C_SOCKET_EACCESS      EACCES        /* access control information */
                                                /* invalid at remote node */
#define RPC_C_SOCKET_EPIPE        EPIPE         /* a write on a pipe */
                                                /* or socket for which there */
                                                /* is no process to */
                                                /* read the data. */
#define RPC_C_SOCKET_EAGAIN       EAGAIN        /* no more processes */
#define RPC_C_SOCKET_EALREADY     EALREADY      /* operation already */
                                                /* in progress */
#define RPC_C_SOCKET_EDEADLK      EDEADLK       /* resource deadlock */
                                                /* would occur */
#define RPC_C_SOCKET_EINPROGRESS  EINPROGRESS   /* operation now in */
                                                /* progress */
#define RPC_C_SOCKET_EISCONN      EISCONN       /* socket is already */
                                                /* connected */

/*
 * A macro to determine if an socket error can be recovered from by
 * retrying.
 */
#define RPC_SOCKET_ERR_IS_BLOCKING(s) \
    ((s == RPC_C_SOCKET_EAGAIN) || (s == RPC_C_SOCKET_EWOULDBLOCK) || (s == RPC_C_SOCKET_EINPROGRESS) || \
     (s == RPC_C_SOCKET_EALREADY) || (s == RPC_C_SOCKET_EDEADLK))

#define RPC_SOCKET_ERR_EQ(serr, e)  ((serr) == e)

#define RPC_SOCKET_IS_ERR(serr)     (! RPC_SOCKET_ERR_EQ(serr, RPC_C_SOCKET_OK))

#define RPC_SOCKET_ETOI(serr)       (serr)

/*
 * Macros to paper over the difference between the 4.4bsd and 4.3bsd
 * socket API.
 *
 * The layout of a 4.4 struct sockaddr includes a 1 byte "length" field
 * which used to be one of the bytes of the "family" field.  (The "family"
 * field is now 1 byte instead of 2 bytes.)  4.4 provides binary
 * compatibility with applications compiled with a 4.3 sockaddr definition
 * by inferring a default length when the supplied length is zero.  Source
 * compatibility is blown however (if _SOCKADDR_LEN is #define'd) --
 * applications that assign only to the "family" field will leave the
 * "length" field possibly non-zero.
 *
 * Note that RPC's "sockaddr_t" is always defined to contains only a
 * family.  (We defined "rpc_addr_t" to be a struct that contains a length
 * and a sockaddr rather than mucking with the sockaddr itself.)  We
 * assumed that "sockaddr_t" and "struct sockaddr" are the same.  At
 * 4.4, this assumption caused problems.  We use RPC_SOCKET_FIX_ADDRLEN
 * at various opportunities to make sure sockaddrs' length is zero and
 * that makes the problems go away.
 *
 * ADDENDUM:
 *    This only makes the problem go away on little-endian systems
 *    where the length field on the 4.4 struct occupies the same position
 *    as the high byte of the family field on the 4.3 struct.  This is
 *    no good for i386 FreeBSD, so we have actually adapted sockaddr_t
 *    to match the system struct sockaddr.
 *                                           -- Brian Koropoff, Likewise
 *
 * RPC_SOCKET_FIX_ADDRLEN takes an "rpc_addr_p_t" (or "rpc_ip_addr_p_t")
 * as input.  The complicated casting (as opposed to simply setting
 * ".sa_len" to zero) is to ensure that the right thing happens regardless
 * of the integer endian-ness of the system).
 *
 * RPC_SOCKET_INIT_MGRHDR deals with the differences in the field names of
 * the "struct msghdr" data type between 4.3 and 4.4.
 */

#ifdef BSD_4_4_SOCKET
#define RPC_SOCKET_INIT_MSGHDR(msgp) ( \
    (msgp)->msg_control         = NULL, \
    (msgp)->msg_controllen      = 0, \
    (msgp)->msg_flags           = 0 \
)
#else
#define RPC_SOCKET_INIT_MSGHDR(msgp) ( \
    (msgp)->msg_accrights       = NULL, \
    (msgp)->msg_accrightslen    = 0 \
)
#endif /* BSD_4_4_SOCKET */

/*#if defined(_SOCKADDR_LEN)
#define RPC_SOCKET_FIX_ADDRLEN(addrp) ( \
      ((struct osockaddr *) &(addrp)->sa)->sa_family = \
              ((struct sockaddr *) &(addrp)->sa)->sa_family \
  )
  #else*/
#define RPC_SOCKET_FIX_ADDRLEN(addrp) do { } while (0)
/*#endif*/

/*
 * Macros for performance critical operations.
 */

inline static void RPC_SOCKET_SENDMSG(
	rpc_socket_t sock,
	rpc_socket_iovec_p_t iovp,
	int iovlen,
	rpc_addr_p_t addrp,
	volatile int *ccp,
  	volatile rpc_socket_error_t *serrp
		)
{
	struct msghdr msg; 
sendmsg_again:
	memset(&msg, 0, sizeof(msg));
	RPC_LOG_SOCKET_SENDMSG_NTR;
	RPC_SOCKET_INIT_MSGHDR(&msg);
	if ((addrp) != NULL)
	{
		RPC_SOCKET_FIX_ADDRLEN(addrp);
		msg.msg_name = (caddr_t) &(addrp)->sa;
		msg.msg_namelen = (addrp)->len;
	}
	else
	{
		msg.msg_name = (caddr_t) NULL;
	}
	msg.msg_iov = (struct iovec *) iovp;
	msg.msg_iovlen = iovlen;
	*(ccp) = dcethread_sendmsg ((int) sock, (struct msghdr *) &msg, 0);
	*(serrp) = (*(ccp) == -1) ? errno : RPC_C_SOCKET_OK;
	RPC_LOG_SOCKET_SENDMSG_XIT;
	if (*(serrp) == EINTR)
	{
		goto sendmsg_again;
	}
}

#if 0
#define RPC_SOCKET_SENDMSG(sock, iovp, iovlen, addrp, ccp, serrp) \
    { \
        struct msghdr msg; \
sendmsg_again:\
			memset(&msg, 0, sizeof(msg));	\
        RPC_LOG_SOCKET_SENDMSG_NTR; \
        RPC_SOCKET_INIT_MSGHDR(&msg); \
        if ((addrp) != NULL)\
        {\
            RPC_SOCKET_FIX_ADDRLEN(addrp); \
            msg.msg_name = (caddr_t) &(addrp)->sa; \
            msg.msg_namelen = (addrp)->len; \
        }\
        else\
        {\
            msg.msg_name = (caddr_t) NULL;\
        }\
        msg.msg_iov = (struct iovec *) iovp; \
        msg.msg_iovlen = iovlen; \
        *(ccp) = dcethread_sendmsg ((int) sock, (struct msghdr *) &msg, 0); \
        *(serrp) = (*(ccp) == -1) ? errno : RPC_C_SOCKET_OK; \
        RPC_LOG_SOCKET_SENDMSG_XIT; \
        if (*(serrp) == EINTR)\
        {\
            goto sendmsg_again;\
        }\
    }
#endif

inline static void RPC_SOCKET_RECVFROM
(
    rpc_socket_t        sock,
    byte_p_t            buf,        /* buf for rcvd data */
    int                 buflen,        /* len of above buf */
    rpc_addr_p_t        from,       /* addr of sender */
    volatile int                 *ccp,        /* returned number of bytes actually rcvd */
	 volatile rpc_socket_error_t *serrp
)
{
recvfrom_again:
	if ((from) != NULL) RPC_SOCKET_FIX_ADDRLEN(from);
	RPC_LOG_SOCKET_RECVFROM_NTR;
	*(ccp) = dcethread_recvfrom ((int) sock, (char *) buf, (int) buflen, (int) 0,
			(struct sockaddr *) (&(from)->sa), (&(from)->len));
	*(serrp) = (*(ccp) == -1) ? errno : RPC_C_SOCKET_OK;
	RPC_LOG_SOCKET_RECVFROM_XIT;
	RPC_SOCKET_FIX_ADDRLEN(from);
	if (*(serrp) == EINTR)
	{
		goto recvfrom_again;
	}

}

#if 0
#define RPC_SOCKET_RECVFROM(sock, buf, buflen, from, ccp, serrp) \
    { \
recvfrom_again:\
        if ((from) != NULL) RPC_SOCKET_FIX_ADDRLEN(from); \
        RPC_LOG_SOCKET_RECVFROM_NTR; \
        *(ccp) = recvfrom ((int) sock, (char *) buf, (int) buflen, (int) 0, \
            (struct sockaddr *) (&(from)->sa), (&(from)->len)); \
        *(serrp) = (*(ccp) == -1) ? errno : RPC_C_SOCKET_OK; \
        RPC_LOG_SOCKET_RECVFROM_XIT; \
        RPC_SOCKET_FIX_ADDRLEN(from); \
        if (*(serrp) == EINTR)\
        {\
            goto recvfrom_again;\
        }\
    }
#endif

inline static void RPC_SOCKET_RECVMSG
(
    rpc_socket_t        sock,
    rpc_socket_iovec_p_t iovp,       /* array of bufs for rcvd data */
    int                 iovlen,    /* number of bufs */
    rpc_addr_p_t        addrp,       /* addr of sender */
    volatile int                 *ccp,        /* returned number of bytes actually rcvd */
	 volatile rpc_socket_error_t *serrp
)
{
	struct msghdr msg;
recvmsg_again:
	memset(&msg, 0, sizeof(msg));
	RPC_LOG_SOCKET_RECVMSG_NTR;
	RPC_SOCKET_INIT_MSGHDR(&msg);
	if ((addrp) != NULL)
	{
		RPC_SOCKET_FIX_ADDRLEN(addrp);
		msg.msg_name = (caddr_t) &(addrp)->sa;
		msg.msg_namelen = (addrp)->len;
	}
	else
	{
		msg.msg_name = (caddr_t) NULL;
	}
	msg.msg_iov = (struct iovec *) iovp;
	msg.msg_iovlen = iovlen;
	*(ccp) = dcethread_recvmsg ((int) sock, (struct msghdr *) &msg, 0);
	if ((addrp) != NULL)
	{
		(addrp)->len = msg.msg_namelen;
	}
	*(serrp) = (*(ccp) == -1) ? errno : RPC_C_SOCKET_OK;
	RPC_LOG_SOCKET_RECVMSG_XIT;
	if (*(serrp) == EINTR)
	{
		goto recvmsg_again;
	}
}
#if 0
#define RPC_SOCKET_RECVMSG(sock, iovp, iovlen, addrp, ccp, serrp) \
    { \
        struct msghdr msg; \
         \
recvmsg_again:\
        RPC_LOG_SOCKET_RECVMSG_NTR; \
        RPC_SOCKET_INIT_MSGHDR(&msg); \
        if ((addrp) != NULL)\
        {\
            RPC_SOCKET_FIX_ADDRLEN(addrp); \
            msg.msg_name = (caddr_t) &(addrp)->sa; \
            msg.msg_namelen = (addrp)->len; \
        }\
        else\
        {\
            msg.msg_name = (caddr_t) NULL;\
        }\
        msg.msg_iov = (struct iovec *) iovp; \
        msg.msg_iovlen = iovlen; \
        *(ccp) = dcethread_recvmsg ((int) sock, (struct msghdr *) &msg, 0); \
        if ((addrp) != NULL)\
        {\
            (addrp)->len = msg.msg_namelen; \
        }\
        *(serrp) = (*(ccp) == -1) ? errno : RPC_C_SOCKET_OK; \
        RPC_LOG_SOCKET_RECVMSG_XIT; \
        if (*(serrp) == EINTR)\
        {\
            goto recvmsg_again;\
        }\
    }
#endif

#endif /* _COMSOC_BSD_H */
