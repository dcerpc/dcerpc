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
#ifndef _GSSAUTHCN_H
#define _GSSAUTHCN_H 	1

/*
**  NAME
**
**      gssauthcn.h
**
**  FACILITY:
**
**      Remote Procedure Call (RPC)
**
**  ABSTRACT:
**
**  The gssauth CN authentication module interface.
**
**
*/

#include <cn.h>

#if HAVE_GSS_FRAMEWORK
/* GSS framework has gss_wrap/unwrap_iov in gssapi.h */
#include <GSS/gssapi.h>
#else
#include <gssapi/gssapi_ext.h>
#endif

#if HAVE_KERBEROS_FRAMEWORK
#include <Kerberos/krb5.h>
#else
#include <krb5.h>
#endif

typedef struct
{
    rpc_cn_auth_info_t cn_info;
    gss_ctx_id_t gss_ctx;
    OM_uint32 gss_stat;
    gss_OID gss_mech;
    boolean header_sign;
} rpc_gssauth_cn_info_t, *rpc_gssauth_cn_info_p_t;

PRIVATE rpc_protocol_id_t rpc__gssauth_negotiate_cn_init (
         rpc_auth_rpc_prot_epv_p_t      * /*epv*/,
         unsigned32                     * /*st*/
    );

PRIVATE rpc_protocol_id_t rpc__gssauth_mskrb_cn_init (
         rpc_auth_rpc_prot_epv_p_t      * /*epv*/,
         unsigned32                     * /*st*/
    );

PRIVATE rpc_protocol_id_t rpc__gssauth_winnt_cn_init (
         rpc_auth_rpc_prot_epv_p_t      * /*epv*/,
         unsigned32                     * /*st*/
    );

PRIVATE rpc_protocol_id_t rpc__gssauth_netlogon_cn_init (
         rpc_auth_rpc_prot_epv_p_t      * /*epv*/,
         unsigned32                     * /*st*/
    );

PRIVATE const char *rpc__gssauth_error_map (
	int			/*major_status*/,
	OM_uint32		/*minor_status*/,
	const gss_OID		/*mech*/,
	char			* /*message_buffer*/,
	unsigned32		/*message_length*/,
	unsigned32		* /*st*/
    );


#endif /* _GSSAUTHCN_H */
