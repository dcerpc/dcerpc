/*
 *
 * (c) Copyright 1991 OPEN SOFTWARE FOUNDATION, INC.
 * (c) Copyright 1991 HEWLETT-PACKARD COMPANY
 * (c) Copyright 1991 DIGITAL EQUIPMENT CORPORATION
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
#ifndef _GSSAUTH_H
#define _GSSAUTH_H	1
/*
**
**  NAME
**
**      gssauth.h
**
**  FACILITY:
**
**      Remote Procedure Call (RPC)
**
**  ABSTRACT:
**
**      Types and routines private to the "gss negotiate"
**      module. The module provides the following implementations:
**      - gss_mskrb5: gssapi krb5 with GSS_C_DCE_STYLE
**      - gss_negotiate: gssapi spnego with GSS_C_DCE_STYLE
**                       but only with krb5 as spnego mech yet
**
*/

#include <commonp.h>
#include <com.h>
#include <comp.h>
#include <gssauthcn.h>

#if HAVE_GSS_FRAMEWORK
#include <GSS/gssapi.h>
#include <GSS/gssapi_krb5.h>
#else
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#endif

/*
 * State block containing all the state of one end of an authenticated
 * connection.
 */

typedef struct rpc_gssauth_info_t {
    rpc_auth_info_t auth_info;  /* This must be the first element. */

    gss_name_t gss_server_name;
    gss_cred_id_t gss_creds;

    /* security context information is available
       here for the server side */
    rpc_gssauth_cn_info_p_t cn_info;

} rpc_gssauth_info_t, *rpc_gssauth_info_p_t;

/*
 * Prototypes for PRIVATE routines.
 */

PRIVATE OM_uint32 rpc__gssauth_select_mech
(
	OM_uint32		*min_stat,
	rpc_authn_protocol_id_t	authn_protocol,
	gss_OID			*req_mech
);

#endif /* _GSSAUTH_H */
