/*
 * Copyright (c) 2007, Novell, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Novell, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Because we don't have kernel support for Named Pipes on UNIX,
 * we need to do some magic in order to pretend that we do. This
 * includes bubbling up the authentication information from the
 * named pipe layer.
 *
 * The function rpc__cn_assoc_listen() is called when a new 
 * connection has been accepted. We need to hook into
 * receive_dispatch() in rpc__cn_network_receiver() so that
 * the first PDU on a Named Pipe will be passed to 
 * rpc__np_get_auth_info().
 *
 * We should call rpc__naf_desc_inq_protseq_id() to check
 * whether we accepted on a Named Pipe.  
 */
#include <commonp.h>    /* Common declarations for all RPC runtime */
#include <com.h>        /* Common communications services */
#include <comprot.h>    /* Common protocol services */
#include <cnp.h>        /* NCA Connection private declarations */
#include <cnid.h>       /* NCA Connection local ID service */
#include <cnrcvr.h>     /* NCA Connection receiver thread */
#include <cnnet.h>      /* NCA Connection network service */
#include <cnpkt.h>      /* NCA Connection packet encoding */
#include <cnsm.h>       /* NCA Connection state machine service */
#include <cnassm.h>     /* NCA Connection association state machine */
#include <cnasgsm.h>    /* NCA Connection association group state machine */
#include <comauth.h>    /* Externals for Auth. Services sub-component   */
#include <cncall.h>     /* NCA connection call service */
#include <cnassoc.h>    
#include <comnp.h>
#include <cnnp.h>
#include <npnaf.h>      /* Named Pipe Network Address Family */

INTERNAL rpc_socket_error_t read_np_sec_context _DCE_PROTOTYPE_ ((
    rpc_socket_t            socket,
    rpc_np_sec_context_p_t  *p_ctx
));

INTERNAL void free_np_sec_context _DCE_PROTOTYPE_ ((rpc_np_sec_context_p_t *p_ctx));

INTERNAL void rpc_np_sec_context_to_auth_info
#ifdef _DCE_PROTO
(
    rpc_np_sec_context_p_t    ctx,
    rpc_np_auth_info_p_t      *auth_info_p,
    unsigned32                *status
)
#else
(ctx, auth_info_p, status)
    rpc_np_sec_context_p_t    ctx;
    rpc_np_auth_info_p_t      *auth_info_p;
    unsigned32                *status;
#endif
{
	rpc_np_auth_info_p_t auth_info;
	unsigned32 len;

	RPC_MEM_ALLOC(auth_info, rpc_np_auth_info_p_t, sizeof(*auth_info),
		RPC_C_MEM_UTIL, RPC_C_MEM_WAITOK);
	if (auth_info == NULL) {
		*status = rpc_s_no_memory;
		return;
	}

	auth_info->refcount = 1;

	len = ctx->UserNameLength;
	if (ctx->DomainNameLength) {
		len += 1 + ctx->DomainNameLength;
	}
	RPC_MEM_ALLOC(auth_info->princ_name, unsigned_char_p_t, len + 1,
		RPC_C_MEM_STRING, RPC_C_MEM_WAITOK);
	if (auth_info->princ_name == NULL) {
		RPC_MEM_FREE(auth_info, RPC_C_MEM_UTIL);
		*status = rpc_s_no_memory;
		return;
	}

	if (ctx->DomainNameLength) {
		memcpy(&auth_info->princ_name[0], ctx->DomainName, ctx->DomainNameLength);
		auth_info->princ_name[ctx->DomainNameLength] = '\\';
		memcpy(&auth_info->princ_name[ctx->DomainNameLength + 1], ctx->UserName, ctx->UserNameLength);
		auth_info->princ_name[ctx->DomainNameLength + 1 + ctx->UserNameLength] = '\0';
	} else {
		memcpy(auth_info->princ_name, ctx->UserName, ctx->UserNameLength);
		auth_info->princ_name[ctx->UserNameLength] = '\0';
	}

	if (ctx->WorkstationLength) {
		RPC_MEM_ALLOC(auth_info->workstation, unsigned_char_p_t, ctx->WorkstationLength + 1,
			RPC_C_MEM_STRING, RPC_C_MEM_WAITOK);
		if (auth_info->workstation == NULL) {
			rpc_string_free(&auth_info->princ_name, status);
			RPC_MEM_FREE(auth_info, RPC_C_MEM_UTIL);
			*status = rpc_s_no_memory;
			return;
		}
		memcpy(auth_info->workstation, ctx->Workstation, ctx->WorkstationLength);
		auth_info->workstation[ctx->WorkstationLength] = '\0';
	} else {
		auth_info->workstation = NULL;
	}
	
	if (ctx->SessionKeyLength) {
		RPC_MEM_ALLOC(auth_info->session_key, unsigned_char_p_t, ctx->SessionKeyLength,
			RPC_C_MEM_STRING, RPC_C_MEM_WAITOK);
		if (auth_info->session_key == NULL) {
			rpc_string_free(&auth_info->princ_name, status);
			rpc_string_free(&auth_info->workstation, status);
			RPC_MEM_FREE(auth_info, RPC_C_MEM_UTIL);
			*status = rpc_s_no_memory;
			return;
		}
		memcpy(auth_info->session_key, ctx->SessionKey, ctx->SessionKeyLength);
		auth_info->session_key_len = ctx->SessionKeyLength;
	} else {
		auth_info->session_key = NULL;
		auth_info->session_key_len = 0;
	}
	
	*auth_info_p = auth_info;
	*status = rpc_s_ok;

	return;
}

/*
 * This function is responsible for reading a rpc_np_sec_context_p_t
 * off the wire and attaching an appropriate authentication state
 * to the handle, as if the client had authenticated over DCE.
 * The trick will be to ensure that the context is not destroyed
 * when we receive a bind PDU.
 */
PRIVATE void rpc__np_get_auth_info
#ifdef _DCE_PROTO_
(
    rpc_cn_assoc_p_t         assoc,
    unsigned32               *status
)
#else
(assoc, status)
    rpc_cn_assoc_p_t         assoc;
    unsigned32               *status;
#endif
{
	rpc_socket_error_t serr;
	rpc_np_sec_context_p_t ctx = NULL;
	rpc_socket_t socket;

	socket = assoc->cn_ctlblk.cn_sock;

	RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
		("(rpc__np_get_auth_info) assoc->%08x socket->%d\n", assoc, socket));

	serr = read_np_sec_context(socket, &ctx);
	if (RPC_SOCKET_IS_ERR(serr)) {
		*status = rpc_s_protocol_error;
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(rpc__np_get_auth_info) could not parse np_sec_context: %d\n", serr));
		return;
	}

	if (assoc->security.assoc_named_pipe_info != NULL) {
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(rpc__np_get_auth_info) warning: assoc named pipe info not initialized to NULL\n"));
	}

	/*
	 * Only create authentication information for non-
	 * anonymous SMB named pipe clients.
	 */
	if (ctx->UserName != NULL) {
		rpc_np_sec_context_to_auth_info(ctx, &assoc->security.assoc_named_pipe_info, status);
		if (*status != rpc_s_ok) {
			RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
				("(rpc__np_get_auth_info) could not create authentication info: %08x\n", *status));
			return;
		}

	} else {
		assoc->security.assoc_named_pipe_info = NULL;
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(rpc__np_get_auth_info) named pipe client is anonymous\n"));
	}

	free_np_sec_context(&ctx);

	*status = rpc_s_ok;

	return;
}

/*
 * Free a Named Pipe security context
 */
INTERNAL void free_np_sec_context
#ifdef _DCE_PROTO_
(
    rpc_np_sec_context_p_t *p_ctx
)
#else
(ctx)
    rpc_np_sec_context_p_t *p_ctx;
#endif
{
    rpc_np_sec_context_p_t ctx;

	ctx = *p_ctx;
	if (ctx != NULL) {
		if (ctx->UserName != NULL)
			RPC_MEM_FREE(ctx->UserName, RPC_C_MEM_STRING);
		if (ctx->DomainName != NULL)
			RPC_MEM_FREE(ctx->DomainName, RPC_C_MEM_STRING);
		if (ctx->Workstation != NULL)
			RPC_MEM_FREE(ctx->Workstation, RPC_C_MEM_STRING);
		if (ctx->SessionKey != NULL)
			RPC_MEM_FREE(ctx->SessionKey, RPC_C_MEM_STRING);
		RPC_MEM_FREE(ctx, RPC_C_MEM_UTIL);
		*p_ctx = NULL;
	}
	return;
}

INTERNAL rpc_socket_error_t read_np_sec_context
#ifdef _DCE_PROTO_
(
    rpc_socket_t            socket,
    rpc_np_sec_context_p_t  *p_ctx
)
#else
(socket, status)
    rpc_socket_t            socket;
    rpc_np_sec_context_p_t  *p_ctx;
#endif
{
	unsigned_char_p_t buf, ptr;
	rpc_np_sec_context_p_t ctx;
	rpc_socket_error_t ret;
	size_t len;
	int readamt;
	rpc_np_addr_t from;

	RPC_MEM_ALLOC(ctx, rpc_np_sec_context_p_t, RPC_C_NP_SEC_CONTEXT_MAX_LEN,
		RPC_C_MEM_UTIL, RPC_C_MEM_WAITOK);
	if (ctx == NULL) {
		return ENOMEM;
	}
	memset(ctx, 0, sizeof(*ctx));

	RPC_MEM_ALLOC(buf, unsigned_char_p_t, RPC_C_NP_SEC_CONTEXT_MAX_LEN,
		RPC_C_MEM_UTIL, RPC_C_MEM_WAITOK);
	if (buf == NULL) {
		RPC_MEM_FREE(ctx, RPC_C_MEM_UTIL);
		return ENOMEM;
	}

	ptr = buf;

	/*
	 * Read the length of the Named Pipe security context
	 * preamble: note that this is not an RPC PDU.
	 */
	len = 0;
	while (len < sizeof(ctx->Length)) {
		from.len = sizeof(from.sa);
		ret = rpc__socket_recvfrom(socket,
			ptr + len,
			sizeof(ctx->Length) - len,
			(rpc_addr_p_t)&from,
			&readamt);
		len += readamt;
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
				("(read_np_sec_context) could not get security preamble length error->%s bytes read->%d\n", strerror(errno), len));
			goto CLEANUP;
		}
	}

	memcpy(&ctx->Length, ptr, sizeof(ctx->Length));
	RPC_RESOLVE_ENDIAN_INT32(ctx->Length);
	ptr += sizeof(ctx->Length);
	if (ctx->Length < RPC_C_NP_SEC_CONTEXT_MIN_LEN ||
	    ctx->Length > RPC_C_NP_SEC_CONTEXT_MAX_LEN) {
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(read_np_sec_context) security preamble too small or large: got %d bytes\n", len));
		ret = ERANGE;
		goto CLEANUP;
	}

	/*
	 * Read the rest of the data.
	 */
	len = 0;
	while (len < ctx->Length) {
		from.len = sizeof(from.sa);
		ret = rpc__socket_recvfrom(socket,
			ptr + len,
			ctx->Length - len,
			(rpc_addr_p_t)&from,
			&readamt);
		len += readamt;
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
				("(read_np_sec_context) could not get security preamble error->%s bytes read->%d length->%d\n", strerror(errno), len, ctx->Length));
			goto CLEANUP;
		}
	}

	memcpy(&ctx->Version, ptr, sizeof(ctx->Version));
	RPC_RESOLVE_ENDIAN_INT32(ctx->Version);
	ptr += sizeof(ctx->Version);
	len -= sizeof(ctx->Version);
	if (ctx->Version != 2) {
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(read_np_sec_context) invalid context version %08x\n", ctx->Version));
		ret = ERANGE;
		goto CLEANUP;
	}

	memcpy(&ctx->UserNameLength, ptr, sizeof(ctx->UserNameLength));
	RPC_RESOLVE_ENDIAN_INT32(ctx->UserNameLength);
	ptr += sizeof(ctx->UserNameLength);
	len -= sizeof(ctx->UserNameLength);
	if (len < ctx->UserNameLength) {
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(read_np_sec_context) string length %d would exceed security preamble length\n", ctx->UserNameLength));
		ret = ERANGE;
		goto CLEANUP;
	}
	if (ctx->UserNameLength) {
		RPC_MEM_ALLOC(ctx->UserName, unsigned_char_p_t, ctx->UserNameLength + 1,
			RPC_C_MEM_STRING, RPC_C_MEM_WAITOK);
		memcpy(ctx->UserName, ptr, ctx->UserNameLength);
		ctx->UserName[ctx->UserNameLength] = '\0';
	} else {
		ctx->UserName = NULL;
	}
	ptr += ctx->UserNameLength;
	len -= ctx->UserNameLength;

	memcpy(&ctx->DomainNameLength, ptr, sizeof(ctx->DomainNameLength));
	RPC_RESOLVE_ENDIAN_INT32(ctx->DomainNameLength);
	ptr += sizeof(ctx->DomainNameLength);
	len -= sizeof(ctx->DomainNameLength);
	if (len < ctx->DomainNameLength) {
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(read_np_sec_context) string length %d would exceed security preamble length\n", ctx->DomainNameLength));
		ret = ERANGE;
		goto CLEANUP;
	}
	if (ctx->DomainNameLength) {
		RPC_MEM_ALLOC(ctx->DomainName, unsigned_char_p_t, ctx->DomainNameLength + 1,
			RPC_C_MEM_STRING, RPC_C_MEM_WAITOK);
		memcpy(ctx->DomainName, ptr, ctx->DomainNameLength);
		ctx->DomainName[ctx->DomainNameLength] = '\0';
	} else {
		ctx->DomainName = NULL;
	}
	ptr += ctx->DomainNameLength;
	len -= ctx->DomainNameLength;

	memcpy(&ctx->WorkstationLength, ptr, sizeof(ctx->WorkstationLength));
	RPC_RESOLVE_ENDIAN_INT32(ctx->WorkstationLength);
	ptr += sizeof(ctx->WorkstationLength);
	len -= sizeof(ctx->WorkstationLength);
	if (len < ctx->WorkstationLength) {
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(read_np_sec_context) string length %d would exceed security preamble length\n", ctx->WorkstationLength));
		ret = ERANGE;
		goto CLEANUP;
	}
	if (ctx->WorkstationLength) {
		RPC_MEM_ALLOC(ctx->Workstation, unsigned_char_p_t, ctx->WorkstationLength + 1,
			RPC_C_MEM_STRING, RPC_C_MEM_WAITOK);
		memcpy(ctx->Workstation, ptr, ctx->WorkstationLength);
		ctx->Workstation[ctx->WorkstationLength] = '\0';
	} else {
		ctx->Workstation = NULL;
	}
	ptr += ctx->WorkstationLength;
	len -= ctx->WorkstationLength;

	memcpy(&ctx->SessionKeyLength, ptr, sizeof(ctx->SessionKeyLength));
	RPC_RESOLVE_ENDIAN_INT32(ctx->SessionKeyLength);
	ptr += sizeof(ctx->SessionKeyLength);
	len -= sizeof(ctx->SessionKeyLength);
	if (len < ctx->SessionKeyLength) {
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(read_np_sec_context) session key length %d would exceed security preamble length\n", ctx->SessionKeyLength));
		ret = ERANGE;
		goto CLEANUP;
	}
	if (ctx->SessionKeyLength) {
		RPC_MEM_ALLOC(ctx->SessionKey, unsigned_char_p_t, ctx->SessionKeyLength,
			RPC_C_MEM_STRING, RPC_C_MEM_WAITOK);
		memcpy(ctx->SessionKey, ptr, ctx->SessionKeyLength);
	} else {
		ctx->SessionKey = NULL;
	}
	ptr += ctx->SessionKeyLength;
	len -= ctx->SessionKeyLength;

	assert(len == 0);

	RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
		("(read_np_sec_context) user->%s domain->%s workstation->%s\n",
			(ctx->UserNameLength) ? (char *)ctx->UserName : "<unspecified>",
			(ctx->DomainNameLength) ? (char *)ctx->DomainName : "<unspecified>",
			(ctx->WorkstationLength) ? (char *)ctx->Workstation : "<unspecified>"));

	if (ctx->SessionKeyLength >= 16) {
		RPC_DBG_PRINTF(rpc_e_dbg_auth, 20,
			("(read_np_sec_context) session key->%08x %08x %08x %08x\n",
				*((unsigned32 *)&ctx->SessionKey[0]), *((unsigned32 *)&ctx->SessionKey[4]),
				*((unsigned32 *)&ctx->SessionKey[8]), *((unsigned32 *)&ctx->SessionKey[12])));
	}

	ret = 0;

CLEANUP:
	if (ret != 0) {
		free_np_sec_context(&ctx);
	}
	RPC_MEM_FREE(buf, RPC_C_MEM_UTIL);

	*p_ctx = ctx;

	return ret;
}

