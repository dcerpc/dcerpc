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

#include <commonp.h>    /* Common declarations for all RPC runtime */
#include <com.h>        /* Common communications services */
#include <comprot.h>    /* Common protocol services */
#include <comnp.h>


PRIVATE void rpc__np_auth_info_reference
#ifdef _DCE_PROTO_
(
    rpc_np_auth_info_p_t   np_auth_info
)
#else
(np_auth_info)
rpc_np_auth_info_p_t   np_auth_info;
#endif
{
    if (np_auth_info == NULL) return;

    RPC_DBG_PRINTF(rpc_e_dbg_auth, 3, ("(rpc__np_auth_info_reference) %lx: bumping refcount (was %u, now %u)\n",
				       (unsigned long)np_auth_info, (unsigned int)np_auth_info->refcount,
				       (unsigned int)(np_auth_info->refcount + 1)));

    np_auth_info->refcount++;
}


PRIVATE void rpc__np_auth_info_release
#ifdef _DCE_PROTO_
(
    rpc_np_auth_info_p_t *np_auth_info
)
#else
(np_auth_info)
rpc_np_auth_info_p_t  *np_auth_info;
#endif
{
    rpc_np_auth_info_p_t info = NULL;

    if (np_auth_info == NULL) return;

    info = *np_auth_info;
    if (info == NULL) return;

    RPC_DBG_PRINTF(rpc_e_dbg_auth, 3, ("(rpc__np_auth_info_release) %lx: dropping refcount (was %d, now %d)\n",
				       (unsigned long)info, info->refcount, info->refcount-1));

    /*
     * Remove the reference
     */
    info->refcount--;

    if (info->refcount == 0)
    {
        /* Free existing np_auth_info data */

        if (info->princ_name)
        {
            RPC_MEM_FREE(info->princ_name, RPC_C_MEM_NAMED_PIPE_INFO);
        }

        if (info->workstation)
        {
            RPC_MEM_FREE(info->workstation, RPC_C_MEM_NAMED_PIPE_INFO);
        }

        if (info->session_key)
        {
            memset((void*)info->session_key, 0, info->session_key_len);
            RPC_MEM_FREE(info->session_key, RPC_C_MEM_NAMED_PIPE_INFO);
	}

        RPC_MEM_FREE(info, RPC_C_MEM_NAMED_PIPE_INFO);
    }

    *np_auth_info = NULL;
}
