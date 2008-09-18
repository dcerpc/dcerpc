#ifndef _SCHNAUTHCN_H
#define _SCHNAUTHCN_H 	1

/*
**  NAME
**
**      schnauthcn.h
**
**  FACILITY:
**
**      Remote Procedure Call (RPC) 
**
**  ABSTRACT:
**
**  The netlogon/schannel CN authentication module interface.
**
**
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <cn.h>

#include <schannel.h>

typedef struct rpc_schnauth_cn_info
{
    rpc_cn_auth_info_t  cn_info;

    /*
     * Schannel security context
     */

    struct schn_auth_ctx sec_ctx;

} rpc_schnauth_cn_info_t, *rpc_schnauth_cn_info_p_t;


typedef struct rpc_schnauth_creds
{
    unsigned32 flags1;
    unsigned32 flags2;
    unsigned_char_p_t domain_name;
    unsigned_char_p_t machine_name;
} rpc_schnauth_creds_t, *rpc_schnauth_creds_p_t;


typedef struct rpc_cn_schnauth_tlr
{
    unsigned8 signature[8];
    unsigned8 seq_number[8];
    unsigned8 digest[8];
    unsigned8 nonce[8];

} rpc_cn_schnauth_tlr_t, *rpc_cn_schnauth_tlr_p_t;

#define RPC_CN_PKT_SIZEOF_SCHNAUTH_TLR  32


EXTERNAL rpc_cn_auth_epv_t rpc_g_schnauth_cn_epv;

#endif /* _SCHNAUTHCN_H */
