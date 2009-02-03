/* ex: set shiftwidth=4 softtabstop=4 expandtab: */
#if defined(IDLBASE_H) && !defined(IDL_CHAR_IS_CHAR)
#error Include mswrappers.h before including dce/idlbase.h
#endif
#define IDL_CHAR_IS_CHAR

#include <lw/base.h>
#include <dce/idlbase.h>
#include <dce/rpc.h>
#define DCETHREAD_CHECKED
#define DCETHREAD_USE_THROW
#include <dce/dcethread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int RPC_STATUS;
typedef handle_t RPC_BINDING_HANDLE;
typedef rpc_if_handle_t RPC_IF_HANDLE;
typedef uuid_t UUID;
typedef rpc_mgr_proc_t RPC_MGR_EPV;

#define RPC_C_PROTSEQ_MAX_REQS_DEFAULT rpc_c_protseq_max_reqs_default
#define RPC_C_LISTEN_MAX_CALLS_DEFAULT rpc_c_listen_max_calls_default

#define RpcTryExcept	DCETHREAD_TRY
#define RpcExcept	DCETHREAD_CATCH_EXPR
#define RpcEndExcept	DCETHREAD_ENDTRY
#define RpcExceptionCode RpcCompatReturnLater(RpcCompatExceptionToCode(DCETHREAD_EXC_CURRENT))

RPC_STATUS RpcCompatExceptionToCode(dcethread_exc *exc);
typedef RPC_STATUS (*RpcCompatReturnCodeFuncPtr)();
RpcCompatReturnCodeFuncPtr RpcCompatReturnLater(RPC_STATUS value);

//User programs put this inside of their type
#define __RPC_USER

RPC_STATUS RpcStringBindingComposeA(
    /* [in] */ UCHAR *string_object_uuid,
    /* [in] */ UCHAR *string_protseq,
    /* [in] */ UCHAR *string_netaddr,
    /* [in] */ UCHAR *string_endpoint,
    /* [in] */ UCHAR *string_options,
    /* [out] */ UCHAR **string_binding
);

RPC_STATUS RpcStringBindingComposeW(
    /* [in] */ PWSTR string_object_uuid,
    /* [in] */ PWSTR string_protseq,
    /* [in] */ PWSTR string_netaddr,
    /* [in] */ PWSTR string_endpoint,
    /* [in] */ PWSTR string_options,
    /* [out] */ PWSTR *string_binding
);

RPC_STATUS RpcBindingFromStringBindingA(
    /* [in] */ UCHAR *string_binding,
    /* [out] */ RPC_BINDING_HANDLE *binding_handle
);

RPC_STATUS RpcBindingFromStringBindingW(
    /* [in] */ PWSTR string_binding,
    /* [out] */ RPC_BINDING_HANDLE *binding_handle
);

RPC_STATUS RpcStringFreeA(
    /* [in, out] */ PUCHAR *string
);

RPC_STATUS RpcStringFreeW(
    /* [in, out] */ PWSTR *string
);

RPC_STATUS RpcBindingFree(
    /* [in, out] */ RPC_BINDING_HANDLE *binding_handle
);

RPC_STATUS RpcServerUseProtseqEpA(
    /* [in] */ PUCHAR protseq,
    /* [in] */ unsigned int max_call_requests,
    /* [in] */ PUCHAR endpoint,
    void *security /*not used*/
);
RPC_STATUS RpcServerUseProtseqEpW(
    /* [in] */ PWSTR protseq,
    /* [in] */ unsigned int max_call_requests,
    /* [in] */ PWSTR endpoint,
    void *security /*not used*/
);

RPC_STATUS RpcServerRegisterIf(
    /* [in] */ RPC_IF_HANDLE if_spec,
    /* [in] */ UUID *mgr_type_uuid,
    /* [in] */ RPC_MGR_EPV *mgr_epv
);

RPC_STATUS RpcServerListen(
    unsigned32 minimum_call_threads, /*not used*/
    /* [in] */ unsigned32 max_calls_exec,
    unsigned32 dont_wait /*not used*/
);

#define RpcStringBindingCompose RpcStringBindingComposeA
#define RpcServerUseProtseqEp RpcServerUseProtseqEpA
#define RpcBindingFromStringBinding RpcBindingFromStringBindingA
#define RpcStringFree RpcStringFreeA

#ifdef __cplusplus
} //extern C
#endif
