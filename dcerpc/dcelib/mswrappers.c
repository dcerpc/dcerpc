/* ex: set shiftwidth=4 softtabstop=4 expandtab: */
#include "compat/mswrappers.h"
#include <stdlib.h>
#include <wc16str.h>
#include <errno.h>

RPC_STATUS WideChar16ToMultiByte(PWSTR input, idl_char **output)
{
    *output = awc16stombs(input);
    if(*output == NULL)
    {
        if(errno == ENOMEM)
            return rpc_s_no_memory;
        return rpc_s_invalid_arg;
    }
    return rpc_s_ok;
}

RPC_STATUS MultiByteToWideChar16(idl_char *input, PWSTR *output)
{
    *output = ambstowc16s(input);
    if(*output == NULL)
    {
        if(errno == ENOMEM)
            return rpc_s_no_memory;
        return rpc_s_invalid_arg;
    }
    return rpc_s_ok;
}

#define CONVERT_INPUTSTR(var) \
    idl_char *converted_##var = NULL; \
    if(status == rpc_s_ok) \
        status = WideChar16ToMultiByte((var), &converted_##var);

#define DECLARE_OUTPUTSTR(var) \
    idl_char *temp_##var = NULL; \
    *(var) = NULL;

#define CONVERT_OUTPUTSTR(var) \
    if(temp_##var != NULL) \
    { \
        RPC_STATUS unused_status; \
        if(status == rpc_s_ok) \
            status = MultiByteToWideChar16(temp_##var, (var)); \
        rpc_string_free(&temp_##var, &unused_status); \
    }

#define OUTPUTSTR(var)  &temp_##var
#define INPUTSTR(var)  converted_##var

#define FREE_INPUTSTR(var) \
    if(converted_##var != NULL) \
    { \
        free(converted_##var); \
        converted_##var = NULL; \
    }

RPC_STATUS RpcCompatExceptionToCode(dcethread_exc *exc)
{
    RPC_STATUS status;
    if((status = dcethread_exc_getstatus(exc)) == -1)
        return rpc_m_unexpected_exc;
    return status;
}

RPC_STATUS g_lastcode = 0;
RPC_STATUS RpcCompatReturnLastCode()
{
    return g_lastcode;
}

RpcCompatReturnCodeFuncPtr RpcCompatReturnLater(RPC_STATUS value)
{
    g_lastcode = value;
    return RpcCompatReturnLastCode;
}

RPC_STATUS RpcStringBindingComposeA(
    /* [in] */ UCHAR *string_object_uuid,
    /* [in] */ UCHAR *string_protseq,
    /* [in] */ UCHAR *string_netaddr,
    /* [in] */ UCHAR *string_endpoint,
    /* [in] */ UCHAR *string_options,
    /* [out] */ UCHAR **string_binding
)
{
    RPC_STATUS status;
    rpc_string_binding_compose((idl_char *)string_object_uuid, (idl_char *)string_protseq, (idl_char *)string_netaddr, (idl_char *)string_endpoint, (idl_char *)string_options, (idl_char **)string_binding, &status);
    return status;
}

RPC_STATUS RpcStringBindingComposeW(
    /* [in] */ PWSTR string_object_uuid,
    /* [in] */ PWSTR string_protseq,
    /* [in] */ PWSTR string_netaddr,
    /* [in] */ PWSTR string_endpoint,
    /* [in] */ PWSTR string_options,
    /* [out] */ PWSTR *string_binding
)
{
    RPC_STATUS status = rpc_s_ok;
    CONVERT_INPUTSTR(string_object_uuid);
    CONVERT_INPUTSTR(string_protseq);
    CONVERT_INPUTSTR(string_netaddr);
    CONVERT_INPUTSTR(string_endpoint);
    CONVERT_INPUTSTR(string_options);
    DECLARE_OUTPUTSTR(string_binding);

    if(status == rpc_s_ok)
    {
        rpc_string_binding_compose(INPUTSTR(string_object_uuid),
                INPUTSTR(string_protseq),
                INPUTSTR(string_netaddr),
                INPUTSTR(string_endpoint),
                INPUTSTR(string_options),
                OUTPUTSTR(string_binding),
		&status);
    }

    FREE_INPUTSTR(string_object_uuid);
    FREE_INPUTSTR(string_protseq);
    FREE_INPUTSTR(string_netaddr);
    FREE_INPUTSTR(string_endpoint);
    FREE_INPUTSTR(string_options);
    CONVERT_OUTPUTSTR(string_binding);

    return status;
}

RPC_STATUS RpcBindingFromStringBindingA(
    /* [in] */ UCHAR *string_binding,
    /* [out] */ RPC_BINDING_HANDLE *binding_handle
)
{
    RPC_STATUS status;
    rpc_binding_from_string_binding((idl_char *)string_binding, binding_handle, &status);
    return status;
}

RPC_STATUS RpcBindingFromStringBindingW(
    /* [in] */ PWSTR string_binding,
    /* [out] */ RPC_BINDING_HANDLE *binding_handle
)
{
    RPC_STATUS status = rpc_s_ok;
    CONVERT_INPUTSTR(string_binding);

    if(status == rpc_s_ok)
    {
        rpc_binding_from_string_binding(
                INPUTSTR(string_binding),
                binding_handle,
                &status);
    }

    FREE_INPUTSTR(string_binding);

    return status;
}

RPC_STATUS RpcStringFreeA(
    /* [in, out] */ PUCHAR *string
)
{
    RPC_STATUS status = rpc_s_ok;
    rpc_string_free((idl_char **)string, &status);
    return status;
}

RPC_STATUS RpcStringFreeW(
    /* [in, out] */ PWSTR *string
)
{
    //We allocated this string, not dce rpc
    if(*string != NULL)
    {
        free(*string);
        *string = NULL;
    }
    return rpc_s_ok;
}

RPC_STATUS RpcBindingFree(
    /* [in, out] */ RPC_BINDING_HANDLE *binding_handle
)
{
    RPC_STATUS status = rpc_s_ok;
    rpc_binding_free(binding_handle, &status);
    return status;
}

RPC_STATUS RpcServerUseProtseqEpA(
    /* [in] */ PUCHAR protseq,
    /* [in] */ unsigned int max_call_requests,
    /* [in] */ PUCHAR endpoint,
    void *security /*not used*/
)
{
    RPC_STATUS status = rpc_s_ok;
    rpc_server_use_protseq_ep((idl_char *)protseq, max_call_requests, (idl_char *)endpoint, &status);
    return status;
}

RPC_STATUS RpcServerUseProtseqEpW(
    /* [in] */ PWSTR protseq,
    /* [in] */ unsigned int max_call_requests,
    /* [in] */ PWSTR endpoint,
    void *security /*not used*/
)
{
    RPC_STATUS status = rpc_s_ok;
    CONVERT_INPUTSTR(protseq);
    CONVERT_INPUTSTR(endpoint);

    if(status == rpc_s_ok)
    {
        rpc_server_use_protseq_ep(INPUTSTR(protseq),
                max_call_requests,
                INPUTSTR(endpoint),
                &status);
    }

    FREE_INPUTSTR(protseq);
    FREE_INPUTSTR(endpoint);

    return status;
}

RPC_STATUS RpcServerRegisterIf(
    /* [in] */ RPC_IF_HANDLE if_spec,
    /* [in] */ UUID *mgr_type_uuid,
    /* [in] */ RPC_MGR_EPV *mgr_epv
)
{
    RPC_STATUS status = rpc_s_ok;
    rpc_server_register_if(if_spec, mgr_type_uuid, mgr_epv, &status);
    return status;
}

RPC_STATUS RpcServerListen(
    unsigned32 minimum_call_threads, /*not used*/
    /* [in] */ unsigned32 max_calls_exec,
    unsigned32 dont_wait /*not used*/
)
{
    RPC_STATUS status = rpc_s_ok;
    rpc_server_listen(max_calls_exec, &status);
    return status;
}

#ifdef __cplusplus
} //extern C
#endif
