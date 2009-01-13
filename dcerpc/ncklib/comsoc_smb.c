#include <commonp.h>
#include <com.h>
#include <comprot.h>
#include <comnaf.h>
#include <comp.h>
#include <comsoc_smb.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cnp.h>
#include <npnaf.h>
#include <stddef.h>

#include <lsmb/lsmb.h>

#define SMB_SOCKET_LOCK(sock) (rpc__smb_socket_lock((rpc_smb_socket_p_t) (sock)->data.pointer))
#define SMB_SOCKET_UNLOCK(sock) (rpc__smb_socket_unlock((rpc_smb_socket_p_t) (sock)->data.pointer))

#if 0
#  define TRANSACT_CUTOFF (60*1024)
#else
#  define TRANSACT_CUTOFF 1
#endif

typedef enum rpc_smb_state_e
{
    SMB_STATE_SEND,
    SMB_STATE_RECV,
    SMB_STATE_ERROR
} rpc_smb_state_t;

typedef struct rpc_smb_buffer_s
{
    size_t capacity;
    unsigned char* base;
    unsigned char* start_cursor;
    unsigned char* end_cursor;
} rpc_smb_buffer_t, *rpc_smb_buffer_p_t;

typedef struct rpc_smb_socket_s
{
    rpc_smb_state_t volatile state;
    rpc_np_addr_t peeraddr;
    HANDLE connection;
    HANDLE np;
    int selectfd[2];
    volatile boolean selectfd_triggered;
    rpc_smb_buffer_t sendbuffer;
    rpc_smb_buffer_t recvbuffer;
    dcethread_mutex lock;
    dcethread_cond event;
} rpc_smb_socket_t, *rpc_smb_socket_p_t;

INTERNAL
inline
size_t
rpc__smb_buffer_pending(
    rpc_smb_buffer_p_t buffer
    )
{
    return buffer->end_cursor - buffer->start_cursor;
}

INTERNAL
inline
size_t
rpc__smb_buffer_available(
    rpc_smb_buffer_p_t buffer
    )
{
    return (buffer->base + buffer->capacity) - buffer->end_cursor;
}

INTERNAL
inline
rpc_socket_error_t
rpc__smb_buffer_ensure_available(
    rpc_smb_buffer_p_t buffer,
    size_t space
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    unsigned char* new_base = NULL;

    if (!buffer->base)
    {
        buffer->capacity = 2048;
        buffer->base = malloc(buffer->capacity);

        if (!buffer->base)
        {
            serr = ENOMEM;
            goto error;
        }

        buffer->end_cursor = buffer->start_cursor = buffer->base;
    }

    if (space > rpc__smb_buffer_available(buffer))
    {
        while (space > rpc__smb_buffer_available(buffer))
        {
            buffer->capacity *= 2;
        }

        new_base = realloc(buffer->base, buffer->capacity);

        if (!new_base)
        {
            serr = ENOMEM;
            goto error;
        }

        buffer->start_cursor = new_base + (buffer->start_cursor - buffer->base);
        buffer->end_cursor = new_base + (buffer->end_cursor - buffer->base);

        buffer->base = new_base;
    }

error:

    return serr;
}

#ifdef WORDS_BIGENDIAN
#  define NATIVE_ORDER 0
#else
#  define NATIVE_ORDER 1
#endif

INTERNAL
inline
size_t
rpc__smb_buffer_packet_size(
    rpc_smb_buffer_p_t buffer
    )
{
    rpc_cn_common_hdr_p_t packet = (rpc_cn_common_hdr_p_t) buffer->start_cursor;
    uint16_t result;

    if (rpc__smb_buffer_pending(buffer) < sizeof(*packet))
    {
        return sizeof(*packet);
    }
    else
    {
        int packet_order = ((packet->drep[0] >> 4) & 1);

        if (packet_order != NATIVE_ORDER)
        {
            swab(&packet->frag_len, &result, 2);
        }
        else
        {
            result = packet->frag_len;
        }

        return (size_t) result;
    }
}

INTERNAL
inline
boolean
rpc__smb_buffer_packet_is_last(
    rpc_smb_buffer_p_t buffer
    )
{
    rpc_cn_common_hdr_p_t packet = (rpc_cn_common_hdr_p_t) buffer->start_cursor;

    return (packet->flags & RPC_C_CN_FLAGS_LAST_FRAG) == RPC_C_CN_FLAGS_LAST_FRAG;
}

INTERNAL
inline
rpc_socket_error_t
rpc__smb_buffer_append(
    rpc_smb_buffer_p_t buffer,
    void* data,
    size_t data_size
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;

    serr = rpc__smb_buffer_ensure_available(buffer, data_size);
    if (serr)
    {
        goto error;
    }

    memcpy(buffer->end_cursor, data, data_size);

    buffer->end_cursor += data_size;

error:

    return serr;
}

INTERNAL
inline
void
rpc__smb_buffer_settle(
    rpc_smb_buffer_p_t buffer
    )
{
    size_t filled = buffer->end_cursor - buffer->start_cursor;
    memmove(buffer->base, buffer->start_cursor, filled);
    buffer->start_cursor = buffer->base;
    buffer->end_cursor = buffer->base + filled;
}

/* Advance buffer start_cursor to the end of the last packet
   or the last packet that is the final fragment in a series,
   whichever comes first.  If the final fragment is found,
   return true, otherwise false.
*/
INTERNAL
inline
boolean
rpc__smb_buffer_advance_cursor(rpc_smb_buffer_p_t buffer, size_t* amount)
{
    boolean last;
    size_t packet_size;

    while (rpc__smb_buffer_packet_size(buffer) <= rpc__smb_buffer_pending(buffer))
    {
        last = rpc__smb_buffer_packet_is_last(buffer);
        packet_size = rpc__smb_buffer_packet_size(buffer);

        buffer->start_cursor += packet_size;

        if (last)
        {
            *amount = buffer->start_cursor - buffer->base;

            return true;
        }
    }

    return false;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_create(
    rpc_smb_socket_p_t* out
    )
{
    rpc_smb_socket_p_t sock = NULL;
    DWORD status = 0;
    int err = 0;

    sock = calloc(1, sizeof(*sock));

    if (!sock)
    {
        err = ENOMEM;
        goto done;
    }

    sock->selectfd[0] = -1;
    sock->selectfd[1] = -1;

    dcethread_mutex_init_throw(&sock->lock, NULL);
    dcethread_cond_init_throw(&sock->event, NULL);

    if (pipe(sock->selectfd) != 0)
    {
        err = errno;
        goto error;
    }

    status = SMBOpenServer(&sock->connection);

    if (status)
    {
        err = -1;
        goto error;
    }

    *out = sock;

done:

    return err;

error:

    if (sock)
    {
        if (sock->connection)
        {
            SMBCloseServer(sock->connection);
        }

        if (sock->selectfd[0] != -1)
        {
            close(sock->selectfd[0]);
            close(sock->selectfd[1]);
        }

        dcethread_mutex_destroy_throw(&sock->lock);
        dcethread_cond_destroy_throw(&sock->event);
    }

    goto done;
}

INTERNAL
void
rpc__smb_socket_destroy(
    rpc_smb_socket_p_t sock
    )
{
    if (sock)
    {
        if (sock->np && sock->connection)
        {
            SMBCloseHandle(sock->connection, sock->np);
        }

        if (sock->connection)
        {
            SMBCloseServer(sock->connection);
        }

        if (sock->selectfd[0] != -1)
        {
            close(sock->selectfd[0]);
            close(sock->selectfd[1]);
        }

        if (sock->sendbuffer.base)
        {
            free(sock->sendbuffer.base);
        }

        if (sock->recvbuffer.base)
        {
            free(sock->recvbuffer.base);
        }

        dcethread_mutex_destroy_throw(&sock->lock);
        dcethread_cond_destroy_throw(&sock->event);

        free(sock);
    }

    return;
}

INTERNAL
inline
void
rpc__smb_socket_lock(
    rpc_smb_socket_p_t sock
    )
{
    dcethread_mutex_lock_throw(&sock->lock);
}

INTERNAL
inline
void
rpc__smb_socket_unlock(
    rpc_smb_socket_p_t sock
    )
{
    dcethread_mutex_unlock_throw(&sock->lock);
}

INTERNAL
inline
void
rpc__smb_socket_change_state(
    rpc_smb_socket_p_t sock,
    rpc_smb_state_t state
    )
{
    sock->state = state;
    dcethread_cond_broadcast_throw(&sock->event);
}

INTERNAL
inline
void
rpc__smb_socket_wait(
    rpc_smb_socket_p_t sock
    )
{
    DCETHREAD_TRY
    {
        dcethread_cond_wait_throw(&sock->event, &sock->lock);
    }
    DCETHREAD_CATCH_ALL(e)
    {
        dcethread_mutex_unlock(&sock->lock);
        DCETHREAD_RAISE(*e);
    }
    DCETHREAD_ENDTRY;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_construct(
    rpc_socket_t sock,
    rpc_protseq_id_t pseq_id ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_smb_socket_p_t smb_sock = NULL;

    serr = rpc__smb_socket_create(&smb_sock);

    if (serr)
    {
        goto error;
    }

    sock->data.pointer = (void*) smb_sock;

done:

    return serr;

error:

    if (smb_sock)
    {
        rpc__smb_socket_destroy(smb_sock);
    }

    goto done;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_destruct(
    rpc_socket_t sock ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;

    rpc__smb_socket_destroy((rpc_smb_socket_p_t) sock->data.pointer);

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_bind(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    rpc_addr_p_t addr ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_set_session_key(
    rpc_cn_assoc_t *assoc,
    size_t len,
    unsigned char* key
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_np_auth_info_t *np_auth = NULL;

    RPC_MEM_ALLOC(np_auth, rpc_np_auth_info_t*, sizeof(rpc_np_auth_info_t), RPC_C_MEM_NP_SEC_CONTEXT, 0);

    if (!np_auth)
    {
        serr = ENOMEM;
        goto error;
    }

    np_auth->refcount = 0;
    np_auth->princ_name = NULL;
    np_auth->workstation = NULL;
    np_auth->session_key_len = len;

    RPC_MEM_ALLOC(np_auth->session_key, unsigned char*,
                  (sizeof(unsigned char)*(len+1)),
                  RPC_C_MEM_NP_SEC_CONTEXT, 0);

    if (!np_auth->session_key)
    {
        serr = ENOMEM;
        goto error;
    }

    memcpy(np_auth->session_key, key, len);

    assoc->security.assoc_named_pipe_info = np_auth;

    np_auth->refcount++;

done:

    return serr;

error:

    if (np_auth)
    {
        if (np_auth->session_key)
        {
            RPC_MEM_FREE(np_auth->session_key, RPC_C_MEM_NP_SEC_CONTEXT);
        }

        RPC_MEM_FREE(np_auth, RPC_C_MEM_NP_SEC_CONTEXT);
    }

    goto done;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_connect(
    rpc_socket_t sock,
    rpc_addr_p_t addr,
    rpc_cn_assoc_t *assoc ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_smb_socket_p_t smb = (rpc_smb_socket_p_t) sock->data.pointer;
    unsigned_char_t *netaddr = NULL, *endpoint = NULL;
    unsigned32 dbg_status = 0;
    /* FIXME: don't use a static buffer unless smb paths are guaranteed to have a maxmimum length */
    char smbpath[2048];
    DWORD smb_status = 0;
    HANDLE acctoken = INVALID_HANDLE_VALUE;
    PBYTE sesskey = NULL;
    DWORD sesskeylen = 0;

    SMB_SOCKET_LOCK(sock);

    /* Break address into host and endpoint */
    rpc__naf_addr_inq_netaddr (addr,
                               &netaddr,
                               &dbg_status);
    rpc__naf_addr_inq_endpoint (addr,
                               &endpoint,
                               &dbg_status);

    snprintf(smbpath, sizeof(smbpath) - 1, "\\\\%s%s", (char*) netaddr, (char*) endpoint);

    smbpath[sizeof(smbpath) - 1] = '\0';

    smb_status = SMBGetThreadToken(&acctoken);

    if (smb_status)
    {
        serr = -1;
        goto error;
    }

    smb_status = SMBCreateFileA(
        /* IPC connection */
        smb->connection,
        /* Security token */
        acctoken,
        /* Pipe path */
        smbpath,
        /* Access mode */
        GENERIC_READ | GENERIC_WRITE,
        /* Sharing mode */
        SHARE_WRITE | SHARE_READ,
        /* Security attributes */
        NULL,
        /* Open existing pipe */
        OPEN_EXISTING,
        /* Other attributes */
        0,
        /* Template file */
        NULL,
        /* Created handle */
        &smb->np);

    if (smb_status)
    {
        serr = -1;
        goto error;
    }

    smb_status = SMBGetSessionKey(
        smb->connection,
        smb->np,
        &sesskeylen,
        &sesskey);

    if (smb_status)
    {
        serr = -1;
        goto error;
    }

    serr = rpc__smb_socket_set_session_key(
        assoc,
        (size_t) sesskeylen,
        (unsigned char*) sesskey);

    if (serr)
    {
        goto error;
    }

    /* Save address for future inquiries on this socket */
    memcpy(&smb->peeraddr, addr, sizeof(smb->peeraddr));

    /* Since we did a connect, we will be sending first */
    smb->state = SMB_STATE_SEND;

done:

    if (acctoken != INVALID_HANDLE_VALUE)
    {
        SMBCloseHandle(NULL, acctoken);
    }

    if (sesskey)
    {
        SMBFreeSessionKey(sesskey);
    }

    SMB_SOCKET_UNLOCK(sock);

    // rpc_string_free handles when *ptr is NULL
    rpc_string_free(&netaddr, &dbg_status);
    rpc_string_free(&endpoint, &dbg_status);

    return serr;

error:

    goto done;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_accept(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    rpc_addr_p_t addr ATTRIBUTE_UNUSED,
    rpc_socket_t *newsock ATTRIBUTE_UNUSED
)
{
    rpc_socket_error_t serr = ENOTSUP;

    fprintf(stderr, "WARNING: unsupported smb socket function %s\n", __FUNCTION__);

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_listen(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    int backlog ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = ENOTSUP;

    fprintf(stderr, "WARNING: unsupported smb socket function %s\n", __FUNCTION__);

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_do_transact(
    rpc_socket_t sock
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_smb_socket_p_t smb = (rpc_smb_socket_p_t) sock->data.pointer;
    DWORD bytes_read = 0;
    DWORD smb_status = 0;
    char c = 0;

    /* We have the last fragment in the buffer, so perform a transact */
    serr = rpc__smb_buffer_ensure_available(&smb->recvbuffer, 8192);
    if (serr)
    {
        goto error;
    }

    bytes_read = 0;

    smb_status = SMBTransactNamedPipe(
        /* IPC connection */
        smb->connection,
        /* Named pipe handle */
        smb->np,
        /* Send buffer */
        smb->sendbuffer.base,
        /* Amount of data to send */
        smb->sendbuffer.start_cursor - smb->sendbuffer.base,
        /* Recv buffer */
        smb->recvbuffer.end_cursor,
        /* Amount of room in receive buffer */
        rpc__smb_buffer_available(&smb->recvbuffer),
        /* Bytes read */
        &bytes_read,
        /* No overlapped IO */
        NULL);

    smb->recvbuffer.end_cursor += bytes_read;

    /* If we didn't get the full reply, keep increasing buffer space until
       we finish the transaction */
    while (smb_status == SMB_ERROR_INSUFFICIENT_BUFFER)
    {
        serr = rpc__smb_buffer_ensure_available(&smb->recvbuffer, 2048);
        if (serr)
        {
            goto error;
        }

        bytes_read = 0;

        smb_status = SMBTransactNamedPipe(
            /* IPC connection */
            smb->connection,
            /* Named pipe handle */
            smb->np,
            /* Don't send anything */
            NULL,
            0,
            /* Recv buffer */
            smb->recvbuffer.end_cursor,
            /* Amount of room in receive buffer */
            rpc__smb_buffer_available(&smb->recvbuffer),
            /* Bytes read */
            &bytes_read,
            /* No overlapped IO */
            NULL);

        smb->recvbuffer.end_cursor += bytes_read;
    }

    if (smb_status)
    {
        serr = -1;
        goto error;
    }

    /* Settle the remaining data (which hopefully should be zero if
       the runtime calls us with complete packets) to the start of
       the send buffer */
    rpc__smb_buffer_settle(&smb->sendbuffer);

    /* Now that a complete message has been sent, we must switch
       into recv mode so the receiver thread can empty the recv buffer */
    rpc__smb_socket_change_state(smb, SMB_STATE_RECV);

    /* Write a byte into the write end of the select pipe to wake up
       anything in a select */
    if (write(smb->selectfd[1], &c, sizeof(c)) < (ssize_t) sizeof(c))
    {
        serr = errno;
        goto error;
    }

    smb->selectfd_triggered = true;

error:

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_do_send_recv(
    rpc_socket_t sock
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_smb_socket_p_t smb = (rpc_smb_socket_p_t) sock->data.pointer;
    DWORD bytes_requested = 0;
    DWORD bytes_read = 0;
    DWORD bytes_written = 0;
    DWORD smb_status = 0;
    char c = 0;
    unsigned char* cursor = smb->sendbuffer.base;

    do
    {
        smb_status = SMBWriteFile(
            /* IPC connection */
            smb->connection,
            /* Named pipe handle */
            smb->np,
            /* Send buffer */
            smb->sendbuffer.base,
            /* Amount of data to send */
            smb->sendbuffer.start_cursor - cursor,
            /* Bytes written */
            &bytes_written,
            /* No overlapped IO */
            NULL);

        cursor += bytes_written;

        if (smb_status)
        {
            serr = -1;
            goto error;
        }
    } while (cursor < smb->sendbuffer.start_cursor);

    do
    {
        serr = rpc__smb_buffer_ensure_available(&smb->recvbuffer, 8192);
        if (serr)
        {
            goto error;
        }

        bytes_read = 0;
        bytes_requested = rpc__smb_buffer_available(&smb->recvbuffer);

        smb_status = SMBReadFile(
            /* IPC connection */
            smb->connection,
            /* Named pipe handle */
            smb->np,
            /* Recv buffer */
            smb->recvbuffer.end_cursor,
            /* Amount of room in receive buffer */
            bytes_requested,
            /* Bytes read */
            &bytes_read,
            /* No overlapped IO */
            NULL);

        if (smb_status)
        {
            serr = -1;
            goto error;
        }

        smb->recvbuffer.end_cursor += bytes_read;
    } while (bytes_read == bytes_requested);

    if (smb_status)
    {
        serr = -1;
        goto error;
    }

    /* Settle the remaining data (which hopefully should be zero if
       the runtime calls us with complete packets) to the start of
       the send buffer */
    rpc__smb_buffer_settle(&smb->sendbuffer);

    /* Now that a complete message has been sent, we must switch
       into recv mode so the receiver thread can empty the recv buffer */
    rpc__smb_socket_change_state(smb, SMB_STATE_RECV);

    /* Write a byte into the write end of the select pipe to wake up
       anything in a select */
    if (write(smb->selectfd[1], &c, sizeof(c)) < (ssize_t) sizeof(c))
    {
        serr = errno;
        goto error;
    }

    smb->selectfd_triggered = true;

error:

    return serr;
}


INTERNAL
rpc_socket_error_t
rpc__smb_socket_sendmsg(
    rpc_socket_t sock,
    rpc_socket_iovec_p_t iov,
    int iov_len,
    rpc_addr_p_t addr ATTRIBUTE_UNUSED,
    int *cc
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_smb_socket_p_t smb = (rpc_smb_socket_p_t) sock->data.pointer;
    int i;
    size_t pending = 0;

    SMB_SOCKET_LOCK(sock);

    /* Wait until we are in a state where we can send */
    while (smb->state != SMB_STATE_SEND)
    {
        if (smb->state == SMB_STATE_ERROR)
        {
            serr = -1;
            goto error;
        }
        rpc__smb_socket_wait(smb);
    }

    *cc = 0;

    /* Append all fragments into a single buffer so that we can use SMB transactions */
    for (i = 0; i < iov_len; i++)
    {
        serr = rpc__smb_buffer_append(&smb->sendbuffer, iov[i].iov_base, iov[i].iov_len);

        if (serr)
        {
            goto error;
        }

        *cc += iov[i].iov_len;
    }

    /* Look for the last fragment and do a transaction if we find it */
    if (rpc__smb_buffer_advance_cursor(&smb->sendbuffer, &pending))
    {
        if (pending < TRANSACT_CUTOFF)
        {
            serr = rpc__smb_socket_do_transact(sock);
        }
        else
        {
            serr = rpc__smb_socket_do_send_recv(sock);
        }

        if (serr)
        {
            goto error;
        }
    }

cleanup:

    SMB_SOCKET_UNLOCK(sock);

    return serr;

error:

    rpc__smb_socket_change_state(smb, SMB_STATE_ERROR);

    goto cleanup;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_recvfrom(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    byte_p_t buf ATTRIBUTE_UNUSED,
    int len ATTRIBUTE_UNUSED,
    rpc_addr_p_t from ATTRIBUTE_UNUSED,
    int *cc ATTRIBUTE_UNUSED
)
{
    rpc_socket_error_t serr = ENOTSUP;

    fprintf(stderr, "WARNING: unsupported smb socket function %s\n", __FUNCTION__);

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_recvmsg(
    rpc_socket_t sock,
    rpc_socket_iovec_p_t iov,
    int iov_len,
    rpc_addr_p_t addr,
    int *cc
)
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_smb_socket_p_t smb = (rpc_smb_socket_p_t) sock->data.pointer;
    int i;
    size_t pending;
    char c;

    SMB_SOCKET_LOCK(sock);

    while (smb->state != SMB_STATE_RECV)
    {
        if (smb->state == SMB_STATE_ERROR)
        {
            serr = -1;
            goto error;
        }
        rpc__smb_socket_wait(smb);
    }

    *cc = 0;

    for (i = 0; i < iov_len; i++)
    {
        pending = rpc__smb_buffer_pending(&smb->recvbuffer);
        if (iov[i].iov_len < pending)
        {
            memcpy(iov[i].iov_base, smb->recvbuffer.start_cursor, iov[i].iov_len);

            smb->recvbuffer.start_cursor += iov[i].iov_len;
            *cc += iov[i].iov_len;
        }
        else
        {
            memcpy(iov[i].iov_base, smb->recvbuffer.start_cursor, pending);

            *cc += pending;

            /* Reset buffer because we have emptied it */
            smb->recvbuffer.start_cursor = smb->recvbuffer.end_cursor = smb->recvbuffer.base;
            /* Switch into send mode */
            rpc__smb_socket_change_state(smb, SMB_STATE_SEND);
            /* Clear select pipe since no data is available for reading */
            if (smb->selectfd_triggered)
            {
                smb->selectfd_triggered = false;
                if (read(smb->selectfd[0], &c, sizeof(c)) < (ssize_t) sizeof(c))
                {
                    serr = errno;
                    goto error;
                }
            }
            break;
        }
    }

    if (addr)
    {
        memcpy(addr, &smb->peeraddr, sizeof(smb->peeraddr));
    }

cleanup:

    SMB_SOCKET_UNLOCK(sock);

    return serr;

error:

    rpc__smb_socket_change_state(smb, SMB_STATE_ERROR);

    goto cleanup;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_inq_endpoint(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    rpc_addr_p_t addr
)
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_np_addr_p_t npaddr = (rpc_np_addr_p_t) addr;

    /* Fill address with stock information */

    npaddr->rpc_protseq_id = RPC_C_PROTSEQ_ID_NCACN_NP;
    npaddr->len = offsetof(rpc_np_addr_t, remote_host) + sizeof(npaddr->remote_host);
    npaddr->sa.sun_family = AF_UNIX;
    npaddr->sa.sun_path[0] = '\0';
    npaddr->remote_host[0] = '\0';

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_set_broadcast(
    rpc_socket_t sock ATTRIBUTE_UNUSED
)
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_set_bufs(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    unsigned32 txsize ATTRIBUTE_UNUSED,
    unsigned32 rxsize ATTRIBUTE_UNUSED,
    unsigned32 *ntxsize ATTRIBUTE_UNUSED,
    unsigned32 *nrxsize ATTRIBUTE_UNUSED
)
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_set_nbio(
    rpc_socket_t sock ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = ENOTSUP;

    fprintf(stderr, "WARNING: unsupported smb socket function %s\n", __FUNCTION__);

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_set_close_on_exec(
    rpc_socket_t sock ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_getpeername(
    rpc_socket_t sock,
    rpc_addr_p_t addr
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;
    rpc_smb_socket_p_t smb = (rpc_smb_socket_p_t) sock->data.pointer;

    SMB_SOCKET_LOCK(sock);

    if (!smb->np)
    {
        serr = EINVAL;
        goto error;
    }

    memcpy(addr, &smb->peeraddr, sizeof(smb->peeraddr));

error:

    SMB_SOCKET_UNLOCK(sock);

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_get_if_id(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    rpc_network_if_id_t *network_if_id ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = ENOTSUP;

    fprintf(stderr, "WARNING: unsupported smb socket function %s\n", __FUNCTION__);

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_set_keepalive(
    rpc_socket_t sock ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_nowriteblock_wait(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    struct timeval *tmo ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = ENOTSUP;

    fprintf(stderr, "WARNING: unsupported smb socket function %s\n", __FUNCTION__);

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_set_rcvtimeo(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    struct timeval *tmo ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = RPC_C_SOCKET_OK;

    return serr;
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_getpeereid(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    uid_t *euid ATTRIBUTE_UNUSED,
    gid_t *egid ATTRIBUTE_UNUSED
    )
{
    rpc_socket_error_t serr = ENOTSUP;

    fprintf(stderr, "WARNING: unsupported smb socket function %s\n", __FUNCTION__);

    return serr;
}

INTERNAL
int
rpc__smb_socket_get_select_desc(
    rpc_socket_t sock
    )
{
    rpc_smb_socket_p_t smb = (rpc_smb_socket_p_t) sock->data.pointer;
    return smb->selectfd[0];
}

INTERNAL
rpc_socket_error_t
rpc__smb_socket_enum_ifaces(
    rpc_socket_t sock ATTRIBUTE_UNUSED,
    rpc_socket_enum_iface_fn_p_t efun ATTRIBUTE_UNUSED,
    rpc_addr_vector_p_t *rpc_addr_vec ATTRIBUTE_UNUSED,
    rpc_addr_vector_p_t *netmask_addr_vec ATTRIBUTE_UNUSED,
    rpc_addr_vector_p_t *broadcast_addr_vec ATTRIBUTE_UNUSED
)
{
    rpc_socket_error_t serr = ENOTSUP;

    fprintf(stderr, "WARNING: unsupported smb socket function %s\n", __FUNCTION__);

    return serr;
}

rpc_socket_vtbl_t rpc_g_smb_socket_vtbl =
{
    .socket_construct = rpc__smb_socket_construct,
    .socket_destruct = rpc__smb_socket_destruct,
    .socket_bind = rpc__smb_socket_bind,
    .socket_connect = rpc__smb_socket_connect,
    .socket_accept = rpc__smb_socket_accept,
    .socket_listen = rpc__smb_socket_listen,
    .socket_sendmsg = rpc__smb_socket_sendmsg,
    .socket_recvfrom = rpc__smb_socket_recvfrom,
    .socket_recvmsg = rpc__smb_socket_recvmsg,
    .socket_inq_endpoint = rpc__smb_socket_inq_endpoint,
    .socket_set_broadcast = rpc__smb_socket_set_broadcast,
    .socket_set_bufs = rpc__smb_socket_set_bufs,
    .socket_set_nbio = rpc__smb_socket_set_nbio,
    .socket_set_close_on_exec = rpc__smb_socket_set_close_on_exec,
    .socket_getpeername = rpc__smb_socket_getpeername,
    .socket_get_if_id = rpc__smb_socket_get_if_id,
    .socket_set_keepalive = rpc__smb_socket_set_keepalive,
    .socket_nowriteblock_wait = rpc__smb_socket_nowriteblock_wait,
    .socket_set_rcvtimeo = rpc__smb_socket_set_rcvtimeo,
    .socket_getpeereid = rpc__smb_socket_getpeereid,
    .socket_get_select_desc = rpc__smb_socket_get_select_desc,
    .socket_enum_ifaces = rpc__smb_socket_enum_ifaces
};
