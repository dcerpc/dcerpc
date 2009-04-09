$ Copyright (c) 2009, Apple, Inc.
$ All rights reserved.
$ 
$ Redistribution and use in source and binary forms, with or without
$ modification, are permitted provided that the following conditions
$ are met:
$ 1. Redistributions of source code must retain the above copyright
$    notice, this list of conditions and the following disclaimer.
$ 2. Redistributions in binary form must reproduce the above copyright
$    notice, this list of conditions and the following disclaimer in the
$    documentation and/or other materials provided with the distribution.
$ 3. Neither the name of the Apple, Inc. nor the names of its contributors
$    may be used to endorse or promote products derived from this software
$    without specific prior written permission.
$
$ THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
$ "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
$ LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
$ A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
$ OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
$ SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
$ LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
$ DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
$ THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
$ (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
$ OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

$set 1

1 rpc_s_op_rng_error
2 rpc_s_cant_create_socket
3 rpc_s_cant_bind_socket
4 rpc_s_not_in_call
5 rpc_s_no_port
6 rpc_s_wrong_boot_time
7 rpc_s_too_many_sockets
8 rpc_s_illegal_register
9 rpc_s_cant_recv
16 rpc_s_binding_has_no_auth
17 rpc_s_unknown_authn_service
18 rpc_s_no_memory
19 rpc_s_cant_nmalloc
20 rpc_s_call_faulted
21 rpc_s_call_failed
22 rpc_s_comm_failure
23 rpc_s_rpcd_comm_failure
24 rpc_s_illegal_family_rebind
25 rpc_s_invalid_handle
32 rpc_s_invalid_rpc_protseq
33 rpc_s_desc_not_registered
34 rpc_s_already_listening
35 rpc_s_no_protseqs
36 rpc_s_no_protseqs_registered
37 rpc_s_no_bindings
38 rpc_s_max_descs_exceeded
39 rpc_s_no_interfaces
40 rpc_s_invalid_timeout
41 rpc_s_cant_inq_socket
48 rpc_s_cancel_timeout
49 rpc_s_call_cancelled
50 rpc_s_invalid_call_handle
51 rpc_s_cannot_alloc_assoc
52 rpc_s_cannot_connect
53 rpc_s_connection_aborted
54 rpc_s_connection_closed
55 rpc_s_cannot_accept
56 rpc_s_assoc_grp_not_found
57 rpc_s_stub_interface_error
64 rpc_s_invalid_string_binding
65 rpc_s_connect_timed_out
66 rpc_s_connect_rejected
67 rpc_s_network_unreachable
68 rpc_s_connect_no_resources
69 rpc_s_rem_network_shutdown
70 rpc_s_too_many_rem_connects
71 rpc_s_no_rem_endpoint
72 rpc_s_rem_host_down
73 rpc_s_host_unreachable
80 rpc_s_unknown_mgr_type
81 rpc_s_assoc_creation_failed
82 rpc_s_assoc_grp_max_exceeded
83 rpc_s_assoc_grp_alloc_failed
84 rpc_s_sm_invalid_state
85 rpc_s_assoc_req_rejected
86 rpc_s_assoc_shutdown
87 rpc_s_tsyntaxes_unsupported
88 rpc_s_context_id_not_found
89 rpc_s_cant_listen_socket
96 rpc_s_unknown_reject
97 rpc_s_type_already_registered
98 rpc_s_stop_listening_disabled
99 rpc_s_invalid_arg
100 rpc_s_not_supported
101 rpc_s_wrong_kind_of_binding
102 rpc_s_authn_authz_mismatch
103 rpc_s_call_queued
104 rpc_s_cannot_set_nodelay
105 rpc_s_not_rpc_tower
112 rpc_s_server_too_busy
113 rpc_s_prot_version_mismatch
114 rpc_s_rpc_prot_version_mismatch
115 rpc_s_ss_no_import_cursor
116 rpc_s_fault_addr_error
117 rpc_s_fault_context_mismatch
118 rpc_s_fault_fp_div_by_zero
119 rpc_s_fault_fp_error
120 rpc_s_fault_fp_overflow
121 rpc_s_fault_fp_underflow
128 rpc_s_fault_pipe_comm_error
129 rpc_s_fault_pipe_discipline
130 rpc_s_fault_pipe_empty
131 rpc_s_fault_pipe_memory
132 rpc_s_fault_pipe_order
133 rpc_s_fault_remote_comm_failure
134 rpc_s_fault_remote_no_memory
135 rpc_s_fault_unspec
136 uuid_s_bad_version
137 uuid_s_socket_failure
144 uuid_s_no_memory
145 rpc_s_no_more_entries
146 rpc_s_unknown_ns_error
147 rpc_s_name_service_unavailable
148 rpc_s_incomplete_name
149 rpc_s_group_not_found
150 rpc_s_invalid_name_syntax
151 rpc_s_no_more_members
152 rpc_s_no_more_interfaces
153 rpc_s_invalid_name_service
256 rpc_s_authn_challenge_malformed
257 rpc_s_protect_level_mismatch
258 rpc_s_no_mepv
259 rpc_s_stub_protocol_error
260 rpc_s_class_version_mismatch
261 rpc_s_helper_not_running
262 rpc_s_helper_short_read
263 rpc_s_helper_catatonic
264 rpc_s_helper_aborted
265 rpc_s_not_in_kernel
272 rpc_s_ss_bad_buffer
273 rpc_s_ss_bad_es_action
274 rpc_s_ss_wrong_es_version
275 rpc_s_fault_user_defined
276 rpc_s_ss_incompatible_codesets
277 rpc_s_tx_not_in_transaction
278 rpc_s_tx_open_failed
279 rpc_s_partial_credentials
280 rpc_s_ss_invalid_codeset_tag
281 rpc_s_mgmt_bad_type
288 dce_cs_c_unknown
289 dce_cs_c_notfound
290 dce_cs_c_cannot_open_file
291 dce_cs_c_cannot_read_file
292 dce_cs_c_cannot_allocate_memory
293 rpc_s_ss_cleanup_failed
294 rpc_svc_desc_general
295 rpc_svc_desc_mutex
296 rpc_svc_desc_xmit
297 rpc_svc_desc_recv
304 rpc_svc_desc_auth
305 rpc_svc_desc_source
306 rpc_svc_desc_stats
307 rpc_svc_desc_mem
308 rpc_svc_desc_mem_type
309 rpc_svc_desc_dg_pktlog
310 rpc_svc_desc_thread_id
311 rpc_svc_desc_timestamp
312 rpc_svc_desc_cn_errors
313 rpc_svc_desc_conv_thread
320 rpc_svc_desc_threads
321 rpc_svc_desc_server_call
322 rpc_svc_desc_nsi
323 rpc_svc_desc_dg_pkt
324 rpc_m_cn_ill_state_trans_sa
325 rpc_m_cn_ill_state_trans_ca
326 rpc_m_cn_ill_state_trans_sg
327 rpc_m_cn_ill_state_trans_cg
328 rpc_m_cn_ill_state_trans_sr
329 rpc_m_cn_ill_state_trans_cr
336 rpc_m_call_failed_no_status
337 rpc_m_call_failed_errno
338 rpc_m_call_failed_s
339 rpc_m_call_failed_c
340 rpc_m_errmsg_toobig
341 rpc_m_invalid_srchattr
342 rpc_m_nts_not_found
343 rpc_m_invalid_accbytcnt
344 rpc_m_pre_v2_ifspec
345 rpc_m_unk_ifspec
352 rpc_m_unimp_call
353 rpc_m_invalid_seqnum
354 rpc_m_cant_create_uuid
355 rpc_m_pre_v2_ss
356 rpc_m_dgpkt_pool_corrupt
357 rpc_m_dgpkt_bad_free
358 rpc_m_lookaside_corrupt
359 rpc_m_alloc_fail
360 rpc_m_realloc_fail
361 rpc_m_cant_open_file
