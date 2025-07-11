#ifndef _MM_WRAP_H_
#define _MM_WRAP_H_
/* $OpenBSD: monitor_wrap.h,v 1.51 2024/05/17 06:42:04 jsg Exp $ */
/*
 * Copyright 2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Copyright (c) 2017-2022 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include "evp-compat.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif

extern int use_privsep;
#define PRIVSEP(x)	(use_privsep ? mm_##x : x)

enum mm_keytype { MM_NOKEY, MM_HOSTKEY, MM_USERKEY };

struct ssh;
struct monitor;
struct Authctxt;
struct sshkey;
struct sshauthopt;

void mm_log_handler(LogLevel level, const char *msg, void *ctx);
int mm_is_monitor(void);
EVP_PKEY*	mm_kex_new_dh_group_bits(int, int, int);
int mm_Xkey_sign(struct ssh *ssh, ssh_sign_ctx *ctx, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen);
void mm_inform_authserv(char *, char *);
struct passwd *mm_getpwnamallow(struct ssh *, const char *);
char *mm_auth2_read_banner(void);
int mm_auth_password(struct ssh *, char *);
int mm_user_xkey_allowed(struct ssh *, struct passwd *, ssh_verify_ctx *, int,
	struct sshauthopt **);
int mm_hostbased_xkey_allowed(struct ssh *, struct passwd *,
	ssh_verify_ctx *, const char *, const char *);
int mm_Xkey_verify(ssh_verify_ctx *ctx,
	const u_char *sig, size_t siglen,
	const u_char *data, size_t datalen);

#ifdef GSSAPI
OM_uint32 mm_ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
OM_uint32 mm_ssh_gssapi_accept_ctx(Gssctxt *,
   gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
int mm_ssh_gssapi_userok(char *user);
OM_uint32 mm_ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
#endif

#ifdef USE_PAM
void mm_start_pam(struct ssh *ssh);
u_int mm_do_pam_account(void);
void *mm_sshpam_init_ctx(struct Authctxt *);
int mm_sshpam_query(void *, char **, char **, u_int *, char ***, u_int **);
int mm_sshpam_respond(void *, u_int, char **);
void mm_sshpam_free_ctx(void *);
#endif

#ifdef SSH_AUDIT_EVENTS
#include "audit.h"
void mm_audit_event(struct ssh *, ssh_audit_event_t);
void mm_audit_run_command(const char *);
#endif

struct Session;
void mm_terminate(void);
int mm_pty_allocate(int *, int *, char *, size_t);
void mm_session_pty_cleanup2(struct Session *);

void mm_send_keystate(struct ssh *, struct monitor*);

/* bsdauth */
int mm_bsdauth_query(void *, char **, char **, u_int *, char ***, u_int **);
int mm_bsdauth_respond(void *, u_int, char **);

void server_process_permitopen(struct ssh *);
void server_process_channel_timeouts(struct ssh *);

struct connection_info *
    server_get_connection_info(struct ssh *, int, int);

#endif /* _MM_WRAP_H_ */
