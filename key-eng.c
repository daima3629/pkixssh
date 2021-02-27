/*
 * Copyright (c) 2011-2021 Roumen Petrov.  All rights reserved.
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

#define SSHKEY_INTERNAL
#include "includes.h"

#include <string.h>
#include <errno.h>

#include <openssl/ui.h>
#ifdef USE_OPENSSL_STORE2
# include <openssl/store.h>
#endif
#include "evp-compat.h"

#include "key-eng.h"
#include "ssh-x509.h"

#include "misc.h"
#include "log.h"
#include "xmalloc.h"
#include "ssherr.h"

/* structure reserved for future use */
typedef struct ssh_pw_cb_data {
	const void *password;
} SSH_PW_CB_DATA;


static UI_METHOD *ssh_ui_method = NULL;

/**/
static int
ui_open(UI *ui) {
	return(UI_method_get_opener(UI_OpenSSL())(ui));
}


static int
ui_read(UI *ui, UI_STRING *uis) {
	enum UI_string_types  uis_type;
	int ui_flags;

	ui_flags = UI_get_input_flags(uis);
	uis_type = UI_get_string_type(uis);

	if (ui_flags & UI_INPUT_FLAG_DEFAULT_PWD) {
		SSH_PW_CB_DATA* cb_data = (SSH_PW_CB_DATA*)UI_get0_user_data(ui);
		if (cb_data != NULL) {
			switch(uis_type) {
			case UIT_PROMPT:
			case UIT_VERIFY: {
				const char *password = cb_data->password;
				if (password && password[0] != '\0') {
					UI_set_result(ui, uis, password);
					return(1);
				}
				} break;
			default:
				break;
			}
		}
	}

{ /* use own method to prompt properly */
	int flags = RP_USE_ASKPASS | RP_ALLOW_STDIN;
	if (ui_flags & UI_INPUT_FLAG_ECHO)
		flags |= RP_ECHO;

	switch(uis_type) {
	case UIT_PROMPT:
	case UIT_VERIFY: {
		const char *prompt;
		char *password;

		prompt = UI_get0_output_string(uis);
		debug3_f("read_passphrase prompt=%s",  prompt);
		password = read_passphrase(prompt, flags);
		UI_set_result(ui, uis, password);
		memset(password, 'x', strlen(password));
		free(password);
		return(1);
		} break;
	case UIT_INFO: {
		const char *s = UI_get0_output_string(uis);
		debug_f("UIT_INFO '%s'", s);
		return(1);
		} break;
	case UIT_ERROR: {
		const char *s = UI_get0_output_string(uis);
		error_f("UIT_ERROR '%s'", s);
		return(1);
		} break;
	default:
		break;
	}
}

	return(UI_method_get_reader(UI_OpenSSL())(ui, uis));
}


static int
ui_write(UI *ui, UI_STRING *uis) {
	enum UI_string_types  uis_type;
	int ui_flags;

	ui_flags = UI_get_input_flags(uis);
	uis_type = UI_get_string_type(uis);

	if (ui_flags & UI_INPUT_FLAG_DEFAULT_PWD) {
		SSH_PW_CB_DATA* cb_data = (SSH_PW_CB_DATA*)UI_get0_user_data(ui);
		if (cb_data != NULL) {
			switch(uis_type) {
			case UIT_PROMPT:
			case UIT_VERIFY: {
				const char *password = cb_data->password;
				if (password && password[0] != '\0') {
					return(1);
				}
				} break;
			default:
				break;
			}
		}
	}
	switch(uis_type) {
	case UIT_INFO: {
		const char *s = UI_get0_output_string(uis);
		debug_f("UIT_INFO '%s'", s);
		return(1);
		} break;
	case UIT_ERROR: {
		const char *s = UI_get0_output_string(uis);
		error_f("UIT_ERROR '%s'", s);
		return(1);
		} break;
	default:
		break;
	}
	return(UI_method_get_writer(UI_OpenSSL())(ui, uis));
}


static int
ui_close(UI *ui) {
	return(UI_method_get_closer(UI_OpenSSL())(ui));
}


static int/*bool*/setup_ssh_ui_method(void);
static void destroy_ssh_ui_method(void);


static int/*bool*/
setup_ssh_ui_method() {
	ssh_ui_method = UI_create_method("PKIX-SSH application user interface");

	if (ssh_ui_method == NULL) return(0);

	if ((UI_method_set_opener(ssh_ui_method, ui_open ) < 0)
	||  (UI_method_set_reader(ssh_ui_method, ui_read ) < 0)
	||  (UI_method_set_writer(ssh_ui_method, ui_write) < 0)
	||  (UI_method_set_closer(ssh_ui_method, ui_close) < 0)) {
		destroy_ssh_ui_method();
		return(0);
	}
	return(1);
}


static void
destroy_ssh_ui_method() {
	if (ssh_ui_method == NULL) return;

	UI_destroy_method(ssh_ui_method);
	ssh_ui_method = NULL;
}


static char*
ignore_suffixes(const char *filename) {
	char* keyid;
	size_t len = strlen(filename);

	/* ignore lame certificates "-cert" */
{	const char sfx[5] = "-cert";
	if (len >= sizeof(sfx)) {
		const char *s = filename + len - sizeof(sfx);
		if (strncmp(s, sfx, sizeof(sfx)) == 0)
			return NULL;
	}
}
	/* ignore lame certificates "-cert.pub" */
{	const char sfx[9] = "-cert.pub";
	if (len >= sizeof(sfx)) {
		const char *s = filename + len - sizeof(sfx);
		if (strncmp(s, sfx, sizeof(sfx)) == 0)
			return NULL;
	}
}

	keyid = xstrdup(filename); /*fatal on error*/

	if (len > 4) {
		/* drop suffix ".pub" from copy */
		char *s = keyid + len - 4;
		if (strncmp(s, ".pub", 4) == 0)
			*s = '\0';
	}
	return keyid;
}


#ifdef USE_OPENSSL_ENGINE
static void
eng_try_load_cert(ENGINE *e, const char *keyid, EVP_PKEY *pk, struct sshkey *k) {
	X509*	x509 = NULL;
	int ctrl_ret = 0;

	if (e == NULL)
		return;

	if ((k->type != KEY_RSA) &&
#ifdef OPENSSL_HAS_ECC
	    (k->type != KEY_ECDSA) &&
#endif
	    (k->type != KEY_DSA))
		return;

	/* try to load certificate with LOAD_CERT_EVP command */
	{
		struct {
			EVP_PKEY *pkey;
			X509 *x509;
		} param = {NULL, NULL};
		param.pkey = pk;

		ctrl_ret = ENGINE_ctrl_cmd(e, "LOAD_CERT_EVP", 0, &param, 0, 0);
		debug3_f("eng cmd LOAD_CERT_EVP return %d", ctrl_ret);
		if (ctrl_ret == 1)
			x509 = param.x509;
	}

	/* try to load certificate with LOAD_CERT_CTRL command */
	if (ctrl_ret != 1) {
		struct {
			const char *keyid;
			X509 *x509;
		} param = {NULL, NULL};
		param.keyid = keyid;

		ctrl_ret = ENGINE_ctrl_cmd(e, "LOAD_CERT_CTRL", 0, &param, 0, 0);
		debug3_f("eng cmd LOAD_CERT_CTRL return %d", ctrl_ret);
		if (ctrl_ret == 1)
			x509 = param.x509;
	}
	debug3_f("certificate=%p", (void*)x509);

	if (x509 == NULL)
		return;

	if (ssh_x509_set_cert(k, x509, NULL))
		x509key_build_chain(k);
	else
		error_f("can not set X.509 certificate to key ");
}


static ENGINE*
split_eng_keyid(const char *keyid, char **engkeyid) {
	ENGINE* e = NULL;
	char *p, *q;

	q = xstrdup(keyid);	/*fatal on error*/

	p = strchr(q, ':');
	if (p == NULL) {
		fatal_f("missing engine identifier");
		goto done; /*;-)*/
	}
	*p = '\0';
	p++;
	if (*p == '\0') {
		fatal_f("missing key identifier");
		goto done; /*;-)*/
	}

	e = ENGINE_by_id(q);
	if (e != NULL) {
		*engkeyid = xstrdup(p);
	}
done:
	free(q);
	return(e);
}


int
engine_load_private(const char *name, const char *passphrase,
	struct sshkey **keyp, char **commentp
) {
	int ret;
	ENGINE *e = NULL;
	char *key_id = NULL;
	const char *e_id;
	EVP_PKEY *pk = NULL;
	struct sshkey *prv = NULL;

	UNUSED(passphrase);
	if (keyp != NULL) *keyp = NULL;
	if (commentp != NULL) *commentp = NULL;

	e = split_eng_keyid(name, &key_id);
	if (e == NULL) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}
	e_id = ENGINE_get_id(e);

	pk = ENGINE_load_private_key(e, key_id, ssh_ui_method, NULL);
	if (pk == NULL) {
		error_crypto_fmt("ENGINE_load_private_key", "engine %s", e_id);
		ret = SSH_ERR_KEY_NOT_FOUND;
		goto done;
	}

	ret = sshkey_from_pkey(pk, &prv);
	if (ret != SSH_ERR_SUCCESS) goto done;

	/* TODO: use EVP_PKEY from sshkey */
	eng_try_load_cert(e, key_id, pk, prv);
	debug3("ENGINE private key type: %s", sshkey_type(prv));

	pk = NULL; /* transferred */

	if (commentp != NULL)
		xasprintf(commentp, "engine:%s:%s", e_id, key_id);

	if (keyp != NULL) {
		*keyp = prv;
		prv = NULL;
	}

done:
	EVP_PKEY_free(pk);
	free(key_id);
	if (e != NULL) {
		/* check for NULL to avoid openssl error*/
		ENGINE_free(e);
	}
	debug("read ENGINE private key done: type %s", (prv ? sshkey_type(prv) : "<not found>"));
	sshkey_free(prv);
	return ret;
}


int
engine_try_load_public(const char *name, struct sshkey **keyp, char **commentp) {
	int ret = SSH_ERR_INTERNAL_ERROR;
	const char *url = NULL;
	ENGINE *e = NULL;
	char *key_id = NULL;
	EVP_PKEY *pk = NULL;
	struct sshkey *k = NULL;

	debug3_f("name=%s", name);
	if (keyp != NULL) *keyp = NULL;
	if (commentp != NULL) *commentp = NULL;

	url = ignore_suffixes(name);
/* NOTE: For external keys simulate "missing" file.
 * This suppress extra messages due to faulty load control in ssh.c
 */
	if (url == NULL) {
		errno = ENOENT;
		return SSH_ERR_SYSTEM_ERROR;
	}

	debug3_f("url=%s", url);

	e = split_eng_keyid(url, &key_id);
	if (e == NULL) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto done;
	}

	pk = ENGINE_load_public_key(e, key_id, ssh_ui_method, NULL);
	if (pk == NULL) {
		error_crypto_fmt("ENGINE_load_public_key", "engine %s", ENGINE_get_id(e));
		/* fatal here to avoid PIN lock, for instance
		 * when ssh-askpass program is missing.
		 * NOTE programs still try to load public key many times!
		 */
		fatal_f("avoid device locks ...");
		/* TODO library mode in case of failure */
		ret = SSH_ERR_KEY_NOT_FOUND;
		goto done;
	}

	ret = sshkey_from_pkey(pk, &k);
	if (ret != SSH_ERR_SUCCESS) goto done;

	/* TODO: use EVP_PKEY from sshkey */
	eng_try_load_cert(e, key_id, pk, k);
	debug3("ENGINE public key type: %s", sshkey_type(k));

	pk = NULL; /* transferred */

	if (commentp != NULL)
		xasprintf(commentp, "engine:%s", url);

	if (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}

done:
	sshkey_free(k);
	EVP_PKEY_free(pk);
	free(key_id);
	free((void*)url);
	if (e != NULL) {
		/* check for NULL to avoid openssl error*/
		ENGINE_free(e);
	}
	return(ret);
}


static ENGINE*
try_load_engine(const char *engine) {
	ENGINE *e = NULL;
	int self_registered = 0;

	if (engine == NULL) return NULL;

	/* Check if engine is not already loaded by openssl
	 * (as internal or from config file).
	 * If is not loaded we will call ENGINE_add to keep it
	 * loaded and registered for subsequent use.
	 */
	for (e = ENGINE_get_first(); e != NULL; e = ENGINE_get_next(e)) {
		if (strcmp(engine, ENGINE_get_id(e)) == 0) {
			/* with increase of structural reference */
			goto done;
		}
	}

	e = ENGINE_by_id(engine);
	if (e == NULL) {
		error_crypto("ENGINE_by_id");
		goto done;
	}

{	/* OpenSSL 1.0.1g start to register engines internaly!
	 * So we try to find our engine in internal list and if not
	 * found we use ENGINE_add to register it for compatibility
	 * with previous OpenSSL versions.
	 * Loop on all entries to avoid increase of structural
	 * reference.
	 */
	ENGINE *g;
	for (g = ENGINE_get_first(); g != NULL; g = ENGINE_get_next(g)) {
		if (strcmp(engine, ENGINE_get_id(g)) == 0)
			self_registered = 1;
	}
}

	if (!self_registered && !ENGINE_add(e)) {
		error_crypto("ENGINE_add");
		/*ENGINE_free(e);?*/
		e = NULL;
	}

done:
	if (e != NULL)
		debug3_f("engine '%s' loaded", ENGINE_get_name(e));
	else
		debug3_f("cannot load engine '%s'", engine);
	return e;
}


static ENGINE*
ssh_engine_setup(const char *engine) {
	int ctrl_ret;
	ENGINE *e = NULL;

	e = try_load_engine(engine);
	if (e == NULL) return NULL;

	if (!ENGINE_init(e)) {
		error_crypto("ENGINE_init");
		return NULL;
	}

	ctrl_ret = ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, ssh_ui_method, 0, 1);
	if (!ctrl_ret)
		debug3_crypto_fmt("ENGINE_ctrl_cmd",
		    "engine %s, command SET_USER_INTERFACE",
		    engine);

	if (!ENGINE_free(e)) e = NULL;

	return e;
}


static void
ssh_engine_reset(const char *engine) {
	ENGINE *e = NULL;

	e = ENGINE_by_id(engine);
	if (e == NULL) return;

	/* decrease functional&structural reference from load - ENGINE_init */
	ENGINE_finish(e);

	/* decrease structural reference from above - ENGINE_by_id */
	ENGINE_free(e);
}


#define WHITESPACE " \t\r\n"
/* hold list with names of used engines to free at shutdown */
static struct sshbuf *eng_list = NULL;

/* name of currect engine to process */
static char *eng_name = NULL;


static int/*bool*/
process_engconfig_line(char *line, const char *filename, int linenum) {
	int ret = 1;
	size_t len;
	char *s, *keyword, *arg;
	ENGINE *e;
	int ctrl_ret, r;

	/* strip trailing whitespace */
	len = strlen(line);
	s = line + len - 1;
	for (; len > 0; s--, len--) {
		int ch = (unsigned char)*s;
		if (strchr(WHITESPACE, ch) == NULL)
			break;
		*s = '\0';
	}

	/* ignore leading whitespace */
	s = line;
	if (*s == '\0') return 1;
	keyword = strdelim(&s);
	if (keyword == NULL) return 1;
	if (*keyword == '\0')
		keyword = strdelim(&s);
	if (keyword == NULL) return 1;

	/* ignore comments */
	if (*keyword == '#') return 1;

	if (strcasecmp(keyword, "engine") == 0) {
		arg = strdelim(&s);
		if (!arg || *arg == '\0') {
			error("%.200s line %d: missing engine identifier"
			    , filename, linenum);
			ret = 0;
			goto done;
		}

		e = ssh_engine_setup(arg);
		if (e == NULL) {
			error("%.200s line %d: cannot load engine %s",
			    filename, linenum, arg);
			ret = 0;
			goto done;
		}
		free(eng_name);
		eng_name = xstrdup(arg); /*fatal on error*/
		r = sshbuf_put_cstring(eng_list, eng_name);
		if (r != 0) {
			error_fr(r, "buffer error");
			ret = 0;
			goto done;
		}
	}
	else {
		if (eng_name == NULL) {
			error("%.200s line %d: engine is not specified"
			    , filename, linenum);
			ret = 0;
			goto done;
		}

		e = ENGINE_by_id(eng_name);
		if (e == NULL) {
			error("%.200s line %d: engine(%s) not found"
			    , filename, linenum, eng_name);
			ret = 0;
			goto done;
		}

		arg = strdelim(&s);

		ctrl_ret = ENGINE_ctrl_cmd_string(e, keyword, arg, 0);
		if (!ctrl_ret) {
			error_crypto("ENGINE_ctrl_cmd_string");
			error("%.200s line %d: engine(%s) command fail"
			    , filename, linenum, eng_name);
			ret = 0;
		}

		ENGINE_free(e);
	}

done:
	/* check that there is no garbage at end of line */
	if ((arg = strdelim(&s)) != NULL && *arg != '\0') {
		error("%.200s line %d: garbage at end of line - '%.200s'.",
		    filename, linenum, arg);
		ret = 0;
	}

	return ret;
}


/*
 * Reads the engine config file and execute commands accordingly.
 * If the file does not exist, just exit.
 */
int/*bool*/
process_engconfig_file(const char *filename) {
	int ret = 1; /*true on empty file*/
	FILE *f;

	debug3("reading engine configuration options from '%s'", filename);

	f = fopen(filename, "r");
	if (f == NULL) return 0;

	{/*always check permissions on user engine file*/
		char errmsg[1024];
		if (safe_usr_fileno(fileno(f), filename,
		    errmsg, sizeof(errmsg)) == -1) {
			error("%s", errmsg);
			ret = 0;
			goto done;
		}
	}

{	char line[1024];
	int linenum = 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		linenum++;
		ret = process_engconfig_line(line, filename, linenum);
		if (!ret) break;
	}
}

done:
{	int oerrno = errno;
	fclose(f);
	errno = oerrno;
}
	return ret;
}
#endif /*def USE_OPENSSL_ENGINE*/


#ifdef USE_OPENSSL_STORE2
struct STORE_KEY_DATA_st {
	EVP_PKEY *pk;
	STACK_OF(X509) *chain;
};
typedef struct STORE_KEY_DATA_st STORE_KEY_DATA;

static STORE_KEY_DATA*
STORE_KEY_DATA_new(void) {
	STORE_KEY_DATA* p;

	p = malloc(sizeof(STORE_KEY_DATA));
	if (p == NULL) return NULL;

	p->chain = sk_X509_new_null();
	if (p->chain == NULL) {
		free(p);
		return NULL;
	}

	p->pk = NULL;
	return p;
}

static void
STORE_KEY_DATA_free(STORE_KEY_DATA* p) {
	if (p == NULL) return;

	sk_X509_pop_free(p->chain, X509_free);
	EVP_PKEY_free(p->pk);
	free(p);
}


static STORE_KEY_DATA*
store_load_key(const char *url) {
	STORE_KEY_DATA *ret;
	OSSL_STORE_CTX *store_ctx;

	ret = STORE_KEY_DATA_new();
	if (ret == NULL) return NULL;

	store_ctx = OSSL_STORE_open(url, ssh_ui_method, NULL, NULL, NULL);
	if (store_ctx == NULL) goto done;

	while (!OSSL_STORE_eof(store_ctx) ) {
		OSSL_STORE_INFO *store_info;
		int info_type;

		store_info = OSSL_STORE_load(store_ctx);
		if (store_info == NULL) break;

		info_type = OSSL_STORE_INFO_get_type(store_info);
		switch (info_type) {
		case OSSL_STORE_INFO_PKEY: {
			ret->pk = OSSL_STORE_INFO_get0_PKEY(store_info);
			EVP_PKEY_up_ref(ret->pk);
			} break;
		case OSSL_STORE_INFO_CERT: {
			X509 *x = OSSL_STORE_INFO_get0_CERT(store_info);
			X509_up_ref(x);
			sk_X509_insert(ret->chain, x, -1 /*last*/);
			} break;
		}
		OSSL_STORE_INFO_free(store_info);
	}
	OSSL_STORE_close(store_ctx);

done:
	if (ret->pk == NULL) {
		STORE_KEY_DATA_free(ret);
		return NULL;
	}
	return ret;
}


static void
store_set_key_certs(STORE_KEY_DATA *kd, struct sshkey *key) {
	int n, len;
	X509 *x = NULL;

	len = sk_X509_num(kd->chain);
	if (len <= 0) return;

	for (n = 0; n < sk_X509_num(kd->chain); n++) {
		x = sk_X509_value(kd->chain, n);

		if (EVP_PKEY_cmp(kd->pk, X509_get0_pubkey(x)) == 1)
			break;
	}
	if (n >= len) {
		debug3_f("no certificate that match private key");
		return;
	}

	x = sk_X509_delete(kd->chain, n);
	(void)ssh_x509_set_cert(key, x, kd->chain);
}


int
store_load_private(const char *name, const char *passphrase,
	struct sshkey **keyp, char **commentp
) {
	int ret;
	STORE_KEY_DATA *kd = NULL;
	struct sshkey *prv = NULL;

	UNUSED(passphrase);
	debug3_f("name=%s", name);

	if (keyp != NULL) *keyp = NULL;
	if (commentp != NULL) *commentp = NULL;

	kd = store_load_key(name);
	if (kd == NULL) {
		ret = SSH_ERR_KEY_NOT_FOUND;
		goto done;
	}

	ret = sshkey_from_pkey(kd->pk, &prv);
	if (ret != SSH_ERR_SUCCESS) goto done;

	store_set_key_certs(kd, prv);
	debug3("STORE private key type: %s", sshkey_type(prv));

	kd->pk = NULL; /* transferred */

	if (commentp != NULL)
		xasprintf(commentp, "store:%s", name);

	if (keyp != NULL) {
		*keyp = prv;
		prv = NULL;
	}

done:
	sshkey_free(prv);
	STORE_KEY_DATA_free(kd);
	return ret;
}


int
store_try_load_public(const char *name, struct sshkey **keyp, char **commentp) {
	int ret;
	const char *url = NULL;
	STORE_KEY_DATA *kd = NULL;
	struct sshkey *k = NULL;

	debug3_f("name=%s", name);
	if (keyp != NULL) *keyp = NULL;
	if (commentp != NULL) *commentp = NULL;

	url = ignore_suffixes(name);
/* NOTE: For external keys simulate "missing" file.
 * This suppress extra messages due to faulty load control in ssh.c
 */
	if (url == NULL) {
		errno = ENOENT;
		return SSH_ERR_SYSTEM_ERROR;
	}

	debug3_f("url=%s", url);

	kd = store_load_key(url);
	if (kd == NULL) {
		ret = SSH_ERR_KEY_NOT_FOUND;
		goto done;
	}

	ret = sshkey_from_pkey(kd->pk, &k);
	if (ret != SSH_ERR_SUCCESS) goto done;

	store_set_key_certs(kd, k);
	debug3("STORE public key type: %s", sshkey_type(k));

	kd->pk = NULL; /* transferred */

	if (commentp != NULL)
		xasprintf(commentp, "store:%s", url);

	if (keyp != NULL) {
		*keyp = k;
		k = NULL;
	}

done:
	sshkey_free(k);
	STORE_KEY_DATA_free(kd);
	free((void*)url);
	return ret;
}
#endif /*USE_OPENSSL_STORE2*/


void
ssh_engines_startup() {
#ifdef USE_OPENSSL_ENGINE
	eng_list = sshbuf_new();
	if (eng_list == NULL)
		fatal_f("sshbuf_new failed");
#endif
	(void) setup_ssh_ui_method();
}


void
ssh_engines_shutdown() {
#ifdef USE_OPENSSL_ENGINE
	free(eng_name);
	eng_name = NULL;

	while (sshbuf_len(eng_list) > 0) {
		char *s;
		int r;

		r = sshbuf_get_cstring(eng_list, &s, NULL);
		if (r != 0)
			fatal_fr(r, "buffer error");
		ssh_engine_reset(s);
		free(s);
	};
	sshbuf_free(eng_list);
	eng_list = NULL;
#endif
	destroy_ssh_ui_method();
}
