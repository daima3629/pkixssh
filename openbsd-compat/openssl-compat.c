/*
 * Copyright (c) 2005 Darren Tucker <dtucker@zip.com.au>
 * Copyright (c) 2011-2024 Roumen Petrov.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#ifdef WITH_OPENSSL

#include <stdarg.h>
#include <string.h>

#ifdef USE_OPENSSL_ENGINE
# include <openssl/engine.h>
# include <openssl/conf.h>
#endif
#include <openssl/rand.h>

#include "log.h"

#include "evp-compat.h"

#if !defined(HAVE_ERR_ADD_ERROR_DATA) && defined(HAVE_ERR_ASPRINTF_ERROR_DATA)
#include <openssl/err.h>	/* for ERR_asprintf_error_data() */

void
ERR_add_error_data(int num, ...) {
	va_list args;
	va_start(args, num);
	ERR_add_error_vdata(num, args);
	va_end(args);
}

void
ERR_add_error_vdata(int num, va_list args) {
	char *arg;
	if (num != 1) return; /* PKIX-SSH call only with one argument */
	arg = va_arg(args, char *);
	ERR_asprintf_error_data("%s", arg);
}
#endif

#ifndef HAVE_EVP_PKEY_PRINT_PARAMS
int
EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
    int indent, /*ASN1_PCTX*/void *pctx)
{
	int ret;
	int evp_id = -1;

	UNUSED(indent);
	UNUSED(pctx);
	if (pkey == NULL) goto err;

	evp_id = EVP_PKEY_base_id(pkey);
	switch (evp_id) {
	case EVP_PKEY_DH: {
		DH *dh = EVP_PKEY_get1_DH((EVP_PKEY*/*safe cast*/)pkey);
		if (dh == NULL) goto err;
		ret = DHparams_print(out, dh);
		DH_free(dh);
		} break;
	/*TODO*/
	default:
		goto err;
	}

	return ret;

err:
	BIO_printf(out, "cannot print parameters for pkey type %d", evp_id);
	return -1;
}
#endif

/* Notes about new OpenSSL 3+ version scheme:
 * Test for compatibility version is not applicable as new base version
 * is assigned to all library symbols. With other words for any new major
 * release, the version number for all symbols is automatically bumped
 * to the new release's version number. Also minor releases should keep
 * binary compatibility.
 * Usable only if OS loader does not support symbol versioning.
 */
/*
 * OpenSSL version numbers: MNNFFPPS: major minor fix patch status
 * Versions >= 3.0 require only major versions to match.
 * For versions < 3.0, accept compatible fix versions, i.e. allow 1.0.1
 * to work with 1.0.0.
 * Going backwards is only allowed within a patch series.
 * See https://www.openssl.org/policies/releasestrat.html
 */
int ssh_compatible_openssl(long headerver, long libver);

int
ssh_compatible_openssl(long headerver, long libver)
{
	long mask, hfix, lfix;

	/* exact match is always OK */
	if (headerver == libver)
		return 1;

	/* for versions >= 3.0, only the major,status must match */
	if (headerver >= 0x3000000f) {
		mask = 0xf000000fL; /* major,status */
		return (headerver & mask) == (libver & mask);
	}

	/* for versions < 1.0.0, major,minor,fix,status must match */
	if (headerver < 0x1000000f) {
		mask = 0xfffff00fL; /* major,minor,fix,status */
		return (headerver & mask) == (libver & mask);
	}

	/*
	 * For versions >= 1.0.0, but < 3, major,minor,status must match and
	 * library fix version must be equal to or newer than the header.
	 */
	mask = 0xfff0000fL; /* major,minor,status */
	hfix = (headerver & 0x000ff000) >> 12;
	lfix = (libver & 0x000ff000) >> 12;
	if ( (headerver & mask) == (libver & mask) && lfix >= hfix)
		return 1;
	return 0;
}


int
ssh_FIPS_mode(int onoff)
{
#ifdef OPENSSL_FIPS
	int mode = FIPS_mode();

	if (onoff && mode)
		return(1);

	if (!onoff && !mode)
		return(1);

	if (!FIPS_mode_set(onoff)) {
		ssh_OpenSSL_load_error_strings();
		do_log_crypto_errors(SYSLOG_LEVEL_ERROR);
		fatal("FIPS_mode_set(%s) failed", (onoff ? "on" : "off"));
	}

#if defined(OPENSSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER < 0x10000000L)
	if(!onoff)
		RAND_set_rand_method(NULL);
#endif

	return(1);

#else	/* ndef OPENSSL_FIPS */
	(void) onoff;
	return(0);
#endif
}


#ifndef HAVE_OPENSSL_INIT_CRYPTO
# include <openssl/err.h>
#endif
#ifdef OPENSSL_FIPS
# if HAVE_DECL_ERR_LOAD_FIPS_STRINGS
#  ifdef HAVE_OPENSSL_FIPS_H
#   include <openssl/fips.h> /* for ERR_load_FIPS_strings() */
#  endif
# else
void ERR_load_FIPS_strings(void);
# endif
#endif

void
ssh_OpenSSL_load_error_strings(void) {
#ifdef HAVE_OPENSSL_INIT_CRYPTO
	OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#else
	ERR_load_crypto_strings();
#endif
#if defined(OPENSSL_FIPS) && defined(HAVE_ERR_LOAD_FIPS_STRINGS)
/* load explicitly as is not loaded in some vendor libraries */
	ERR_load_FIPS_strings();
#endif
}


void
ssh_OpenSSL_startup(void)
{
#ifdef HAVE_OPENSSL_INIT_CRYPTO
	OPENSSL_init_crypto(
	#ifdef USE_OPENSSL_ENGINE
	    OPENSSL_INIT_ENGINE_ALL_BUILTIN |
	#endif
	    OPENSSL_INIT_ADD_ALL_CIPHERS |
	    OPENSSL_INIT_ADD_ALL_DIGESTS |
	    OPENSSL_INIT_LOAD_CONFIG, NULL);

#ifdef OPENSSL_FIPS
	/* vendor OpenSSL 1.1 may support FIPS */
	if (getenv("OPENSSL_FIPS")) {
		(void) ssh_FIPS_mode(1);
	}
#endif
#else
	OpenSSL_add_all_algorithms();

#ifdef OPENSSL_FIPS
	if (getenv("OPENSSL_FIPS")) {
		(void) ssh_FIPS_mode(1);
	}
#endif

#ifdef	USE_OPENSSL_ENGINE
#if 0
/* Next two calls are useless if link is with dynamic engine. Also
 * they will initialize static engines and later OPENSSL_config load
 * engines again. This double initialization could crash application,
 * usually in application shutdown code (engine cleanup) even without
 * use of engines.
 */
	/* Enable use of crypto hardware */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
#endif

	/* OPENSSL_config will load buildin engines and engines
	 * specified in configuration file, i.e. method call
	 * ENGINE_load_builtin_engines. Latter is only for
	 * dynamic engines.
	 */
	OPENSSL_config(NULL);

	/* Starting from openssl 1.0.1 ENGINE_load_builtin_engines
	 * call ENGINE_register_all_complete internally.
	 * Application should request registration for compatibility
	 * with all previous versions and it is save to request again.
	 * Note that dynamic_path in openssl engine configuration
	 * may register engine as default. If engine methods are not
	 * usable as default methods use of non-engine keys may trigger
	 * error in sign/verify operation.
	 */
	ENGINE_register_all_complete();
#endif /*def USE_OPENSSL_ENGINE*/
#endif /*def HAVE_OPENSSL_INIT_CRYPTO*/
}


void
ssh_OpenSSL_shuthdown(void) {
#ifdef HAVE_OPENSSL_CLEANUP
	OPENSSL_cleanup();
#else
	/* clean configuration before engine:
	 * - it should clean internaly initialized engines */
	CONF_modules_unload(1);
	/* engine may provide rand implementation:
	 * - lets clean rand before engines */
	RAND_cleanup();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	/* engine may use extra data so clean it after engines */
	CRYPTO_cleanup_all_ex_data();
	EVP_cleanup();
	OBJ_cleanup();
#ifdef HAVE_ERR_REMOVE_THREAD_STATE
	ERR_remove_thread_state(NULL);
#else
	ERR_remove_state(0);
#endif
	ERR_free_strings();
#endif /*def HAVE_OPENSSL_INIT_CRYPTO*/
}

#else

void ssh_OpenSSL_startup()   {}
void ssh_OpenSSL_shuthdown() {}

#endif /* WITH_OPENSSL */
