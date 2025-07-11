/* $OpenBSD: dh.c,v 1.75 2024/12/03 16:27:53 dtucker Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2021-2025 Roumen Petrov.  All rights reserved.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef ENABLE_KEX_DH

#ifndef USE_OPENSSL_PROVIDER
/* TODO: implement OpenSSL 4.0 API, as OpenSSL 3.* is quite nonfunctional */
# define OPENSSL_SUPPRESS_DEPRECATED
#endif

#include "includes.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/bn.h>

#include "dh.h"
#include "dh-crypto.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"


struct dhgroup {
	int size;
	BIGNUM *g;
	BIGNUM *p;
};


static DH *dh_new_group_fallback(int);
extern DH* dh_new_group(BIGNUM *, BIGNUM *);
extern DH* _dh_new_group_num(int);
extern DH* _choose_dh(int, int, int);

extern void dh_set_moduli_file(const char *);


static const char *moduli_filename = NULL;

void dh_set_moduli_file(const char *filename)
{
	moduli_filename = filename;
}

static inline const char*
get_moduli_filename(void)
{
	return moduli_filename != NULL ? moduli_filename : _PATH_DH_MODULI;
}


static int
parse_prime(int linenum, char *line, struct dhgroup *dhg)
{
	char *cp, *arg;
	char *strsize, *gen, *prime;
	const char *errstr = NULL;
	long long n;

	dhg->p = dhg->g = NULL;
	cp = line;
	if ((arg = strdelim(&cp)) == NULL)
		return 0;
	/* Ignore leading whitespace */
	if (*arg == '\0')
		arg = strdelim(&cp);
	if (!arg || !*arg || *arg == '#')
		return 0;

	/* time */
	if (cp == NULL || *arg == '\0')
		goto truncated;
	arg = strsep(&cp, " "); /* type */
	if (cp == NULL || *arg == '\0')
		goto truncated;
	/* Ensure this is a safe prime */
	n = strtonum(arg, 0, 5, &errstr);
	if (errstr != NULL || n != MODULI_TYPE_SAFE) {
		error("moduli:%d: type is not %d", linenum, MODULI_TYPE_SAFE);
		goto fail;
	}
	arg = strsep(&cp, " "); /* tests */
	if (cp == NULL || *arg == '\0')
		goto truncated;
	/* Ensure prime has been tested and is not composite */
	n = strtonum(arg, 0, 0x1f, &errstr);
	if (errstr != NULL ||
	    (n & MODULI_TESTS_COMPOSITE) || !(n & ~MODULI_TESTS_COMPOSITE)) {
		error("moduli:%d: invalid moduli tests flag", linenum);
		goto fail;
	}
	arg = strsep(&cp, " "); /* tries */
	if (cp == NULL || *arg == '\0')
		goto truncated;
	n = strtonum(arg, 0, 1<<30, &errstr);
	if (errstr != NULL || n == 0) {
		error("moduli:%d: invalid primality trial count", linenum);
		goto fail;
	}
	strsize = strsep(&cp, " "); /* size */
	if (cp == NULL || *strsize == '\0' ||
	    (dhg->size = (int)strtonum(strsize, 0, 64*1024, &errstr)) == 0 ||
	    errstr) {
		error("moduli:%d: invalid prime length", linenum);
		goto fail;
	}
	/* The whole group is one bit larger */
	dhg->size++;
	gen = strsep(&cp, " "); /* gen */
	if (cp == NULL || *gen == '\0')
		goto truncated;
	prime = strsep(&cp, " "); /* prime */
	if (cp != NULL || *prime == '\0') {
 truncated:
		error("moduli:%d: truncated", linenum);
		goto fail;
	}

	if ((dhg->g = BN_new()) == NULL ||
	    (dhg->p = BN_new()) == NULL) {
		error("parse_prime: BN_new failed");
		goto fail;
	}
	if (BN_hex2bn(&dhg->g, gen) == 0) {
		error("moduli:%d: could not parse generator value", linenum);
		goto fail;
	}
	if (BN_hex2bn(&dhg->p, prime) == 0) {
		error("moduli:%d: could not parse prime value", linenum);
		goto fail;
	}
	if (BN_num_bits(dhg->p) != dhg->size) {
		error("moduli:%d: prime has wrong size: actual %d listed %d",
		    linenum, BN_num_bits(dhg->p), dhg->size - 1);
		goto fail;
	}
	if (BN_cmp(dhg->g, BN_value_one()) <= 0) {
		error("moduli:%d: generator is invalid", linenum);
		goto fail;
	}
	return 1;

 fail:
	BN_clear_free(dhg->g);
	BN_clear_free(dhg->p);
	dhg->g = dhg->p = NULL;
	return 0;
}


DH *
_choose_dh(int min, int wantbits, int max)
{
	FILE *f;
	char *line = NULL;
	size_t linesize = 0;
	int best, bestcount, which, linenum;
	struct dhgroup dhg;

	if ((f = fopen(get_moduli_filename(), "r")) == NULL) {
		logit("WARNING: could not open %s (%s), using fixed modulus",
		    get_moduli_filename(), strerror(errno));
		return (dh_new_group_fallback(max));
	}

	linenum = 0;
	best = bestcount = 0;
	while (getline(&line, &linesize, f) != -1) {
		linenum++;
		if (!parse_prime(linenum, line, &dhg))
			continue;
		BN_clear_free(dhg.g);
		BN_clear_free(dhg.p);

		if (dhg.size > max || dhg.size < min)
			continue;

		if ((dhg.size > wantbits && dhg.size < best) ||
		    (dhg.size > best && best < wantbits)) {
			best = dhg.size;
			bestcount = 0;
		}
		if (dhg.size == best)
			bestcount++;
	}
	free(line);
	line = NULL;
	linesize = 0;
	rewind(f);

	if (bestcount == 0) {
		fclose(f);
		logit("WARNING: no suitable primes (size %d/%d/%d) in %s",
		    min, wantbits, max, get_moduli_filename());
		return NULL;
	}
	which = arc4random_uniform(bestcount);

	linenum = 0;
	bestcount = 0;
	while (getline(&line, &linesize, f) != -1) {
		linenum++;
		if (!parse_prime(linenum, line, &dhg))
			continue;
		if ((dhg.size > max || dhg.size < min) ||
		    dhg.size != best ||
		    bestcount++ != which) {
			BN_clear_free(dhg.g);
			BN_clear_free(dhg.p);
			continue;
		}
		break;
	}
	free(line);
	line = NULL;
	fclose(f);
	if (bestcount != which + 1) {
		logit("WARNING: selected prime disappeared in %s, giving up",
		    get_moduli_filename());
		return (dh_new_group_fallback(max));
	}

	return dh_new_group(dhg.p, dhg.g);
}


/*
 * This just returns the group, we still need to generate the exchange
 * value.
 */
DH*
dh_new_group(BIGNUM *modulus, BIGNUM *gen)
{
	DH *dh;

	dh = DH_new();
	if (dh == NULL) return NULL;

	if (!DH_set0_pqg(dh, modulus, NULL, gen)) {
		DH_free(dh);
		return NULL;
	}

	return dh;
}


/* diffie-hellman-groupN-sha1 */
#ifdef USE_BN_GET_RFC_PRIME	/*OpenSSL > 1.1*/
typedef BIGNUM* (*BN_get_rfc_prime)(BIGNUM *bn);
#endif

struct dh_group {
	int id;
	const char *generator;
#ifdef USE_BN_GET_RFC_PRIME
	BN_get_rfc_prime get_modulus;
#else
	const char *modulus;
#endif
} dh_group_list[] = {
/* rfc2409 "Second Oakley Group" (1024 bits) */
	{ 1, "2",
#ifdef USE_BN_GET_RFC_PRIME
	    BN_get_rfc2409_prime_1024
#else
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	    "FFFFFFFF" "FFFFFFFF"
#endif
	},
/* rfc3526 group 14 "2048-bit MODP Group" */
	{ 14, "2",
#ifdef USE_BN_GET_RFC_PRIME
	    BN_get_rfc3526_prime_2048
#else
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF"
#endif
	},
#ifdef USE_BN_GET_RFC_PRIME
/* rfc3526 group 15 "3072-bit MODP Group" */
	{ 15, "2", BN_get_rfc3526_prime_3072 },
#endif
/* rfc3526 group 16 "4096-bit MODP Group" */
	{ 16, "2",
#ifdef USE_BN_GET_RFC_PRIME
	    BN_get_rfc3526_prime_4096
#else
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AAAC42D" "AD33170D" "04507A33" "A85521AB" "DF1CBA64"
	    "ECFB8504" "58DBEF0A" "8AEA7157" "5D060C7D" "B3970F85" "A6E1E4C7"
	    "ABF5AE8C" "DB0933D7" "1E8C94E0" "4A25619D" "CEE3D226" "1AD2EE6B"
	    "F12FFA06" "D98A0864" "D8760273" "3EC86A64" "521F2B18" "177B200C"
	    "BBE11757" "7A615D6C" "770988C0" "BAD946E2" "08E24FA0" "74E5AB31"
	    "43DB5BFC" "E0FD108E" "4B82D120" "A9210801" "1A723C12" "A787E6D7"
	    "88719A10" "BDBA5B26" "99C32718" "6AF4E23C" "1A946834" "B6150BDA"
	    "2583E9CA" "2AD44CE8" "DBBBC2DB" "04DE8EF9" "2E8EFC14" "1FBECAA6"
	    "287C5947" "4E6BC05D" "99B2964F" "A090C3A2" "233BA186" "515BE7ED"
	    "1F612970" "CEE2D7AF" "B81BDD76" "2170481C" "D0069127" "D5B05AA9"
	    "93B4EA98" "8D8FDDC1" "86FFB7DC" "90A6C08F" "4DF435C9" "34063199"
	    "FFFFFFFF" "FFFFFFFF"
#endif
	},
#ifdef USE_BN_GET_RFC_PRIME
/* rfc3526 group 17 "6144-bit MODP Group" */
	{ 17, "2", BN_get_rfc3526_prime_6144 },
#endif
/* rfc3526 group 18 "8192-bit MODP Group" */
	{ 18, "2",
#ifdef USE_BN_GET_RFC_PRIME
	    BN_get_rfc3526_prime_8192
#else
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
	    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
	    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
	    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
	    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
	    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
	    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
	    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
	    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
	    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
	    "15728E5A" "8AAAC42D" "AD33170D" "04507A33" "A85521AB" "DF1CBA64"
	    "ECFB8504" "58DBEF0A" "8AEA7157" "5D060C7D" "B3970F85" "A6E1E4C7"
	    "ABF5AE8C" "DB0933D7" "1E8C94E0" "4A25619D" "CEE3D226" "1AD2EE6B"
	    "F12FFA06" "D98A0864" "D8760273" "3EC86A64" "521F2B18" "177B200C"
	    "BBE11757" "7A615D6C" "770988C0" "BAD946E2" "08E24FA0" "74E5AB31"
	    "43DB5BFC" "E0FD108E" "4B82D120" "A9210801" "1A723C12" "A787E6D7"
	    "88719A10" "BDBA5B26" "99C32718" "6AF4E23C" "1A946834" "B6150BDA"
	    "2583E9CA" "2AD44CE8" "DBBBC2DB" "04DE8EF9" "2E8EFC14" "1FBECAA6"
	    "287C5947" "4E6BC05D" "99B2964F" "A090C3A2" "233BA186" "515BE7ED"
	    "1F612970" "CEE2D7AF" "B81BDD76" "2170481C" "D0069127" "D5B05AA9"
	    "93B4EA98" "8D8FDDC1" "86FFB7DC" "90A6C08F" "4DF435C9" "34028492"
	    "36C3FAB4" "D27C7026" "C1D4DCB2" "602646DE" "C9751E76" "3DBA37BD"
	    "F8FF9406" "AD9E530E" "E5DB382F" "413001AE" "B06A53ED" "9027D831"
	    "179727B0" "865A8918" "DA3EDBEB" "CF9B14ED" "44CE6CBA" "CED4BB1B"
	    "DB7F1447" "E6CC254B" "33205151" "2BD7AF42" "6FB8F401" "378CD2BF"
	    "5983CA01" "C64B92EC" "F032EA15" "D1721D03" "F482D7CE" "6E74FEF6"
	    "D55E702F" "46980C82" "B5A84031" "900B1C9E" "59E7C97F" "BEC7E8F3"
	    "23A97A7E" "36CC88BE" "0F1D45B7" "FF585AC5" "4BD407B2" "2B4154AA"
	    "CC8F6D7E" "BF48E1D8" "14CC5ED2" "0F8037E0" "A79715EE" "F29BE328"
	    "06A1D58B" "B7C5DA76" "F550AA3D" "8A1FBFF0" "EB19CCB1" "A313D55C"
	    "DA56C9EC" "2EF29632" "387FE8D7" "6E3C0468" "043E8F66" "3F4860EE"
	    "12BF2D5B" "0B7474D6" "E694F91E" "6DBE1159" "74A3926F" "12FEE5E4"
	    "38777CB6" "A932DF8C" "D8BEC4D0" "73B931BA" "3BC832B6" "8D9DD300"
	    "741FA7BF" "8AFC47ED" "2576F693" "6BA42466" "3AAB639C" "5AE4F568"
	    "3423B474" "2BF1C978" "238F16CB" "E39D652D" "E3FDB8BE" "FC848AD9"
	    "22222E04" "A4037C07" "13EB57A8" "1A23F0C7" "3473FC64" "6CEA306B"
	    "4BCBC886" "2F8385DD" "FA9D4B7F" "A2C087E8" "79683303" "ED5BDD3A"
	    "062B3CF5" "B3A278A6" "6D2A13F8" "3F44F82D" "DF310EE0" "74AB6A36"
	    "4597E899" "A0255DC1" "64F31CC5" "0846851D" "F9AB4819" "5DED7EA1"
	    "B1D510BD" "7EE74D73" "FAF36BC3" "1ECFA268" "359046F4" "EB879F92"
	    "4009438B" "481C6CD7" "889A002E" "D5EE382B" "C9190DA6" "FC026E47"
	    "9558E447" "5677E9AA" "9E3050E2" "765694DF" "C81F56E8" "80B96E71"
	    "60C980DD" "98EDD3DF" "FFFFFFFF" "FFFFFFFF"
#endif
	}
};

static inline DH*
_dh_new_group_def(struct dh_group *def) {
	BIGNUM *p, *g;

#ifdef USE_BN_GET_RFC_PRIME
	p = def->get_modulus(NULL);
	if (p == NULL) return NULL;
#else
	p = NULL;
	if (BN_hex2bn(&p, def->modulus) == 0)
		return NULL;
#endif
	g = NULL;
	if (BN_hex2bn(&g, def->generator) == 0) {
		BN_clear_free(p);
		return NULL;
	}

	return dh_new_group(p, g);
}

DH*
_dh_new_group_num(int num) {
	size_t k, len = sizeof(dh_group_list) / sizeof(*dh_group_list);
	struct dh_group *p;

	for (k = 0, p = dh_group_list; k < len; k++, p++) {
		if (num == dh_group_list[k].id)
			return _dh_new_group_def(p);
	}
	return NULL;
}

/* Select fallback group used by DH-GEX if moduli file cannot be read. */
DH *
dh_new_group_fallback(int max)
{
	debug3_f("requested max size %d", max);
	if (max < 3072) {
		debug3("using 2k bit group 14");
		return _dh_new_group_num(14);
	} else if (max < 6144) {
		debug3("using 4k bit group 16");
		return _dh_new_group_num(16);
	}
	debug3("using 8k bit group 18");
	return _dh_new_group_num(18);
}
#else /*ndef ENABLE_KEX_DH*/

typedef int dh_empty_translation_unit;

#endif /*ndef ENABLE_KEX_DH*/
