/* 	$OpenBSD: test_file.c,v 1.11 2024/01/11 01:45:58 djm Exp $ */
/*
 * Regress test for sshkey.h key management API
 *
 * Placed in the public domain
 */

#define OPENSSL_SUPPRESS_DEPRECATED	/* TODO implement OpenSSL 3.1 API */

#include "../test_helper/test_helper.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_OPENSSL
#include "evp-compat.h"
#endif /* WITH_OPENSSL */

#include "ssherr.h"
#include "authfile.h"
#include "sshkey.h"
#include "sshbuf.h"
#include "digest.h"

#include "common.h"


/* TODO: rewrite direct RSA tests */
#ifndef HAVE_RSA_GET0_KEY
/* opaque RSA key structure */
static inline void
RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d) {
	if (n != NULL) *n = rsa->n;
	if (e != NULL) *e = rsa->e;
	if (d != NULL) *d = rsa->d;
}

static inline void
RSA_get0_factors(const RSA *rsa, const BIGNUM **p, const BIGNUM **q) {
	if (p != NULL) *p = rsa->p;
	if (q != NULL) *q = rsa->q;
}
#endif /*ndef HAVE_RSA_GET0_KEY*/

#ifdef WITH_DSA
/* TODO: rewrite direct DSA tests */
#ifndef HAVE_DSA_GET0_KEY
/* opaque DSA key structure */
static inline void
DSA_get0_key(const DSA *dsa, const BIGNUM **pub_key, const BIGNUM **priv_key) {
	if (pub_key  != NULL) *pub_key  = dsa->pub_key;
	if (priv_key != NULL) *priv_key = dsa->priv_key;
}

static inline void
DSA_get0_pqg(const DSA *dsa, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g) {
	if (p != NULL) *p = dsa->p;
	if (q != NULL) *q = dsa->q;
	if (g != NULL) *g = dsa->g;
}
#endif /*ndef HAVE_DSA_GET0_KEY*/
#endif /*def WITH_DSA*/


void sshkey_file_tests(void);

void
sshkey_file_tests(void)
{
	struct sshkey *k1, *k2;
	struct sshbuf *buf, *pw;
#ifdef WITH_OPENSSL
	BIGNUM *a, *b, *c;
#endif
	char *cp;

	TEST_START("load passphrase");
	pw = load_text_file("pw");
	TEST_DONE();

#ifdef WITH_OPENSSL
	TEST_START("parse RSA from private");
	buf = load_file("rsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, NULL);
	a = load_bignum("rsa_1.param.n");
	b = load_bignum("rsa_1.param.p");
	c = load_bignum("rsa_1.param.q");
{
	const BIGNUM *n = NULL, *p = NULL, *q = NULL;
	RSA *rsa = EVP_PKEY_get1_RSA(k1->pk);

	ASSERT_PTR_NE(rsa, NULL);
	RSA_get0_key(rsa, &n, NULL, NULL);
	RSA_get0_factors(rsa, &p, &q);

	ASSERT_BIGNUM_EQ(n, a);
	ASSERT_BIGNUM_EQ(p, b);
	ASSERT_BIGNUM_EQ(q, c);

	RSA_free(rsa);
}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_DONE();

	TEST_START("parse RSA from private w/ passphrase");
	buf = load_file("rsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (const char *)sshbuf_ptr(pw), &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse RSA from new-format");
	buf = load_file("rsa_n");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse RSA from new-format w/ passphrase");
	buf = load_file("rsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (const char *)sshbuf_ptr(pw), &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("rsa_1.pub"), &k2,
	    NULL), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load RSA cert with SHA1 signature");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1_sha1"), &k2), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(k2->type, KEY_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "ssh-rsa");
	sshkey_free(k2);
	TEST_DONE();

#ifdef HAVE_EVP_SHA256
	TEST_START("load RSA cert with SHA512 signature");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1_sha512"), &k2), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(k2->type, KEY_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	ASSERT_STRING_EQ(k2->cert->signature_type, "rsa-sha2-512");
	sshkey_free(k2);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

	TEST_START("load RSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("rsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(k2->type, KEY_RSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

#ifdef HAVE_EVP_SHA256
	TEST_START("RSA key hex fingerprint");
	buf = load_text_file("rsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

#ifdef HAVE_EVP_SHA256
	TEST_START("RSA cert hex fingerprint");
	buf = load_text_file("rsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	sshkey_free(k2);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

	TEST_START("RSA key bubblebabble fingerprint");
	buf = load_text_file("rsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	TEST_DONE();

	sshkey_free(k1);

#ifdef WITH_DSA
	TEST_START("parse DSA from private");
	buf = load_file("dsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, NULL);
	a = load_bignum("dsa_1.param.g");
	b = load_bignum("dsa_1.param.priv");
	c = load_bignum("dsa_1.param.pub");
{
	const BIGNUM *g = NULL, *pub_key = NULL, *priv_key = NULL;
	DSA *dsa = EVP_PKEY_get1_DSA(k1->pk);

	ASSERT_PTR_NE(dsa, NULL);
	DSA_get0_pqg(dsa, NULL, NULL, &g);
	DSA_get0_key(dsa, &pub_key, &priv_key);

	ASSERT_BIGNUM_EQ(g, a);
	ASSERT_BIGNUM_EQ(priv_key, b);
	ASSERT_BIGNUM_EQ(pub_key, c);

	DSA_free(dsa);
}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_DONE();

	TEST_START("parse DSA from private w/ passphrase");
	buf = load_file("dsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (const char *)sshbuf_ptr(pw), &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse DSA from new-format");
	buf = load_file("dsa_n");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse DSA from new-format w/ passphrase");
	buf = load_file("dsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (const char *)sshbuf_ptr(pw), &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load DSA from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("dsa_1.pub"), &k2,
	    NULL), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load DSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("dsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(k2->type, KEY_DSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

#ifdef HAVE_EVP_SHA256
	TEST_START("DSA key hex fingerprint");
	buf = load_text_file("dsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

#ifdef HAVE_EVP_SHA256
	TEST_START("DSA cert hex fingerprint");
	buf = load_text_file("dsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	sshkey_free(k2);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

	TEST_START("DSA key bubblebabble fingerprint");
	buf = load_text_file("dsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	TEST_DONE();

	sshkey_free(k1);
#endif /*def WITH_DSA*/

#ifdef OPENSSL_HAS_ECC
	TEST_START("parse ECDSA from private");
	buf = load_file("ecdsa_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, NULL);
	buf = load_text_file("ecdsa_1.param.curve");
	ASSERT_STRING_EQ((const char *)sshbuf_ptr(buf),
	    OBJ_nid2sn(k1->ecdsa_nid));
	sshbuf_free(buf);
	a = load_bignum("ecdsa_1.param.priv");
	b = load_bignum("ecdsa_1.param.pub");
{
	const EC_GROUP *ec_group;
	const EC_POINT *ec_pub;
	const BIGNUM *ec_priv;
	EC_KEY *ec = EVP_PKEY_get1_EC_KEY(k1->pk);

	ASSERT_PTR_NE(ec, NULL);
	ec_group = EC_KEY_get0_group(ec);
	ec_pub = EC_KEY_get0_public_key(ec);
	ec_priv = EC_KEY_get0_private_key(ec);

	c = EC_POINT_point2bn(ec_group, ec_pub, POINT_CONVERSION_UNCOMPRESSED, NULL, NULL);
	ASSERT_PTR_NE(c, NULL);
	ASSERT_BIGNUM_EQ(ec_priv, a);
	ASSERT_BIGNUM_EQ(b, c);
	EC_KEY_free(ec);
}
	BN_free(a);
	BN_free(b);
	BN_free(c);
	TEST_DONE();

	TEST_START("parse ECDSA from private w/ passphrase");
	buf = load_file("ecdsa_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (const char *)sshbuf_ptr(pw), &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse ECDSA from new-format");
	buf = load_file("ecdsa_n");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("parse ECDSA from new-format w/ passphrase");
	buf = load_file("ecdsa_n_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (const char *)sshbuf_ptr(pw), &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ecdsa_1.pub"), &k2,
	    NULL), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load ECDSA cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("ecdsa_1"), &k2), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(k2->type, KEY_ECDSA_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

#ifdef HAVE_EVP_SHA256
	TEST_START("ECDSA key hex fingerprint");
	buf = load_text_file("ecdsa_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

#ifdef HAVE_EVP_SHA256
	TEST_START("ECDSA cert hex fingerprint");
	buf = load_text_file("ecdsa_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	sshkey_free(k2);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

	TEST_START("ECDSA key bubblebabble fingerprint");
	buf = load_text_file("ecdsa_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	TEST_DONE();

	sshkey_free(k1);
#endif /* OPENSSL_HAS_ECC */
#endif /* WITH_OPENSSL */

	TEST_START("parse Ed25519 from private");
	buf = load_file("ed25519_1");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf, "", &k1, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k1, NULL);
	ASSERT_INT_EQ(k1->type, KEY_ED25519);
	/* XXX check key contents */
	TEST_DONE();

	TEST_START("parse Ed25519 from private w/ passphrase");
	buf = load_file("ed25519_1_pw");
	ASSERT_INT_EQ(sshkey_parse_private_fileblob(buf,
	    (const char *)sshbuf_ptr(pw), &k2, NULL), 0);
	sshbuf_free(buf);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519 from public");
	ASSERT_INT_EQ(sshkey_load_public(test_data_file("ed25519_1.pub"), &k2,
	    NULL), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 1);
	sshkey_free(k2);
	TEST_DONE();

	TEST_START("load Ed25519 cert");
	ASSERT_INT_EQ(sshkey_load_cert(test_data_file("ed25519_1"), &k2), 0);
	ASSERT_PTR_NE(k2, NULL);
	ASSERT_INT_EQ(k2->type, KEY_ED25519_CERT);
	ASSERT_INT_EQ(sshkey_equal(k1, k2), 0);
	ASSERT_INT_EQ(sshkey_equal_public(k1, k2), 1);
	TEST_DONE();

#ifdef HAVE_EVP_SHA256
	TEST_START("Ed25519 key hex fingerprint");
	buf = load_text_file("ed25519_1.fp");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

#ifdef HAVE_EVP_SHA256
	TEST_START("Ed25519 cert hex fingerprint");
	buf = load_text_file("ed25519_1-cert.fp");
	cp = sshkey_fingerprint(k2, SSH_DIGEST_SHA256, SSH_FP_BASE64);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	sshkey_free(k2);
	TEST_DONE();
#endif /*def HAVE_EVP_SHA256*/

	TEST_START("Ed25519 key bubblebabble fingerprint");
	buf = load_text_file("ed25519_1.fp.bb");
	cp = sshkey_fingerprint(k1, SSH_DIGEST_SHA1, SSH_FP_BUBBLEBABBLE);
	ASSERT_PTR_NE(cp, NULL);
	ASSERT_STRING_EQ(cp, (const char *)sshbuf_ptr(buf));
	sshbuf_free(buf);
	free(cp);
	TEST_DONE();

	sshkey_free(k1);

	sshbuf_free(pw);

}
