/* 	$OpenBSD: tests.c,v 1.2 2023/02/02 12:12:52 djm Exp $ */
/*
 * Placed in the public domain
 */

#include "../test_helper/test_helper.h"
#include "ssh_api.h"

void kex_tests(void);
void kex_proposal(void);

void
tests(void)
{
	ssh_crypto_init();

	kex_tests();
	kex_proposal();

	ssh_crypto_fini();
}
