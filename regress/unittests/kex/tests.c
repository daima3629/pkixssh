/* 	$OpenBSD: tests.c,v 1.3 2023/03/06 12:15:47 dtucker Exp $ */
/*
 * Placed in the public domain
 */

#include "../test_helper/test_helper.h"
#include "ssh_api.h"

extern void dh_set_moduli_file(const char *);

void kex_tests(void);
void kex_proposal_tests(void);
void kex_proposal_populate_tests(void);

void
tests(void)
{
	ssh_crypto_init();

{	char *name = getenv("TEST_SSH_MODULI_FILE");
	if (name != NULL)
		dh_set_moduli_file(name);
}
	kex_tests();
	kex_proposal_tests();
	kex_proposal_populate_tests();

	ssh_crypto_fini();
}
