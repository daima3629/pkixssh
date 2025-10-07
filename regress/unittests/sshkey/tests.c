/* 	$OpenBSD: tests.c,v 1.2 2025/04/15 04:00:42 djm Exp $ */
/*
 * Regress test for sshbuf.h buffer API
 *
 * Placed in the public domain
 */

#include "../test_helper/test_helper.h"

#include <stdio.h>

#include "ssh_api.h"

void sshkey_tests(void);
void sshkey_file_tests(void);
void sshkey_fuzz_tests(void);
void sshkey_benchmarks(void);

void
tests(void)
{
	ssh_crypto_init();

	sshkey_tests();
	sshkey_file_tests();
	sshkey_fuzz_tests();

	ssh_crypto_fini();
}

void
benchmarks(void)
{
	printf("\n");
	sshkey_benchmarks();
}
