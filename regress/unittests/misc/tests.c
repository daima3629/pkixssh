/* 	$OpenBSD: tests.c,v 1.12 2025/09/02 11:04:58 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#include "../test_helper/test_helper.h"

#include <stdio.h>

void test_parse(void);
void test_expand(void);
void test_argv(void);
void test_strdelim(void);
void test_hpdelim(void);
void test_ptimeout(void);
void test_xextendf(void);

void
tests(void)
{
	test_parse();
	test_expand();
	test_argv();
	if (getenv("UNITTEST_MISC_STRDELIM") != NULL)
		test_strdelim();
	test_hpdelim();
	test_ptimeout();
	test_xextendf();
}

void
benchmarks(void)
{
	printf("no benchmarks\n");
}
