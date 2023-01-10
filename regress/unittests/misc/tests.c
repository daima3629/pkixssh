/* 	$OpenBSD: tests.c,v 1.10 2023/01/06 02:59:50 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#include "../test_helper/test_helper.h"

void test_parse(void);
void test_expand(void);
void test_argv(void);
void test_strdelim(void);
void test_hpdelim(void);
void test_ptimeout(void);

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
}
