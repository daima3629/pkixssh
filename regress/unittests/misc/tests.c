/* 	$OpenBSD: tests.c,v 1.9 2022/02/04 07:53:44 dtucker Exp $ */
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

void
tests(void)
{
	test_parse();
	test_expand();
	test_argv();
	if (getenv("UNITTEST_MISC_STRDELIM") != NULL)
		test_strdelim();
	test_hpdelim();
}
