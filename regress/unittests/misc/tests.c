/* 	$OpenBSD: tests.c,v 1.7 2021/05/21 03:48:07 djm Exp $ */
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

void
tests(void)
{
	test_parse();
	test_expand();
	test_argv();
	if (getenv("UNITTEST_MISC_STRDELIM") != NULL)
		test_strdelim();
}
