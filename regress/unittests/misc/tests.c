/* 	$OpenBSD: tests.c,v 1.6 2021/03/19 04:23:50 djm Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#include "../test_helper/test_helper.h"

void test_parse(void);
void test_expand(void);
void test_argv(void);

void
tests(void)
{
	test_parse();
	test_expand();
	test_argv();
}
