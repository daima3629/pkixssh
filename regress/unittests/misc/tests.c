/* 	$OpenBSD: tests.c,v 1.4 2021/01/15 02:58:11 dtucker Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#include "../test_helper/test_helper.h"

void test_parse(void);
void test_expand(void);

void
tests(void)
{
	test_parse();
	test_expand();
}
