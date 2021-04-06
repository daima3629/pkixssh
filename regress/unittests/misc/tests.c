/* 	$OpenBSD: tests.c,v 1.4 2021/01/15 02:58:11 dtucker Exp $ */
/*
 * Regress test for misc helper functions.
 *
 * Placed in the public domain.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "log.h"
#include "misc.h"

void test_parse(void);

void
tests(void)
{
	int parseerr;
	char *ret;

	test_parse();

	TEST_START("dollar_expand");
	if (setenv("FOO", "bar", 1) != 0)
		abort();
	if (setenv("BAR", "baz", 1) != 0)
		abort();
	if (unsetenv("BAZ") != 0)
		abort();
#define ASSERT_DOLLAR_EQ(x, y) do { \
	char *str = dollar_expand(NULL, (x)); \
	ASSERT_STRING_EQ(str, (y)); \
	free(str); \
} while(0)
	ASSERT_DOLLAR_EQ("${FOO}", "bar");
	ASSERT_DOLLAR_EQ(" ${FOO}", " bar");
	ASSERT_DOLLAR_EQ("${FOO} ", "bar ");
	ASSERT_DOLLAR_EQ(" ${FOO} ", " bar ");
	ASSERT_DOLLAR_EQ("${FOO}${BAR}", "barbaz");
	ASSERT_DOLLAR_EQ(" ${FOO} ${BAR}", " bar baz");
	ASSERT_DOLLAR_EQ("${FOO}${BAR} ", "barbaz ");
	ASSERT_DOLLAR_EQ(" ${FOO} ${BAR} ", " bar baz ");
	ASSERT_DOLLAR_EQ("$", "$");
	ASSERT_DOLLAR_EQ(" $", " $");
	ASSERT_DOLLAR_EQ("$ ", "$ ");

	/* suppress error messages for error handing tests */
	log_init("test_misc", SYSLOG_LEVEL_QUIET, SYSLOG_FACILITY_AUTH, 1);
	/* error checking, non existent variable */
	ret = dollar_expand(&parseerr, "a${BAZ}");
	ASSERT_PTR_EQ(ret, NULL); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "${BAZ}b");
	ASSERT_PTR_EQ(ret, NULL); ASSERT_INT_EQ(parseerr, 0);
	ret = dollar_expand(&parseerr, "a${BAZ}b");
	ASSERT_PTR_EQ(ret, NULL); ASSERT_INT_EQ(parseerr, 0);
	/* invalid format */
	ret = dollar_expand(&parseerr, "${");
	ASSERT_PTR_EQ(ret, NULL); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${F");
	ASSERT_PTR_EQ(ret, NULL); ASSERT_INT_EQ(parseerr, 1);
	ret = dollar_expand(&parseerr, "${FO");
	ASSERT_PTR_EQ(ret, NULL); ASSERT_INT_EQ(parseerr, 1);
	/* empty variable name */
	ret = dollar_expand(&parseerr, "${}");
	ASSERT_PTR_EQ(ret, NULL); ASSERT_INT_EQ(parseerr, 1);
	/* restore loglevel to default */
	log_init("test_misc", SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_AUTH, 1);
	TEST_DONE();

	TEST_START("percent_expand");
	ret = percent_expand("%%", "%h", "foo", NULL);
	ASSERT_STRING_EQ(ret, "%"); free(ret);
	ret = percent_expand("%h", "h", "foo", NULL);
	ASSERT_STRING_EQ(ret, "foo"); free(ret);
	ret = percent_expand("%h ", "h", "foo", NULL);
	ASSERT_STRING_EQ(ret, "foo "); free(ret);
	ret = percent_expand(" %h", "h", "foo", NULL);
	ASSERT_STRING_EQ(ret, " foo"); free(ret);
	ret = percent_expand(" %h ", "h", "foo", NULL);
	ASSERT_STRING_EQ(ret, " foo "); free(ret);
	ret = percent_expand(" %a%b ", "a", "foo", "b", "bar", NULL);
	ASSERT_STRING_EQ(ret, " foobar "); free(ret);
	TEST_DONE();

	TEST_START("percent_dollar_expand");
	ret = percent_dollar_expand("%h${FOO}", "h", "foo", NULL);
	ASSERT_STRING_EQ(ret, "foobar"); free(ret);
	TEST_DONE();
}
