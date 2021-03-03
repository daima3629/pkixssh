/* 	$OpenBSD: tests.c,v 1.3 2021/01/18 11:43:34 dtucker Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "../test_helper/test_helper.h"

#include "misc.h"

void
tests(void)
{
	char buf[1024];

	TEST_START("conversion_convtime");
	ASSERT_LONG_EQ(convtime("0"), 0);
	ASSERT_LONG_EQ(convtime("1"), 1);
	ASSERT_LONG_EQ(convtime("1S"), 1);
	/* from the examples in the comment above the function */
	ASSERT_LONG_EQ(convtime("90m"), 5400);
	ASSERT_LONG_EQ(convtime("1h30m"), 5400);
	ASSERT_LONG_EQ(convtime("2d"), 172800);
	ASSERT_LONG_EQ(convtime("1w"), 604800);

	/* negative time is not allowed */
	ASSERT_LONG_EQ(convtime("-7"), -1);
	ASSERT_LONG_EQ(convtime("-9d"), -1);

	/* reverse description / based on misc */
	ASSERT_LONG_EQ(convtime("1s1h"), 3601);
	ASSERT_LONG_EQ(convtime("4m3h2d1w5"), 788645);
	ASSERT_LONG_EQ(convtime("5s4m3h2d1w"), 788645);

	/* overflow */
	snprintf(buf, sizeof buf, "%llu", (unsigned long long)LONG_MAX);
	ASSERT_LONG_EQ(convtime(buf), -1);
	snprintf(buf, sizeof buf, "%llu", (unsigned long long)LONG_MAX + 1);
	ASSERT_LONG_EQ(convtime(buf), -1);

	/* overflow with multiplier */
	snprintf(buf, sizeof buf, "%lluM", (unsigned long long)LONG_MAX/60 + 1);
	ASSERT_LONG_EQ(convtime(buf), -1);
	ASSERT_LONG_EQ(convtime("1000000000000000000000w"), -1);
	TEST_DONE();

	TEST_START("misc_convtime"); /* moved here;) */
	ASSERT_LONG_EQ(convtime("1"), 1);
	ASSERT_LONG_EQ(convtime("2s"), 2);
	ASSERT_LONG_EQ(convtime("3m"), 180);
	ASSERT_LONG_EQ(convtime("1m30"), 90);
	ASSERT_LONG_EQ(convtime("1m30s"), 90);
	ASSERT_LONG_EQ(convtime("1h1s"), 3601);
	ASSERT_LONG_EQ(convtime("1h30m"), 90 * 60);
	ASSERT_LONG_EQ(convtime("1d"), 24 * 60 * 60);
	ASSERT_LONG_EQ(convtime("1w"), 7 * 24 * 60 * 60);
	ASSERT_LONG_EQ(convtime("1w2d3h4m5"), 788645);
	ASSERT_LONG_EQ(convtime("1w2d3h4m5s"), 788645);
	/* any negative number or error returns -1 */
	ASSERT_LONG_EQ(convtime("-1"),  -1);
	ASSERT_LONG_EQ(convtime(""),  -1);
	ASSERT_LONG_EQ(convtime("trout"),  -1);
	ASSERT_LONG_EQ(convtime("-77"),  -1);
	TEST_DONE();

	TEST_START("conversion_fmttime");
{	char *res;
	res = fmttime(13);
	ASSERT_STRING_EQ(res, "13s");
	free(res);
	res = fmttime((12)*60+13);
	ASSERT_STRING_EQ(res, "12m13s");
	free(res);
	res = fmttime(((11)*60+12)*60+13);
	ASSERT_STRING_EQ(res, "11h12m13s");
	free(res);
	res = fmttime((((5)*24+11)*60+12)*60+13);
	ASSERT_STRING_EQ(res, "5d11h12m");
	free(res);
	res = fmttime(((((4)*7+5)*24+11)*60+12)*60+13);
	ASSERT_STRING_EQ(res, "4w5d11h");
	free(res);
}
	TEST_DONE();
}
