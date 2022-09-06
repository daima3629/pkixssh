/* 	$OpenBSD: tests.c,v 1.4 2021/12/14 21:25:27 deraadt Exp $ */
/*
 * Regress test for conversions
 *
 * Placed in the public domain
 */

#include "../test_helper/test_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "ssherr.h"

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

{	uint64_t t;
	/* XXX timezones/DST make verification of this tricky */
	/* XXX maybe setenv TZ and tzset() to make it unambiguous? */
	TEST_START("misc_parse_absolute_time");
	ASSERT_INT_EQ(parse_absolute_time("20000101", &t), 0);
	ASSERT_INT_EQ(parse_absolute_time("200001011223", &t), 0);
	ASSERT_INT_EQ(parse_absolute_time("20000101122345", &t), 0);

	/* forced UTC TZ */
	ASSERT_INT_EQ(parse_absolute_time("20000101Z", &t), 0);
	ASSERT_U64_EQ(t, 946684800);
	ASSERT_INT_EQ(parse_absolute_time("200001011223Z", &t), 0);
	ASSERT_U64_EQ(t, 946729380);
	ASSERT_INT_EQ(parse_absolute_time("20000101122345Z", &t), 0);
	ASSERT_U64_EQ(t, 946729425);
	ASSERT_INT_EQ(parse_absolute_time("20000101UTC", &t), 0);
	ASSERT_U64_EQ(t, 946684800);
	ASSERT_INT_EQ(parse_absolute_time("200001011223UTC", &t), 0);
	ASSERT_U64_EQ(t, 946729380);
	ASSERT_INT_EQ(parse_absolute_time("20000101122345UTC", &t), 0);
	ASSERT_U64_EQ(t, 946729425);

	/* Bad month */
	ASSERT_INT_EQ(parse_absolute_time("20001301", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("20000001", &t),
	    SSH_ERR_INVALID_FORMAT);
	/* Incomplete */
	ASSERT_INT_EQ(parse_absolute_time("2", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("2000", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("20000", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("200001", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("2000010", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("200001010", &t),
	    SSH_ERR_INVALID_FORMAT);
	/* Bad day, hour, minute, second */
	ASSERT_INT_EQ(parse_absolute_time("20000199", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("200001019900", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("200001010099", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("20000101000099", &t),
	    SSH_ERR_INVALID_FORMAT);
	/* Invalid TZ specifier */
	ASSERT_INT_EQ(parse_absolute_time("20000101ZZ", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("20000101PDT", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("20000101U", &t),
	    SSH_ERR_INVALID_FORMAT);
	ASSERT_INT_EQ(parse_absolute_time("20000101UTCUTC", &t),
	    SSH_ERR_INVALID_FORMAT);
}
	TEST_DONE();
}
