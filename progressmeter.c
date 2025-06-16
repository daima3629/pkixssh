/* $OpenBSD: progressmeter.c,v 1.56 2025/06/11 13:27:11 dtucker Exp $ */
/*
 * Copyright (c) 2003 Nils Nordman.  All rights reserved.
 * Copyright (c) 2019-2023 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "progressmeter.h"
#include "atomicio.h"
#include "misc.h"
#include "utf8.h"

#define DEFAULT_WINSIZE 80
#define MAX_WINSIZE 512
#define UPDATE_INTERVAL 1	/* update the progress meter every second */
#define STALL_TIME 5		/* we're stalled after this many seconds */

/* Progress format: {name+space(1)}[info(34)].
 * Do not write to last column!
 *
 * Progress information part, items separated by space:
 *  percent  : format "nnn% ", i.e. 4+1 characters
 *  amount   : format "nnnnuu ", i.e. 6+1 characters
 *  bandwidth: format "nnn.nuu/s ", i.e. 9+1 characters
 *  ETA      : various formats, 12 characters
 * , i.e. 34 ascii characters.
 *
 * NOTE: length counts trailing '\0'.
 */
#define PROGRESS_INFO_LEN	(34+1)

/* determines whether we can output to the terminal */
static int can_output(void);

/* window resizing */
static void sig_winch(int);
static void setscreensize(void);

/* signal handler for updating the progress meter */
static void sig_alarm(int);

static double start;		/* start progress */
static double last_update;	/* last progress update */
static const char *file;	/* name of the file being transferred */
static off_t start_pos;		/* initial position of transfer */
static off_t end_pos;		/* ending position of transfer */
static off_t cur_pos;		/* transfer position as of last refresh */
static volatile off_t *counter;	/* progress counter */
static long stalled;		/* how long we have been stalled */
static int bytes_per_second;	/* current speed in bytes per second */
static int win_size;		/* terminal window size */
static volatile sig_atomic_t win_resized; /* for window resizing */
static volatile sig_atomic_t alarm_fired;

/* units for format_size */
static const char unit[] = " KMGT";

static int
can_output(void)
{
	return (getpgrp() == tcgetpgrp(STDOUT_FILENO));
}

static int
format_rate(char *buf, int size, off_t bytes)
{
	int i;

	bytes *= 100;
	for (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	/* Display at least KB, even when rate is low or zero. */
	if (i == 0) {
		i++;
		bytes = (bytes + 512) / 1024;
	}
	return snprintf(buf, size, "%3lld.%1lld%cB/s ",
	    (long long) (bytes + 5) / 100,
	    (long long) (bytes + 5) / 10 % 10,
	    unit[i]);
}

static int
format_size(char *buf, int size, off_t bytes)
{
	int i;

	for (i = 0; bytes >= 10000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	return snprintf(buf, size, "%4lld%c%c ",
	    (long long) bytes,
	    unit[i], i > 0 ? 'B' : ' ');
}

void
refresh_progress_meter(int force_update)
{
	char buf[4 * MAX_WINSIZE + 1];
	off_t transferred;
	double elapsed, now;
	off_t bytes_left;
	int cur_speed;
	int len;

	if (file == NULL) return;
	if ((!force_update && !alarm_fired && !win_resized) || !can_output())
		return;
	alarm_fired = 0;

	if (win_resized) {
		setscreensize();
		win_resized = 0;
	}

	transferred = *counter - (cur_pos ? cur_pos : start_pos);
	cur_pos = *counter;
	now = monotime_double();
	bytes_left = end_pos - cur_pos;

	if (bytes_left > 0)
		elapsed = now - last_update;
	else {
		elapsed = now - start;
		/* Calculate true total speed when done */
		transferred = end_pos - start_pos;
		bytes_per_second = 0;
	}

	/* calculate speed */
	if (elapsed != 0)
		cur_speed = (transferred / elapsed);
	else
		cur_speed = transferred;

#define AGE_FACTOR 0.9
	if (bytes_per_second != 0) {
		bytes_per_second = (bytes_per_second * AGE_FACTOR) +
		    (cur_speed * (1.0 - AGE_FACTOR));
	} else
		bytes_per_second = cur_speed;

	last_update = now;

	/* Skip output if cannot display the completion percentage at least.
	 * NOTE: win_size counts trailing '\0'!
	 */
	if (win_size < 6) return;

	buf[0] = '\r';
	buf[1] = '\0';

	/* filename */
	if (win_size > (PROGRESS_INFO_LEN + 2)) {
		int file_len = win_size - (PROGRESS_INFO_LEN + 2);
	#if 0
		/* TODO: lost space character from format! */
		snmprintf(buf+1, sizeof(buf)-1, &file_len, "%-*s ",
		    file_len, file);
	#else
		snmprintf(buf+1, sizeof(buf)-1, &file_len, "%-*s",
		    file_len, file);
		/* work-around */
		strlcat(buf+1, " ", sizeof(buf)-1);
	#endif
	}

{	int ilen;
	char *ibuf;

	len = strlen(buf);
	ilen = len > 1 ? PROGRESS_INFO_LEN : (win_size - 1);
	ibuf = buf + len;

	/* percent of transfer done */
{	int percent;
	if (end_pos == 0 || cur_pos == end_pos)
		percent = 100;
	else
		percent = ((float)cur_pos / end_pos) * 100;
	len = snprintf(ibuf, ilen, "%3d%% ", percent);
	ilen -= len;
	if (ilen < 1) goto done;
	ibuf += len;
}

	/* amount transferred */
	len = format_size(ibuf, ilen, cur_pos);
	ilen -= len;
	if (ilen < 1) goto done;
	ibuf += len;

	/* bandwidth usage */
	len = format_rate(ibuf, ilen, (off_t)bytes_per_second);
	ilen -= len;
	if (ilen < 1) goto done;
	ibuf += len;

	/* ETA */
	if (!transferred)
		stalled += elapsed;
	else
		stalled = 0;

	if (stalled >= STALL_TIME)
		strlcat(ibuf, "- stalled - ", ilen);
	else if (bytes_per_second == 0 && bytes_left)
		strlcat(ibuf, "  --:-- ETA ", ilen);
	else {
		int hours, minutes, seconds;

		if (bytes_left > 0)
			seconds = bytes_left / bytes_per_second;
		else
			seconds = elapsed;

		hours = seconds / 3600;
		seconds -= hours * 3600;
		minutes = seconds / 60;
		seconds -= minutes * 60;

		/* formats:
		 *  "nn:nn:nn", i.e. 8 charactes
		 *  "n:nn:nn", i.e. 7 charactes
		 *  "  nn:nn", i.e. 7 charactes
		 */
		if (hours != 0)
			len = snprintf(ibuf, ilen,
			    "%d:%02d:%02d", hours, minutes, seconds);
		else
			len = snprintf(ibuf, ilen,
			    "  %02d:%02d", minutes, seconds);
		if (len >= ilen) goto done;

		/* format 4 charactes */
		if (bytes_left > 0)
			strlcat(ibuf, " ETA", ilen);
		else
			strlcat(ibuf, "    ", ilen);

		/* cleanup last column */
		if (len < 8)
			strlcat(ibuf, " ", ilen);
	}
}
done:
	len = strlen(buf);
	atomicio(vwrite, STDOUT_FILENO, buf, len);
}

static void
sig_alarm(int ignore)
{
	UNUSED(ignore);
	alarm_fired = 1;
	alarm(UPDATE_INTERVAL);
}

void
start_progress_meter(const char *f, off_t filesize, off_t *ctr)
{
	start = last_update = monotime_double();
	file = f;
	start_pos = *ctr;
	end_pos = filesize;
	cur_pos = 0;
	counter = ctr;
	stalled = 0;
	bytes_per_second = 0;

	setscreensize();
	refresh_progress_meter(1);

	ssh_signal(SIGALRM, sig_alarm);
	ssh_signal(SIGWINCH, sig_winch);
	alarm(UPDATE_INTERVAL);
}

void
stop_progress_meter(void)
{
	/* stop watching for window change */
	ssh_signal(SIGWINCH, SIG_DFL);
	alarm(0);

	if (!can_output())
		return;

	/* Ensure we complete the progress */
	if (cur_pos != end_pos)
		refresh_progress_meter(1);

	atomicio(vwrite, STDOUT_FILENO, "\n", 1);
	file = NULL;
}

static void
sig_winch(int sig)
{
	UNUSED(sig);
	win_resized = 1;
}

static void
setscreensize(void)
{
	struct winsize winsize;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != -1 &&
	    winsize.ws_col != 0) {
		if (winsize.ws_col > MAX_WINSIZE)
			win_size = MAX_WINSIZE;
		else
			win_size = winsize.ws_col;
	} else
		win_size = DEFAULT_WINSIZE;
	win_size += 1;					/* trailing \0 */
}
