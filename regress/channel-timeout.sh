#	$OpenBSD: channel-timeout.sh,v 1.2 2024/01/09 22:19:36 djm Exp $
#	Placed in the Public Domain.

tid="channel timeout"

# XXX not comprehensive. Still need -R -L agent X11 forwarding + interactive
SFTPSUBSYS=$OBJ/slow-sftp-server.sh

rm -f $OBJ/finished.*

make_tmpdir
CTL="$SSH_REGRESS_TMP"/ctl-sock

mux_cmd() {
	$REAL_SSH -q -F $OBJ/ssh_proxy -S $CTL -O $1 somehost 2>&1
}

open_mux() {
	$SSH -nNfM -F $OBJ/ssh_proxy -S $CTL somehost ||
	    fatal "open mux failed"
	test -e $CTL || fatal "mux socket $CTL not established"
}

close_mux() {
	test -e $CTL || fatal "mux socket $CTL missing"
	mux_cmd exit >/dev/null
	r=$?
	if test $r -ne 0 ; then
		fatal "ssh process did not respond to close"
	fi
	for x in 1 2 3 4 5 6 7 8 9 10 ; do
		test -e $CTL && break
		sleep 1
	done
	test -e $CTL && fatal "mux did not clean up"
}

mux_client() {
	$SSH -F $OBJ/ssh_proxy -S $CTL somehost "$@"
}

rm -f $OBJ/sshd_proxy.orig
cp $OBJ/sshd_proxy $OBJ/sshd_proxy.orig

# Set up a "slow sftp server" that sleeps before executing the real one.
cat > $SFTPSUBSYS << EOF
#! /bin/sh

sleep 5
$SFTPSERVER
EOF
chmod a+x $SFTPSUBSYS


verbose "no timeout"
${SSH} -F $OBJ/ssh_proxy somehost "sleep 5 ; exit 23"
r=$?
if [ $r -ne 23 ]; then
	fail "ssh failed"
fi

verbose "command timeout"
(cat $OBJ/sshd_proxy.orig ; echo "ChannelTimeout session:command=1") \
	> $OBJ/sshd_proxy
${SSH} -F $OBJ/ssh_proxy somehost "sleep 5 ; exit 23"
r=$?
if [ $r -ne 255 ]; then
	fail "ssh returned unexpected error code $r"
fi

verbose "command long timeout"
(cat $OBJ/sshd_proxy.orig ; echo "ChannelTimeout session:command=60") \
	> $OBJ/sshd_proxy
${SSH} -F $OBJ/ssh_proxy somehost "exit 23"
r=$?
if [ $r -ne 23 ]; then
	fail "ssh returned unexpected error code $r"
fi

verbose "command wildcard timeout"
(cat $OBJ/sshd_proxy.orig ; echo "ChannelTimeout session:*=1") \
	> $OBJ/sshd_proxy
${SSH} -F $OBJ/ssh_proxy somehost "sleep 5 ; exit 23"
r=$?
if [ $r -ne 255 ]; then
	fail "ssh returned unexpected error code $r"
fi

verbose "command irrelevant timeout"
(cat $OBJ/sshd_proxy.orig ; echo "ChannelTimeout session:shell=1") \
	> $OBJ/sshd_proxy
${SSH} -F $OBJ/ssh_proxy somehost "sleep 5 ; exit 23"
r=$?
if [ $r -ne 23 ]; then
	fail "ssh failed"
fi

if config_defined DISABLE_FD_PASSING ; then
	verbose "skipping multiplexed command timeout"
else
	verbose "multiplexed command timeout"
	(cat $OBJ/sshd_proxy.orig ; echo "ChannelTimeout session:command=1") \
		> $OBJ/sshd_proxy
	open_mux
	mux_client "sleep 5 ; exit 23"
	r=$?
	if [ $r -ne 255 ]; then
		fail "ssh returned unexpected error code $r"
	fi
	close_mux
fi

if config_defined DISABLE_FD_PASSING ; then
	verbose "skipping irrelevant multiplexed command timeout"
else
	verbose "irrelevant multiplexed command timeout"
	(cat $OBJ/sshd_proxy.orig ; echo "ChannelTimeout session:shell=1") \
		> $OBJ/sshd_proxy
	open_mux
	mux_client "sleep 5 ; exit 23"
	r=$?
	if [ $r -ne 23 ]; then
		fail "ssh returned unexpected error code $r"
	fi
	close_mux
fi

if config_defined DISABLE_FD_PASSING ; then
	verbose "skipping global command timeout (test requires multiplexing)"
else
	verbose "global command timeout"
	(cat $OBJ/sshd_proxy.orig ; echo "ChannelTimeout global=10") \
		> $OBJ/sshd_proxy
	open_mux
	mux_client "sleep 1 ; echo ok ; sleep 1; echo ok; sleep 60; touch $OBJ/finished.1" >/dev/null &
	mux_client "sleep 60 ; touch $OBJ/finished.2" >/dev/null &
	mux_client "sleep 2 ; touch $OBJ/finished.3" >/dev/null &
	wait
	test -f $OBJ/finished.1 && fail "first mux process completed"
	test -f $OBJ/finished.2 && fail "second mux process completed"
	test -f $OBJ/finished.3 || fail "third mux process did not complete"
	close_mux
fi

verbose "sftp no timeout"
(grep -vi subsystem.*sftp $OBJ/sshd_proxy.orig;
 echo "Subsystem sftp $SFTPSUBSYS" ) > $OBJ/sshd_proxy

rm -f ${COPY}
$SFTP -qS $SSH -F $OBJ/ssh_proxy somehost:$DATA $COPY >>$TEST_REGRESS_LOGFILE 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "sftp failed"
fi
cmp $DATA $COPY || fail "corrupted copy"

verbose "sftp timeout"
(grep -vi subsystem.*sftp $OBJ/sshd_proxy.orig;
 echo "ChannelTimeout session:subsystem:sftp=1" ;
 echo "Subsystem sftp $SFTPSUBSYS" ) > $OBJ/sshd_proxy

rm -f ${COPY}
$SFTP -qS $SSH -F $OBJ/ssh_proxy somehost:$DATA $COPY >>$TEST_REGRESS_LOGFILE 2>&1
r=$?
if [ $r -eq 0 ]; then
	fail "sftp succeeded unexpectedly"
fi
test -f $COPY && cmp $DATA $COPY && fail "intact copy"

verbose "sftp irrelevant timeout"
(grep -vi subsystem.*sftp $OBJ/sshd_proxy.orig;
 echo "ChannelTimeout session:subsystem:command=1" ;
 echo "Subsystem sftp $SFTPSUBSYS" ) > $OBJ/sshd_proxy

rm -f ${COPY}
$SFTP -qS $SSH -F $OBJ/ssh_proxy somehost:$DATA $COPY >>$TEST_REGRESS_LOGFILE 2>&1
r=$?
if [ $r -ne 0 ]; then
	fail "sftp failed"
fi
cmp $DATA $COPY || fail "corrupted copy"

rm -f "$SFTPSUBSYS"
