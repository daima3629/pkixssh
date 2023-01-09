#	$OpenBSD: dynamic-forward.sh,v 1.14 2023/01/02 07:03:57 djm Exp $
#	Placed in the Public Domain.

tid="dynamic forwarding"

pidfile=$OBJ/remote_pid
FWDPORT=`expr $PORT + 1`

cp $OBJ/ssh_config $OBJ/ssh_config.orig

proxycmd="$OBJ/netcat -x 127.0.0.1:$FWDPORT -X"

start_ssh() {
	direction="$1"
	arg="$2"
	n=0
	error="1"
	trace "start dynamic -$direction forwarding, fork to background"
	(cat $OBJ/ssh_config.orig ; echo "$arg") > $OBJ/ssh_config

	rm -f $pidfile
	while [ "$error" -ne 0 -a "$n" -lt 3 ]; do
		n=`expr $n + 1`
		$SSH -F $OBJ/ssh_config -f -$direction $FWDPORT -q \
		    -oExitOnForwardFailure=yes somehost exec sh -c \
			\'"echo \$\$ > $pidfile; exec sleep 444"\'
		error=$?
		if [ "$error" -ne 0 ]; then
			trace "forward failed attempt $n err $error"
			sleep $n
		fi
	done
	if [ "$error" -ne 0 ]; then
		fatal "failed to start dynamic forwarding"
	fi
}

stop_ssh() {
	if test -f $pidfile ; then
		remote=`cat $pidfile`

		trace "terminate remote shell, pid $remote"
		if [ $remote -gt 1 ]; then
			kill -HUP $remote
		fi
	else
		fail "no pid file: $pidfile"
	fi
}

check_socks() {
	direction="$1"
	expect_success="$2"
	for s in 4 5; do
	    for h in 127.0.0.1 localhost; do
		trace "testing ssh socks version $s host $h (-$direction)"
		$SSH -F $OBJ/ssh_config \
			-o "ProxyCommand ${proxycmd}${s} $h $PORT 2>/dev/null" \
			somehost cat ${DATA} > ${COPY}
		r=$?
		if test "x$expect_success" = "xN" ; then
			if test $r -eq 0 ; then
				fail "ssh unexpectedly succeeded"
				r=33
			fi
			return $r
		fi
		if test $r -ne 0 ; then
			fail "ssh failed with exit status $r"
			return $r
		fi
		test -f ${COPY}	 || fail "failed copy ${DATA}"
		cmp ${DATA} ${COPY} || fail "corrupted copy of ${DATA}"
	    done
	done
}

start_sshd

for d in D R; do
	verbose "test -$d forwarding"
	start_ssh $d
	check_socks $d Y
	stop_ssh
	test "x$d" = "xR" || continue

	# Test PermitRemoteOpen
	verbose "PermitRemoteOpen=any"
	start_ssh $d PermitRemoteOpen=any
	check_socks $d Y
	stop_ssh

	verbose "PermitRemoteOpen=none"
	start_ssh $d PermitRemoteOpen=none
	check_socks $d N
	stop_ssh

	verbose "PermitRemoteOpen=explicit"
	start_ssh $d \
	    PermitRemoteOpen="127.0.0.1:$PORT [::1]:$PORT localhost:$PORT"
	check_socks $d Y
	stop_ssh

	verbose "PermitRemoteOpen=disallowed"
	start_ssh $d \
	    PermitRemoteOpen="127.0.0.1:1 [::1]:1 localhost:1"
	check_socks $d N
	stop_ssh
done
