#	$OpenBSD: dynamic-forward.sh,v 1.18 2025/05/21 08:41:52 djm Exp $
#	Placed in the Public Domain.

tid="dynamic forwarding"

FWDPORT=`expr $PORT + 1`

cp $OBJ/ssh_config $OBJ/ssh_config.orig

proxycmd="$OBJ/netcat -x 127.0.0.1:$FWDPORT -X"

SKIP_IPV6=false
if ! config_defined HAVE_STRUCT_IN6_ADDR ; then
	SKIP_IPV6=true
fi

WAIT_SECONDS=20
make_tmpdir
CTL=${SSH_REGRESS_TMP}/ctl-sock

wait_for_process_to_exit() {
	_pid=$1
	_n=0
	while kill -0 $_pid 2>/dev/null ; do
		test $_n -eq 1 && trace "waiting for $_pid to exit"
		_n=`expr $_n + 1`
		test $_n -ge $WAIT_SECONDS && return 1
		sleep 1
	done
	return 0
}

mux_cmd() {
	$REAL_SSH -q -F $OBJ/ssh_proxy -S $CTL -O $1 somehost 2>&1
}

mux_exit() {
	_sshpid=`mux_cmd check | cut -f 2 -d = | cut -f 1 -d ')'`
	r=$?
	test $r -ne 0 && return $r
	test -z "$_sshpid" && return 0
	mux_cmd exit
	r=$?
	if test $r -ne 0 ; then
		fatal "forwarding ssh process did not respond to close"
		return $r
	fi
	wait_for_process_to_exit $_sshpid
	r=$?
	if test $r -ne 0 ; then
		fatal "forwarding ssh process did not exit"
	fi
	return $r
}


start_ssh() {
	direction="$1"
	arg="$2"
	n=0
	error="1"
	trace "start dynamic -$direction forwarding, fork to background"
	(cat $OBJ/ssh_config.orig ; echo "$arg") > $OBJ/ssh_config
	$REAL_SSH -nN -F $OBJ/ssh_config -f -vvvv -E$TEST_SSH_LOGFILE \
	    -$direction $FWDPORT -oExitOnForwardFailure=yes \
	    -oControlMaster=yes -oControlPath=$CTL somehost
	r=$?
	test $r -eq 0 || fatal "failed to start dynamic forwarding $r"
	mux_cmd check >/dev/null
	r=$?
	test $r -ne 0 && fatal "forwarding ssh process unresponsive"
	return $r
}

stop_ssh() {
	mux_exit
}

check_socks() {
	direction="$1"
	expect_success="$2"
	for s in 4 4A 5; do
	    for h in 127.0.0.1 localhost; do
		trace "testing ssh socks version $s host $h (-$direction)"
		$REAL_SSH -q -F $OBJ/ssh_config \
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

gen_permit_argument() {
	permit="127.0.0.1:$1"
	$SKIP_IPV6 || permit="$permit [::1]:$1"
	permit="$permit localhost:$1"
}

start_sshd
trap "stop_ssh" EXIT

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
	gen_permit_argument $PORT
	start_ssh $d PermitRemoteOpen="$permit"
	check_socks $d Y
	stop_ssh

	verbose "PermitRemoteOpen=disallowed"
	gen_permit_argument 1
	start_ssh $d PermitRemoteOpen="$permit"
	check_socks $d N
	stop_ssh
done
