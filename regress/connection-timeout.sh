#	$OpenBSD: connection-timeout.sh,v 1.2 2023/01/17 10:15:10 djm Exp $
#	Placed in the Public Domain.

tid="unused connection timeout"

WAIT_SECONDS=20
make_tmpdir
CTL=$SSH_REGRESS_TMP/ctl-sock

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
	mux_cmd exit >/dev/null
	r=$?
	if test $r -ne 0 ; then
		fatal "ssh process did not respond to close"
	fi
	wait_for_process_to_exit $_sshpid
	r=$?
	if test $r -ne 0 ; then
		fatal "ssh process did not exit"
	fi
	return $r
}

check_ssh() {
	mux_cmd check >/dev/null
}

start_ssh() {
	trace "start ssh"
	${SSH} -nNfF $OBJ/ssh_proxy "$@" -oExitOnForwardFailure=yes \
	    -oControlMaster=yes -oControlPath=$CTL somehost
	r=$?
	test $r -eq 0 || fatal "failed to start ssh $r"
	check_ssh
	r=$?
	test $r -eq 0 || fatal "ssh process unresponsive"
}

stop_ssh() {
	mux_exit
}

trap "stop_ssh" EXIT

cp $OBJ/sshd_proxy $OBJ/sshd_proxy.orig

verbose "no timeout"
start_ssh
sleep 5
check_ssh || fail "ssh unexpectedly missing"
stop_ssh

(cat $OBJ/sshd_proxy.orig ; echo "UnusedConnectionTimeout 2") > $OBJ/sshd_proxy

verbose "timeout"
start_ssh
sleep 8
check_ssh && fail "ssh unexpectedly present"
stop_ssh

verbose "session inhibits timeout"
rm -f $OBJ/copy2
start_ssh
${REAL_SSH} -qoControlPath=$CTL -oControlMaster=no -Fnone somehost \
	"sleep 8; touch $OBJ/copy2" &
check_ssh || fail "ssh unexpectedly missing"
wait
test -f $OBJ/copy2 || fail "missing result file"

verbose "timeout after session"
# Session should still be running from previous
sleep 8
check_ssh && fail "ssh unexpectedly present"
stop_ssh

LPORT=`expr $PORT + 1`
RPORT=`expr $LPORT + 1`
DPORT=`expr $RPORT + 1`
RDPORT=`expr $DPORT + 1`
verbose "timeout with listeners"
start_ssh -L$LPORT:127.0.0.1:$PORT -R$RPORT:127.0.0.1:$PORT -D$DPORT -R$RDPORT
sleep 8
check_ssh && fail "ssh unexpectedly present"
stop_ssh
