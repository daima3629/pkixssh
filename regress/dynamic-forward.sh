#	$OpenBSD: dynamic-forward.sh,v 1.13 2017/09/21 19:18:12 markus Exp $
#	Placed in the Public Domain.

tid="dynamic forwarding"

pidfile=$OBJ/remote_pid
FWDPORT=`expr $PORT + 1`

if have_prog nc && nc -h 2>&1 | grep "proxy address" >/dev/null; then
	proxycmd="nc -x 127.0.0.1:$FWDPORT -X"
elif have_prog connect; then
	proxycmd="connect -S 127.0.0.1:$FWDPORT -"
else
	skip "no suitable ProxyCommand found"
fi
trace "will use ProxyCommand $proxycmd"

start_ssh() {
	direction="$1"
	n=0
	error="1"
	trace "start dynamic -$direction forwarding, fork to background"

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
	for s in 4 5; do
	    for h in 127.0.0.1 localhost; do
		trace "testing ssh socks version $s host $h (-$direction)"
		$SSH -F $OBJ/ssh_config \
			-o "ProxyCommand ${proxycmd}${s} $h $PORT" \
			somehost cat ${DATA} > ${COPY}
		test -f ${COPY}	 || fail "failed copy ${DATA}"
		cmp ${DATA} ${COPY} || fail "corrupted copy of ${DATA}"
	    done
	done
}

start_sshd

for d in D R; do
	start_ssh $d
	check_socks $d
	stop_ssh
done
