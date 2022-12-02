#	$OpenBSD: agent-ptrace.sh,v 1.3 2015/09/11 04:55:01 djm Exp $
#	Placed in the Public Domain.

tid="disallow agent ptrace attach"

if have_prog uname ; then
	case `uname` in
	AIX|CYGWIN*|OSF1)
		skip "not supported on this platform"
		;;
	esac
fi

if [ "x$USER" = "xroot" ]; then
	skip "running as root"
fi

if have_prog gdb ; then
	: ok
else
	skip "gdb not found"
fi

if $OBJ/setuid-allowed ${SSHAGENT} ; then
	: ok
else
	skip "$SSHAGENT is mounted on a no-setuid filesystem"
fi

if test -z "$SUDO" ; then
	skip "SUDO not set"
else
	$SUDO chown 0 ${SSHAGENT}
	$SUDO chgrp 0 ${SSHAGENT}
	$SUDO chmod 2755 ${SSHAGENT}
	trap "$SUDO chown ${USER} ${SSHAGENT}; $SUDO chmod 755 ${SSHAGENT}" 0
fi

trace "start agent"
eval `${SSHAGENT} ${EXTRA_AGENT_ARGS} -s` > /dev/null
r=$?
if [ $r -ne 0 ]; then
	fail "could not start ssh-agent: exit code $r"
else
	# ls -l ${SSH_AUTH_SOCK}
	gdb ${SSHAGENT} ${SSH_AGENT_PID} > ${OBJ}/gdb.out 2>&1 << EOF
		quit
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "gdb failed: exit code $r"
	fi
	egrep 'ptrace: Operation not permitted.|procfs:.*Permission denied.|ttrace.*Permission denied.|procfs:.*: Invalid argument.|Unable to access task ' >/dev/null ${OBJ}/gdb.out
	r=$?
	rm -f ${OBJ}/gdb.out
	if [ $r -ne 0 ]; then
		fail "ptrace succeeded?: exit code $r"
	fi

	trace "kill agent"
	${SSHAGENT} -k > /dev/null
fi
