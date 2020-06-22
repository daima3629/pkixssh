#	$OpenBSD: agent-subprocess.sh,v 1.1 2020/06/19 05:07:09 dtucker Exp $
#	Placed in the Public Domain.

tid="agent subprocess"

trace "ensure agent exits when run as subprocess"
$SSHAGENT $TEST_SHELL -c "echo \$SSH_AGENT_PID >$OBJ/pidfile; sleep 1"
sleep 1
pid=`cat $OBJ/pidfile`

echo "waiting about 10s agent to exit ..."
# currently ssh-agent polls every 10s so we need to wait at least that long.
count=12
while test $count -gt 0 ; do
  sleep 1
  if ! kill -0 $pid >/dev/null 2>&1 ; then
    break
  fi
  count=`expr $count - 1`
done

if test $count -eq 0 ; then
  fail "agent still running"
fi

rm -f $OBJ/pidfile
