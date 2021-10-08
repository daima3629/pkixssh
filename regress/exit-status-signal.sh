# This test performs validation that ssh client is not successive on being terminated

tid="exit status on signal"

pidfile=$OBJ/remote_pid

# spawn client in background
rm -f $pidfile
$SSH -F $OBJ/ssh_proxy somehost 'echo $$ >'$pidfile'; sleep 444' &
client_pid=$!

# wait for it to start
n=0
while test ! -f $pidfile ; do
	sleep 1
	n=`expr $n + 1`
	if test $n -gt 60; then
		kill $client_pid
		fatal "timeout waiting for background ssh"
	fi
done

kill $client_pid
wait $client_pid
exit_code=$?

if test $exit_code -eq 0 ; then
	fail "ssh client should fail on signal"
fi
