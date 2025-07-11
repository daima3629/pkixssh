#	$OpenBSD: percent.sh,v 1.20 2025/03/03 06:54:37 dtucker Exp $
#	Placed in the Public Domain.

tid="percent expansions"

USERID=`id -u`
HOSTNAME=`hostname`
test -z "$HOSTNAME" && HOSTNAME=`uname -n`
HOST=`echo $HOSTNAME | cut -f1 -d.`
HASH=

# Localcommand is evaluated after connection because %T is not available
# until then.  Because of this we use a different method of exercising it,
# and we can't override the remote user otherwise authentication will fail.
# We also have to explicitly enable it.
echo "permitlocalcommand yes" >> $OBJ/ssh_proxy

trial()
{
	opt="$1"; arg="$2"; expect="$3"

	trace "test $opt=$arg $expect"
	rm -f $OBJ/actual
	got=""
	case "$opt" in
	localcommand)
		${SSH} -F $OBJ/ssh_proxy -o $opt="echo '$arg' >$OBJ/actual" \
		    somehost true
		got=`cat $OBJ/actual`
		;;
	userknownhostsfile)
		# Move the userknownhosts file to what the expansion says,
		# make sure ssh works then put it back.
		mv "$OBJ/known_hosts" "$OBJ/$expect"
		${SSH} -F $OBJ/ssh_proxy -o $opt="$OBJ/$arg" somehost true && \
			got="$expect"
		mv "$OBJ/$expect" "$OBJ/known_hosts"
		;;
	matchexec)
		(cat $OBJ/ssh_proxy && \
		 echo "Match Exec \"echo '$arg' >$OBJ/actual\"") \
		    >$OBJ/ssh_proxy_match
		${SSH} -F $OBJ/ssh_proxy_match remuser@somehost true || true
		got=`cat $OBJ/actual`
		;;
	*forward)
		# LocalForward and RemoteForward take two args and only
		# operate on Unix domain socket paths
		got=`${SSH} -F $OBJ/ssh_proxy -o $opt="/$arg /$arg" -d \
		    remuser@somehost | awk '$1=="'$opt'"{print $2" "$3}'`
		expect="/$expect /$expect"
		;;
	setenv)
		# First do not expand variable name.
		got=`$SSH -F $OBJ/ssh_proxy -o $opt="$arg=TESTVAL" -d \
		    remuser@somehost | awk '$1=="'$opt'"{print $2}'`
		if [ "$got" != "$arg=TESTVAL" ]; then
			fatal "incorrectly expanded setenv variable name"
		fi
		# Now check that the value expands as expected.
		got=`$SSH -F $OBJ/ssh_proxy -o $opt=TESTVAL="$arg" -d \
		    remuser@somehost | awk '$1=="'$opt'"{print $2}'`
		got=`echo "$got" | sed 's/^TESTVAL=//'`
		;;
	*)
		got=`${SSH} -F $OBJ/ssh_proxy -o $opt="$arg" -d \
		    remuser@somehost | awk '$1=="'$opt'"{print $2}'`
	esac
	if [ "$got" != "$expect" ]; then
		fail "$opt=$arg expect $expect got $got"
	fi
}

for i in matchexec localcommand remotecommand controlpath identityagent \
    forwardagent localforward remoteforward revokedhostkeys \
    setenv userknownhostsfile; do
	verbose $tid $i percent
	case "$i" in
	localcommand|userknownhostsfile)
		# Any test that's going to actually make a connection needs
		# to use the real username.
		REMUSER=$USER ;;
	*)
		REMUSER=remuser ;;
	esac
	if [ "$i" = "$localcommand" ]; then
		trial $i '%T' NONE
	fi
	# Matches implementation in readconf.c:ssh_connection_hash()
	HASH=`printf "${HOSTNAME}127.0.0.1${PORT}$REMUSER" |
	    $OPENSSL sha1 | cut -f2 -d' '`
	trial $i '%%' '%'
	test -n "$HASH" && \
	trial $i '%C' $HASH
	trial $i '%i' $USERID
	trial $i '%h' 127.0.0.1
	trial $i '%L' $HOST
	trial $i '%l' $HOSTNAME
	trial $i '%n' somehost
	trial $i '%k' localhost-with-alias
	trial $i '%p' $PORT
	trial $i '%r' $REMUSER
	trial $i '%u' $USER
	# We can't specify a full path outside the regress dir, so skip tests
	# containing %d for UserKnownHostsFile
	if [ "$i" != "userknownhostsfile" ]; then
		trial $i '%d' $HOME
		in='%%/%i/%h/%d/%L/%l/%n/%p/%r/%u'
		out="%/$USERID/127.0.0.1/$HOME/$HOST/$HOSTNAME/somehost/$PORT/$REMUSER/$USER"
		if test -n "$HASH" ; then
			in="$in/%C"
			out="$out/$HASH"
		fi
		trial $i "$in" "$out"
	fi
done

# Subset of above since we don't expand shell-style variables on anything that
# runs a command because the shell will expand those.
for i in controlpath identityagent forwardagent localforward remoteforward \
    setenv userknownhostsfile; do
	verbose $tid $i dollar
	FOO=bar
	export FOO
	trial $i '${FOO}' $FOO
done


# A subset of options support tilde expansion
PREFIX=$HOME
test "$PREFIX" = "/" && PREFIX=
for i in controlpath identityagent forwardagent; do
	verbose $tid $i tilde
	trial $i '~' $PREFIX/
	trial $i '~/.ssh' $PREFIX/.ssh
done
