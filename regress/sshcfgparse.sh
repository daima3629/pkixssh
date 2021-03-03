#	$OpenBSD: sshcfgparse.sh,v 1.7 2021/02/24 23:12:35 dtucker Exp $
#	Placed in the Public Domain.

tid="ssh config parse"

expect_result_present() {
	_str="$1" ; shift
	for _expect in "$@" ; do
		echo "$f" | tr ',' '\n' | grep "^$_expect\$" >/dev/null
		if test $? -ne 0 ; then
			fail "missing expected \"$_expect\" from \"$_str\""
		fi
	done
}

verbose "reparse minimal config"
(${SSH} -d -F $OBJ/ssh_config somehost >$OBJ/ssh_config.1 &&
 ${SSH} -d -F $OBJ/ssh_config.1 somehost >$OBJ/ssh_config.2 &&
 diff $OBJ/ssh_config.1 $OBJ/ssh_config.2) || fail "reparse minimal config"

verbose "ssh -W opts"
f=`${SSH} -dF $OBJ/ssh_config host | awk '/exitonforwardfailure/{print $2}'`
test "$f" = "no" || fail "exitonforwardfailure default"
f=`${SSH} -dF $OBJ/ssh_config -W a:1 h | awk '/exitonforwardfailure/{print $2}'`
test "$f" = "yes" || fail "exitonforwardfailure enable"
f=`${SSH} -dF $OBJ/ssh_config -W a:1 -o exitonforwardfailure=no h | \
    awk '/exitonforwardfailure/{print $2}'`
test "$f" = "no" || fail "exitonforwardfailure override"

f=`${SSH} -dF $OBJ/ssh_config host | awk '/clearallforwardings/{print $2}'`
test "$f" = "no" || fail "clearallforwardings default"
f=`${SSH} -dF $OBJ/ssh_config -W a:1 h | awk '/clearallforwardings/{print $2}'`
test "$f" = "yes" || fail "clearallforwardings enable"
f=`${SSH} -dF $OBJ/ssh_config -W a:1 -o clearallforwardings=no h | \
    awk '/clearallforwardings/{print $2}'`
test "$f" = "no" || fail "clearallforwardings override"

verbose "user first match"
user=`awk '$1=="User" {print $2}' $OBJ/ssh_config`
f=`${SSH} -dF $OBJ/ssh_config host | awk '/^user /{print $2}'`
test "$f" = "$user" || fail "user from config, expected '$user' got '$f'"
f=`${SSH} -dF $OBJ/ssh_config -o user=foo -l bar baz@host | awk '/^user /{print $2}'`
test "$f" = "foo" || fail "user first match -oUser, expected 'foo' got '$f' "
f=`${SSH} -dF $OBJ/ssh_config -lbar baz@host user=foo baz@host | awk '/^user /{print $2}'`
test "$f" = "bar" || fail "user first match -l, expected 'bar' got '$f'"
f=`${SSH} -dF $OBJ/ssh_config baz@host -o user=foo -l bar baz@host | awk '/^user /{print $2}'`
test "$f" = "baz" || fail "user first match user@host, expected 'baz' got '$f'"

verbose "agentforwarding"
f=`${SSH} -dF none host | awk '/^forwardagent /{print$2}'`
expect_result_present "$f" "no"
f=`${SSH} -dF none -oforwardagent=no host | awk '/^forwardagent /{print$2}'`
expect_result_present "$f" "no"
f=`${SSH} -dF none -oforwardagent=yes host | awk '/^forwardagent /{print$2}'`
expect_result_present "$f" "yes"
f=`${SSH} -dF none '-oforwardagent=SSH_AUTH_SOCK.forward' host | awk '/^forwardagent /{print$2}'`
expect_result_present "$f" "SSH_AUTH_SOCK.forward"

# cleanup
rm -f $OBJ/ssh_config.[012]
