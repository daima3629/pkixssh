#	$OpenBSD: knownhosts-command.sh,v 1.2 2020/12/22 06:47:24 djm Exp $
#	Placed in the Public Domain.

tid="known hosts command "

# cross-project configuration
if test "$sshd_type" != "pkix" ; then
mv $OBJ/sshd_proxy $OBJ/sshd_proxy.orig
(
	grep -v "HostkeyAlgorithms"  $OBJ/sshd_proxy.orig
	echo "HostkeyAlgorithms *,ssh-dss*"
) > $OBJ/sshd_proxy
fi


rm -f $OBJ/knownhosts_command $OBJ/ssh_proxy_khc
cp $OBJ/ssh_proxy $OBJ/ssh_proxy_orig

( grep -vi GlobalKnownHostsFile $OBJ/ssh_proxy_orig | \
    grep -vi UserKnownHostsFile;
  echo "GlobalKnownHostsFile none" ;
  echo "UserKnownHostsFile none" ;
  echo "KnownHostsCommand $OBJ/knownhosts_command '%t' '%K' '%u'" ;
) > $OBJ/ssh_proxy

> $OBJ/knownhosts_command
chmod a+x $OBJ/knownhosts_command

verbose "simple connection"
cat > $OBJ/knownhosts_command << _EOF
#! $TEST_SHELL
cat $OBJ/known_hosts
_EOF
$SSH -F $OBJ/ssh_proxy x true || fail "ssh connect failed"

verbose "no keys"
cat > $OBJ/knownhosts_command << _EOF
#! $TEST_SHELL
exit 0
_EOF
$SSH -F $OBJ/ssh_proxy x true && fail "ssh connect succeeded with no keys"

verbose "bad exit status"
cat > $OBJ/knownhosts_command << _EOF
#! $TEST_SHELL
cat $OBJ/known_hosts
exit 1
_EOF
$SSH -F $OBJ/ssh_proxy x true && fail "ssh connect succeeded with bad exit"

for keytype in $SSH_HOSTKEY_TYPES ; do
case $keytype in
ssh-xmss@openssh.com) continue;; # TODO
esac
	verbose "keytype $keytype"
	cat > $OBJ/knownhosts_command << _EOF
#! $TEST_SHELL
if test "x\$1" = "xNONE" ; then
  grep " $keytype " $OBJ/known_hosts
  exit 0
fi
die() { echo \${1+"\$@"} >&2 ; exit 1; }
test "x\$1" = "x$keytype" || die "wrong keytype \$1 (expected $keytype)"
test "x\$3" = "x$LOGNAME" || die "wrong username \$3 (expected $LOGNAME)"
grep "\$1.*\$2" $OBJ/known_hosts
_EOF
	$SSH -F $OBJ/ssh_proxy -oHostKeyAlgorithms=$keytype x true ||
	    fail "ssh connect failed for keytype $keytype"
done

# cleanup
rm -f knownhosts_command
