#	$OpenBSD: hostkey-rotate.sh,v 1.10 2022/01/05 08:25:05 djm Exp $
#	Placed in the Public Domain.

tid="hostkey rotate"

#
# GNU (f)grep <=2.18, as shipped by FreeBSD<=12 and NetBSD<=9 will occasionally
# fail to find ssh host keys in the hostkey-rotate test.  If we have those
# versions, use awk instead.
# See # https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=258616
#
case `$FGREP --version 2>&1 | awk '/GNU grep/{print $4}'` in
2.19)			fgrep_ver=good ;;
1.*|2.?|2.?.?|2.1?)	fgrep_ver=bad ;;	# stock GNU grep
2.5.1*)			fgrep_ver=bad ;;	# FreeBSD and NetBSD
*)			fgrep_ver=good ;;
esac
if test "x$fgrep_ver" = "xbad"; then
	fgrep()
{
	awk 'BEGIN{e=1} {if (index($0,"'$1'")>0){e=0;print}} END{exit e}' $2
}
fi

rm -f $OBJ/hkr.* $OBJ/ssh_proxy.orig $OBJ/ssh_proxy.orig

grep -vi 'hostkey' $OBJ/sshd_proxy > $OBJ/sshd_proxy.orig
mv $OBJ/ssh_proxy $OBJ/ssh_proxy.orig
(
grep -vi 'globalknownhostsfile' $OBJ/ssh_proxy.orig
echo "GlobalKnownHostsFile /dev/null"
echo "UpdateHostkeys yes"
) > $OBJ/ssh_proxy
rm $OBJ/known_hosts

# The "primary" key type is ed25519 since it's supported even when built
# without OpenSSL.  The secondary is RSA if it's supported.
primary="ssh-ed25519"
secondary="$primary"

trace "prepare hostkeys"
nkeys=0
all_algs=""
for k in $SSH_HOSTKEY_TYPES ; do
	keytype_compat $k
	$SSHKEYGEN -q -N '' $keytype_val -f $OBJ/hkr.$k || fatal "ssh-keygen $k"
	echo "Hostkey $OBJ/hkr.${k}" >> $OBJ/sshd_proxy.orig
	nkeys=`expr $nkeys + 1`
	test "x$all_algs" = "x" || all_algs="${all_algs},"
	case "$k" in
	ssh-rsa)
		secondary="ssh-rsa"
		if config_defined HAVE_EVP_SHA256 ; then
			all_algs="${all_algs}rsa-sha2-256,rsa-sha2-512,"
		fi
		;;
	esac
	all_algs="$all_algs$k"
done

dossh() {
	# All ssh should succeed in this test
	$SSH -F $OBJ/ssh_proxy ${1+"$@"} x true || fail "ssh $@ failed"
}

expect_nkeys() {
	_expected=$1
	_message=$2
	_n=`wc -l $OBJ/known_hosts | awk '{ print $1 }'` || fatal "wc failed"
	[ "x$_n" = "x$_expected" ] || fail "$_message (got $_n wanted $_expected)"
}

check_key_present() {
	_type=$1
	_kfile=$2
	test "x$_kfile" = "x" && _kfile="$OBJ/hkr.${_type}.pub"
	_kpub=`awk "/$_type /"' { print $2 }' < $_kfile` || \
		fatal "awk failed"
	fgrep "$_kpub" $OBJ/known_hosts > /dev/null
}

cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy

# Connect to sshd with StrictHostkeyChecking=no
verbose "learn hostkey with StrictHostKeyChecking=no"
>$OBJ/known_hosts
dossh -oHostKeyAlgorithms=$primary -oStrictHostKeyChecking=no
# Verify no additional keys learned
expect_nkeys 1 "unstrict connect keys"
check_key_present $primary || fail "unstrict didn't learn key"

# Connect to sshd as usual
verbose "learn additional hostkeys"
dossh -oStrictHostKeyChecking=yes -oHostKeyAlgorithms=$all_algs
# Check that other keys learned
expect_nkeys $nkeys "learn hostkeys"
for k in $SSH_HOSTKEY_TYPES ; do
	check_key_present $k || fail "didn't learn keytype $k"
done

# Check each key type
for k in $SSH_HOSTKEY_TYPES ; do
	alg=
	case "$k" in
	ssh-rsa)
		if config_defined HAVE_EVP_SHA256 ; then
			alg="rsa-sha2-256,rsa-sha2-512,"
		fi
		;;
	esac
	alg="$alg$k"
	verbose "learn additional hostkeys, type=$k"
	dossh -oStrictHostKeyChecking=yes -oHostKeyAlgorithms=$alg,$all_algs
	expect_nkeys $nkeys "learn hostkeys $k"
	check_key_present $k || fail "didn't learn $k correctly"
done

# Change one hostkey (non primary) and relearn
if [ "$primary" != "$secondary" ]; then
	verbose "learn changed non-primary hostkey type=${secondary}"
	mv $OBJ/hkr.${secondary}.pub $OBJ/hkr.${secondary}.pub.old
	rm -f $OBJ/hkr.${secondary}
	keytype_compat $secondary
	$SSHKEYGEN -q -N '' $keytype_val -f $OBJ/hkr.$secondary || \
	    fatal "ssh-keygen $secondary"
	dossh -oStrictHostKeyChecking=yes -oHostKeyAlgorithms=$all_algs
	# Check that the key was replaced
	expect_nkeys $nkeys "learn hostkeys"
	check_key_present ${secondary} $OBJ/hkr.${secondary}.pub.old && \
	    fail "old key present"
	check_key_present ${secondary} || fail "didn't learn changed key"
fi

# Add new hostkey (primary type) to sshd and connect
verbose "learn new primary hostkey"
keytype_compat $primary
$SSHKEYGEN -q -N '' $keytype_val -f $OBJ/hkr.${primary}-new || fatal "ssh-keygen ed25519"
( cat $OBJ/sshd_proxy.orig ; echo HostKey $OBJ/hkr.${primary}-new ) \
    > $OBJ/sshd_proxy
# Check new hostkey added
dossh -oStrictHostKeyChecking=yes -oHostKeyAlgorithms=${primary},$all_algs
expect_nkeys `expr $nkeys + 1` "learn hostkeys"
check_key_present ${primary} || fail "current key missing"
check_key_present ${primary} $OBJ/hkr.${primary}-new.pub || fail "new key missing"

# Remove old hostkey (primary type) from sshd
verbose "rotate primary hostkey"
cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
mv $OBJ/hkr.${primary}.pub $OBJ/hkr.${primary}.pub.old
mv $OBJ/hkr.${primary}-new.pub $OBJ/hkr.${primary}.pub
mv $OBJ/hkr.${primary}-new $OBJ/hkr.${primary}
# Check old hostkey removed
dossh -oStrictHostKeyChecking=yes -oHostKeyAlgorithms=${primary},$all_algs
expect_nkeys $nkeys "learn hostkeys"
check_key_present ${primary} $OBJ/hkr.${primary}.pub.old && fail "old key present"
check_key_present ${primary} || fail "didn't learn changed key"

# Connect again, forcing rotated key
verbose "check rotate primary hostkey"
dossh -oStrictHostKeyChecking=yes -oHostKeyAlgorithms=${primary}
expect_nkeys 1 "learn hostkeys"
check_key_present ${primary} || fail "didn't learn changed key"

rm -f $OBJ/known_hosts.old
