#	$OpenBSD: hostbased.sh,v 1.3 2022/01/08 07:55:26 dtucker Exp $
#	Placed in the Public Domain.

# Since helper for host-based authentication uses keys with hard coded
# paths, unlike the other tests it needs to use the real host keys.
# In addition host-based requires:
# - helper(ssh-keysign) must be installed and setuid root.
# - "EnableSSHKeysign yes" must be in the system client configuration.
# - host and user accepted by system-wide shosts.equiv.
# - host public key listed in known hosts files.

tid="hostbased"

if test -z "$SUDO" ; then
	skip "SUDO not set"
fi

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_orig
grep -vi hostkey $OBJ/sshd_proxy_orig > $OBJ/sshd_proxy
cat >>$OBJ/sshd_proxy <<EOD
HostbasedAuthentication yes
HostbasedUsesNameFromPacketOnly yes
EOD

cp $OBJ/ssh_proxy $OBJ/ssh_proxy_orig
( grep -vi HostbasedAuthentication $OBJ/ssh_proxy_orig | \
  grep -vi GlobalKnownHostsFile | grep -vi UserKnownHostsFile | \
  grep -vi HostKeyAlias
) > $OBJ/ssh_proxy
cat >>$OBJ/ssh_proxy <<EOD
HostKeyAlias localhost
HostbasedAuthentication yes
PreferredAuthentications hostbased
EOD

algos=
# keep order as in ssh-keysign.c, exclude xmms for now
for t in ed25519 ecdsa rsa dsa ; do
	key="$sysconfdir/ssh_host_${t}_key"
	case "`$SUDO $SSHKEYGEN -l -f $key.pub 2>/dev/null`" in
	256*ECDSA*)	algos="$algos ecdsa-sha2-nistp256" ;;
	384*ECDSA*)	algos="$algos ecdsa-sha2-nistp384" ;;
	521*ECDSA*)	algos="$algos ecdsa-sha2-nistp521" ;;
	*RSA*)		algos="$algos ssh-rsa rsa-sha2-256 rsa-sha2-512" ;;
	*ED25519*)	algos="$algos ssh-ed25519" ;;
	*DSA*)		algos="$algos ssh-dss" ;;
	*)		verbose "unknown host key $key"
			continue;;
	esac
	echo "HostKey $key" >> $OBJ/sshd_proxy
done
test -z "$algos" && fail "no default host-keys"

for algo in $algos; do
	trace "hostbased algo $algo"
	opts="-F $OBJ/ssh_proxy"
	opts="$opts -oHostbasedAcceptedAlgorithms=$algo"
	SSH_CONNECTION=`$SSH $opts localhost 'echo $SSH_CONNECTION'`
	if test $? -ne 0 ; then
		fail "connect failed, hostbased algo $algo"
	elif test "x$SSH_CONNECTION" != "xUNKNOWN 65535 UNKNOWN 65535" ; then
		fail "hostbased algo $algo bad SSH_CONNECTION" \
		    "$SSH_CONNECTION"
	else
		verbose "ok hostbased $algo"
	fi
done
