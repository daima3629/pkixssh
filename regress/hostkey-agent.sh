#	$OpenBSD: hostkey-agent.sh,v 1.14 2024/11/26 22:02:28 djm Exp $
#	Placed in the Public Domain.

tid="hostkey agent"
PLAIN_TYPES=`echo "$SSH_HOSTKEY_TYPES" | sed 's/ssh-xmss@openssh.com//'` # TODO

rm -f $OBJ/agent-key.* $OBJ/ssh_proxy.orig $OBJ/agent-ca $OBJ/agent-ca.pub

trace "start agent"
eval `${SSHAGENT} ${EXTRA_AGENT_ARGS} -s` > /dev/null
r=$?
[ $r -ne 0 ] && fatal "could not start ssh-agent: exit code $r"

grep -vi 'hostkey' $OBJ/sshd_proxy > $OBJ/sshd_proxy.orig
echo "HostKeyAgent $SSH_AUTH_SOCK" >> $OBJ/sshd_proxy.orig

trace "make CA key"

${SSHKEYGEN} -qt ed25519 -f $OBJ/agent-ca -N '' || fatal "ssh-keygen CA"

trace "load hostkeys"
for k in $PLAIN_TYPES ; do
	${SSHKEYGEN} -qt $k -f $OBJ/agent-key.$k -N '' || fatal "ssh-keygen $k"
	${SSHKEYGEN} -s $OBJ/agent-ca -qh -n localhost-with-alias \
		-I localhost-with-alias $OBJ/agent-key.$k.pub || \
		fatal "sign $k"
	${SSHADD} -k $OBJ/agent-key.$k >/dev/null 2>&1 || \
		fatal "couldn't load key $OBJ/agent-key.$k"
	# Remove private key so the server can't use it.
	rm $OBJ/agent-key.$k || fatal "couldn't rm $OBJ/agent-key.$k"
done
rm $OBJ/agent-ca # Don't need CA private any more either

unset SSH_AUTH_SOCK

for ps in $SSHD_PRIVSEP ; do
for k in $PLAIN_TYPES ; do
	verbose "key type $k privsep=$ps"
	cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
	echo "UsePrivilegeSeparation $ps" >> $OBJ/sshd_proxy
	echo "HostKeyAlgorithms $k" >> $OBJ/sshd_proxy
	echo "Hostkey $OBJ/agent-key.${k}" >> $OBJ/sshd_proxy
	opts="-oHostKeyAlgorithms=$k -F $OBJ/ssh_proxy"
	( printf 'localhost-with-alias,127.0.0.1,::1 ' ;
	  cat $OBJ/agent-key.$k.pub) > $OBJ/known_hosts
	SSH_CONNECTION=`${SSH} $opts host 'echo $SSH_CONNECTION'`
	if [ $? -ne 0 ]; then
		fail "key type $k privsep=$ps failed"
	fi
	if [ "$SSH_CONNECTION" != "UNKNOWN 65535 UNKNOWN 65535" ]; then
		fail "bad SSH_CONNECTION key type $k privsep=$ps"
	fi
done
done

SSH_CERTTYPES=`$SSH -Q key | grep 'cert-v01@openssh.com'`
SSH_CERTTYPES=`echo "$SSH_CERTTYPES" | sed 's/ssh-xmss-cert-v01@openssh.com//'` # TODO

# Prepare sshd_proxy for certificates.
cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
HOSTKEYALGS=""
for k in $SSH_CERTTYPES ; do
	if test -z "$HOSTKEYALGS" ; then
		HOSTKEYALGS="$k"
	else
		HOSTKEYALGS="$HOSTKEYALGS,$k"
	fi
done
for k in $PLAIN_TYPES ; do
	echo "Hostkey $OBJ/agent-key.${k}" >> $OBJ/sshd_proxy
	echo "HostCertificate $OBJ/agent-key.${k}-cert.pub" >> $OBJ/sshd_proxy
	test -f $OBJ/agent-key.${k}.pub || fatal "no $k key"
	test -f $OBJ/agent-key.${k}-cert.pub || fatal "no $k cert"
done
echo "HostKeyAlgorithms $HOSTKEYALGS" >> $OBJ/sshd_proxy
cp $OBJ/sshd_proxy $OBJ/sshd_proxy.orig

# Add only CA trust anchor to known_hosts.
( printf '@cert-authority localhost-with-alias ' ;
  cat $OBJ/agent-ca.pub) > $OBJ/known_hosts

for ps in $SSHD_PRIVSEP ; do
for k in $SSH_CERTTYPES ; do
	verbose "cert type $k privsep=$ps"
	cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
	echo "UsePrivilegeSeparation $ps" >> $OBJ/sshd_proxy
	opts="-oHostKeyAlgorithms=$k -F $OBJ/ssh_proxy"
	SSH_CONNECTION=`${SSH} $opts host 'echo $SSH_CONNECTION'`
	if test $? -ne 0 ; then
		fail "cert type $k privsep=$ps failed"
	fi
	if test "$SSH_CONNECTION" != "UNKNOWN 65535 UNKNOWN 65535" ; then
		fail "bad SSH_CONNECTION key type $k privsep=$ps"
	fi
done
done

verbose "multiple hostkeys"
cp $OBJ/sshd_proxy.orig $OBJ/sshd_proxy
cp $OBJ/ssh_proxy $OBJ/ssh_proxy.orig
grep -vi 'globalknownhostsfile' $OBJ/ssh_proxy.orig > $OBJ/ssh_proxy
echo "UpdateHostkeys=yes" >> $OBJ/ssh_proxy
echo "GlobalKnownHostsFile=none" >> $OBJ/ssh_proxy

> $OBJ/known_hosts
for k in $PLAIN_TYPES ; do
	verbose "  add key type $k"
	echo "Hostkey $OBJ/agent-key.${k}" >> $OBJ/sshd_proxy

	( printf 'localhost-with-alias ' ;
    cat $OBJ/agent-key.$k.pub) >> $OBJ/known_hosts
done

opts="-oStrictHostKeyChecking=yes -F $OBJ/ssh_proxy"
SSH_CONNECTION=`${SSH} $opts host 'echo $SSH_CONNECTION'`
if [ $? -ne 0 ]; then
	fail "connection to server with multiple hostkeys failed"
fi
if [ "$SSH_CONNECTION" != "UNKNOWN 65535 UNKNOWN 65535" ]; then
	fail "bad SSH_CONNECTION key while using multiple hostkeys"
fi

trace "kill agent"
${SSHAGENT} -k > /dev/null

rm $OBJ/agent-ca.pub
rm $OBJ/known_hosts
