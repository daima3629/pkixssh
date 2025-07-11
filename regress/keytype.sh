#	$OpenBSD: keytype.sh,v 1.11 2021/02/25 03:27:34 djm Exp $
#	Placed in the Public Domain.

tid="login with different key types"

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak
cp $OBJ/ssh_proxy $OBJ/ssh_proxy_bak

config_defined HAVE_EVP_SHA256 && extra_algs=",rsa-sha2-*"

# Construct list of key types based on what the built binaries support.
ktypes=""
for i in ${SSH_KEYTYPES}; do
	case "$i" in
		ssh-dss)		ktypes="$ktypes dsa-1024" ;;
		ssh-rsa)		ktypes="$ktypes rsa-2048 rsa-3072" ;;
		ssh-ed25519)		ktypes="$ktypes ed25519-512" ;;
		ecdsa-sha2-nistp256)	ktypes="$ktypes ecdsa-256" ;;
		ecdsa-sha2-nistp384)	ktypes="$ktypes ecdsa-384" ;;
		ecdsa-sha2-nistp521)	ktypes="$ktypes ecdsa-521" ;;
	esac
done

for kt in $ktypes; do
	rm -f $OBJ/key.$kt
	bits=`echo ${kt} | awk -F- '{print $2}'`
	type=`echo ${kt} | awk -F- '{print $1}'`
	verbose "keygen $type, $bits bits"
	keytype_compat $type
	$SSHKEYGEN -b $bits -q -N '' $keytype_val -f $OBJ/key.$kt || \
		fail "ssh-keygen for type $type, $bits bits failed"
done

kname_to_ktype() {
	case $1 in
	dsa-1024)	echo ssh-dss;;
	ecdsa-256)	echo ecdsa-sha2-nistp256;;
	ecdsa-384)	echo ecdsa-sha2-nistp384;;
	ecdsa-521)	echo ecdsa-sha2-nistp521;;
	ed25519-512)	echo ssh-ed25519;;
	rsa-*)		echo ssh-rsa$extra_algs;;
	esac
}

tries="1 2 3"
for ut in $ktypes; do
	user_type=`kname_to_ktype "$ut"`
	htypes=$ut
	#htypes=$ktypes
	for ht in $htypes; do
		host_type=`kname_to_ktype "$ht"`
		trace "ssh connect, userkey $ut, hostkey $ht"
		(
			grep -v HostKey $OBJ/sshd_proxy_bak
			echo HostKey $OBJ/key.$ht
			echo PubkeyAcceptedAlgorithms $user_type
			echo HostKeyAlgorithms $host_type
		) > $OBJ/sshd_proxy
		(
			grep -v IdentityFile $OBJ/ssh_proxy_bak
			echo IdentityFile $OBJ/key.$ut
			echo PubkeyAcceptedAlgorithms $user_type
			echo HostKeyAlgorithms $host_type
		) > $OBJ/ssh_proxy
		(
			printf 'localhost-with-alias,127.0.0.1,::1 '
			cat $OBJ/key.$ht.pub
		) > $OBJ/known_hosts
		cat $OBJ/key.$ut.pub > $OBJ/authorized_keys_$USER
		for i in $tries; do
			verbose "userkey $ut, hostkey ${ht}"
			${SSH} -F $OBJ/ssh_proxy 999.999.999.999 true
			if [ $? -ne 0 ]; then
				fail "ssh userkey $ut, hostkey $ht failed"
			fi
		done
	done
done
