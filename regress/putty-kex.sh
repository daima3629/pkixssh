#	$OpenBSD: putty-kex.sh,v 1.11 2024/02/09 08:56:59 dtucker Exp $
#	Placed in the Public Domain.

tid="putty KEX"

puttysetup

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

# NOTE: PuTTY tests are optional.
# Test uses predefined list of key-exchange algorithms.
# The list requires build with more recent OpenSSL library
# and test with recent PuTTY releases.
kex='dh-gex-sha1 dh-group1-sha1'
kex="$kex dh-group14-sha1 dh-group14-sha256"
kex="$kex dh-group16 dh-group18" # requires PuTTY 0.78
kex="$kex ecdh ecdh-256 ecdh-384 ecdh-521" # requires PuTTY 0.68
kex="$kex curve25519-sha256" # requires PuTTY 0.68

for k in $kex ; do
	verbose "$tid: kex $k"

	case $k in
	dh-gex-sha1)		sk=diffie-hellman-group-exchange-sha1;;
	dh-group1-sha1)		sk=diffie-hellman-group1-sha1;;
	dh-group14)		sk=diffie-hellman-group14-sha1;;
	dh-group14-sha1)	sk=diffie-hellman-group14-sha1;;
	dh-group14-sha256)	sk=diffie-hellman-group14-sha256;;
	dh-group16)		sk=diffie-hellman-group16-sha512;;
	dh-group18)		sk=diffie-hellman-group18-sha512;;
	ecdh)			sk=ecdh-sha2-nistp256;;
	ecdh-256)		sk=ecdh-sha2-nistp256;;
	ecdh-384)		sk=ecdh-sha2-nistp384;;
	ecdh-521)		sk=ecdh-sha2-nistp521;;
	curve25519-sha256)	sk=curve25519-sha256;;
	*) continue;;
	esac
	cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
	echo "KexAlgorithms $sk" >>$OBJ/sshd_proxy

	cp $PUTTYDIR/sessions/localhost_proxy \
	    $PUTTYDIR/sessions/kex_$k
	echo "KEX=$k" >> $PUTTYDIR/sessions/kex_$k

	env HOME=$PWD ${PLINK} -load kex_$k -batch -i ${OBJ}/putty.rsa2 true
	if [ $? -ne 0 ]; then
		fail "KEX $k failed"
	fi
done
