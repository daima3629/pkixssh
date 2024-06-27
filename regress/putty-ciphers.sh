#	$OpenBSD: putty-ciphers.sh,v 1.13 2024/02/09 08:56:59 dtucker Exp $
#	Placed in the Public Domain.

tid="putty ciphers"

puttysetup

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

# NOTE: PuTTY tests are optional.
# Test uses predefined list of macs.
# The list requires build with more recent OpenSSL library
# and test with recent PuTTY releases.
macs='hmac-sha1 hmac-sha1-96 hmac-sha2-256'
macs="$macs hmac-sha2-512" # requires PuTTY 0.79

# Test uses predefined list of ciphers.
# The list requires build with more recent OpenSSL library
# and test with recent PuTTY releases.
ciphers='3des chacha20'
ciphers="$ciphers aes"
ciphers="$ciphers aes128-ctr aes192-ctr aes256-ctr"
ciphers="$ciphers aes128-gcm aes256-gcm"

for c in default $ciphers ; do
    for m in default $macs ; do
	verbose "$tid: cipher $c, server mac $m"
	cp $PUTTYDIR/sessions/localhost_proxy \
	    $PUTTYDIR/sessions/cipher_$c
	if test "x$c" != "xdefault" ; then
		echo "Cipher=$c" >> $PUTTYDIR/sessions/cipher_$c
	fi

	# PuTTY lacks client options to set mac.
	# Set it on server side.
	cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
	if test "x$m" != "xdefault" ; then
		echo "MACs $m" >> $OBJ/sshd_proxy
	fi

	rm -f ${COPY}
	env HOME=$PWD ${PLINK} -load cipher_$c -batch -i ${OBJ}/putty.rsa2 \
	    cat ${DATA} > ${COPY}
	if [ $? -ne 0 ]; then
		fail "ssh cat $DATA failed"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
    done
done
rm -f ${COPY}
