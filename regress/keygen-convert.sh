#	$OpenBSD: keygen-convert.sh,v 1.6 2021/07/24 02:57:28 dtucker Exp $
#	Placed in the Public Domain.

tid="convert keys"

cat > $OBJ/askpass <<EOD
#! $TEST_SHELL
echo hunter2
EOD
chmod u+x $OBJ/askpass

do_test() {
	fmt=$1
	msg=$2
	sfx=$3

	case $fmt in
	PKCS8)
		case $t in
		ed25519)
			config_defined OPENSSL_HAS_ED25519 ||
			return;;
		esac
		;;
	esac

	trace "export $t private to $msg public"
	${SSHKEYGEN} -q -e -m $fmt -f $OBJ/$t-key >$OBJ/$t-key-$sfx || \
	    fail "export $t private to rfc4716 public"

	trace "export $t public to $msg public"
	${SSHKEYGEN} -q -e -m $fmt -f $OBJ/$t-key.only-pub >$OBJ/$t-key-$sfx.pub || \
	    fail "$t public to $msg public"

	cmp $OBJ/$t-key-$sfx $OBJ/$t-key-$sfx.pub > /dev/null || \
	    fail "$t $msg exports differ between public and private"

	trace "import $t $msg public"
	${SSHKEYGEN} -q -i -m $fmt -f $OBJ/$t-key-$sfx >$OBJ/$t-$sfx-imported || \
	    fail "$t import $msg public"

	cmp $OBJ/$t-key-nocomment.pub $OBJ/$t-$sfx-imported > /dev/null || \
	    fail "$t $msg imported differs from original"

	rm -f $OBJ/$t-key-$sfx $OBJ/$t-key-$sfx.pub $OBJ/$t-$sfx-imported
}

do_test_askpass() {
	e=$t-key-nocomment.pub
	case $t in
	ed25519)
		config_defined OPENSSL_HAS_ED25519 ||
		e=$t-key.only-pub;;
	esac

	trace "set passphrase $t"
	${SSHKEYGEN} -q -p -P '' -N 'hunter2' -f $OBJ/$t-key >/dev/null || \
	    fail "$t set passphrase failed"

	trace "export $t to public with passphrase"
	SSH_ASKPASS=$OBJ/askpass SSH_ASKPASS_REQUIRE=force \
	    ${SSHKEYGEN} -y -f $OBJ/$t-key >$OBJ/$t-key-askpass.pub
	cmp $OBJ/$t-key-askpass.pub $OBJ/$e || \
	    fail "$t exported pubkey differs from generated"
}

for i in ${SSH_KEYTYPES}; do
	case "$i" in
	ssh-rsa)		t=rsa;     type="-t rsa" ;;
	ecdsa-sha2-nistp256)	t=ec_p256; type="-t ecdsa -b 256" ;;
	ecdsa-sha2-nistp384)	t=ec_p384; type="-t ecdsa -b 384" ;;
	ecdsa-sha2-nistp521)	t=ec_p521; type="-t ecdsa -b 521" ;;
	ssh-ed25519)		t=ed25519; type="-t ed25519" ;;
	ssh-dss)		t=dsa;     type="-t dsa" ;;
	*) continue ;;
	esac

	# generate user key for import/export
	trace "generating $t key"
	rm -f $OBJ/$t-key
	${SSHKEYGEN} -q -N "" $type -f $OBJ/$t-key
	mv $OBJ/$t-key.pub $OBJ/$t-key.only-pub
	cut -f1,2 -d " " $OBJ/$t-key.only-pub >$OBJ/$t-key-nocomment.pub

	do_test RFC4716 "rfc4716" rfc
	do_test PKCS8 "pkcs#8" pk8

	do_test_askpass

	rm -f $OBJ/$t-key $OBJ/$t-key.only-pub \
	    $OBJ/$t-key-askpass.pub $OBJ/$t-key-nocomment.pub
done
