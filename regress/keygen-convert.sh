#	$OpenBSD: keygen-convert.sh,v 1.2 2019/07/23 07:55:29 dtucker Exp $
#	Placed in the Public Domain.

tid="convert keys"

do_test() {
	fmt=$1
	msg=$2
	sfx=$3

	case $fmt in
	PKCS8)
	  case $t in
	  rsa|ec_p*|dsa);;
	  ed25519)
		config_defined OPENSSL_HAS_ED25519 ||
		return;;
	  *) return;;
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

	rm -f $OBJ/$t-key $OBJ/$t-key.only-pub $OBJ/$t-key-nocomment.pub
done
