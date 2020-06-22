#	$OpenBSD: keygen-convert.sh,v 1.2 2019/07/23 07:55:29 dtucker Exp $
#	Placed in the Public Domain.

tid="convert keys"

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

	trace "export $t private to rfc4716 public"
	${SSHKEYGEN} -q -e -f $OBJ/$t-key >$OBJ/$t-key-rfc || \
	    fail "export $t private to rfc4716 public"

	trace "export $t public to rfc4716 public"
	${SSHKEYGEN} -q -e -f $OBJ/$t-key.pub >$OBJ/$t-key-rfc.pub || \
	    fail "$t public to rfc4716 public"

	cmp $OBJ/$t-key-rfc $OBJ/$t-key-rfc.pub || \
	    fail "$t rfc4716 exports differ between public and private"

	trace "import $t rfc4716 public"
	${SSHKEYGEN} -q -i -f $OBJ/$t-key-rfc >$OBJ/$t-rfc-imported || \
	    fail "$t import rfc4716 public"

	cut -f1,2 -d " " $OBJ/$t-key.pub >$OBJ/$t-key-nocomment.pub
	cmp $OBJ/$t-key-nocomment.pub $OBJ/$t-rfc-imported || \
	    fail "$t imported differs from original"

	rm -f $OBJ/$t-key $OBJ/$t-key.pub $OBJ/$t-key-rfc $OBJ/$t-key-rfc.pub \
	    $OBJ/$t-rfc-imported $OBJ/$t-key-nocomment.pub
done
