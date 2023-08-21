#	$OpenBSD: keygen-sshfp.sh,v 1.3 2023/02/10 05:06:03 djm Exp $
#	Placed in the Public Domain.

tid="keygen-sshfp"

trace "keygen fingerprints"

# Expect N lines of output without an explicit algorithm
if config_defined HAVE_EVP_SHA256 ; then
	N=2
else
	N=1
fi
fp=`${SSHKEYGEN} -r test -f ${SRC}/ed25519_openssh.pub | wc -l`
fp=`echo $fp` # avoid wc indentation
if test "x$fp" != "x$N" ; then
	fail "incorrect number of SSHFP records $fp (expected 2)"
fi

# Test explicit algorithm selection
exp="test IN SSHFP 4 1 8a8647a7567e202ce317e62606c799c53d4c121f"
fp=`${SSHKEYGEN} -Ohashalg=sha1 -r test -f ${SRC}/ed25519_openssh.pub`
if test "x$exp" != "x$fp" ; then
	fail "incorrect SHA1 SSHFP output"
fi

if config_defined HAVE_EVP_SHA256 ; then
exp="test IN SSHFP 4 2 54a506fb849aafb9f229cf78a94436c281efcb4ae67c8a430e8c06afcb5ee18f"
fp=`${SSHKEYGEN} -Ohashalg=sha256 -r test -f ${SRC}/ed25519_openssh.pub`
if test "x$exp" != "x$fp" ; then
	fail "incorrect SHA256 SSHFP output"
fi
fi

for k in $SSH_KEYTYPES ; do
	case $k in
	ssh-ed25519)
	N=ed25519;
	fp1='8a8647a7567e202ce317e62606c799c53d4c121f';
	fp2='54a506fb849aafb9f229cf78a94436c281efcb4ae67c8a430e8c06afcb5ee18f';
	;;
	ssh-rsa)
	N=rsa;
	fp1='99c79cc09f5f81069cc017cdf9552cfc94b3b929';
	fp2='e30d6b9eb7a4de495324e4d5870b8220577993ea6af417e8e4a4f1c5bf01a9b6';
	;;
	*)
	continue
	;;
	esac
	res=`${SSHKEYGEN} -r test -f ${SRC}/${N}_openssh.pub`
	fp=`echo "$res" | awk '$5=="1" { print $6 }'`
	if test "x$fp" != "x$fp1" ; then
		fail "keygen fingerprint sha1 for keytype $k"
	fi
	config_defined HAVE_EVP_SHA256 || continue
	fp=`echo "$res" | awk '$5=="2" { print $6 }'`
	if test "x$fp" != "x$fp2" ; then
		fail "keygen fingerprint sha256 for keytype $k"
	fi
done
