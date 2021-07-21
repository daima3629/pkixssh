#	$OpenBSD: keygen-sshfp.sh,v 1.2 2021/07/19 02:29:28 dtucker Exp $
#	Placed in the Public Domain.

tid="keygen-sshfp"

trace "keygen fingerprints"
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
