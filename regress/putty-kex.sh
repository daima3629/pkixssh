#	$OpenBSD: putty-kex.sh,v 1.11 2024/02/09 08:56:59 dtucker Exp $
#	Placed in the Public Domain.

tid="putty KEX"

puttysetup

for k in dh-gex-sha1 dh-group1-sha1 dh-group14-sha1 ecdh ; do
	verbose "$tid: kex $k"
	cp $PUTTYDIR/sessions/localhost_proxy \
	    $PUTTYDIR/sessions/kex_$k
	echo "KEX=$k" >> $PUTTYDIR/sessions/kex_$k

	env HOME=$PWD ${PLINK} -load kex_$k -batch -i ${OBJ}/putty.rsa2 true
	if [ $? -ne 0 ]; then
		fail "KEX $k failed"
	fi
done
