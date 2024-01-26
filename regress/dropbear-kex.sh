#	$OpenBSD: dropbear-kex.sh,v 1.1 2023/10/20 06:56:45 dtucker Exp $
#	Placed in the Public Domain.

tid="dropbear kex"

$REGRESS_INTEROP_DROPBEAR || { RESULT=1; skip "dropbear interop tests are not enabled"; }

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

kex="curve25519-sha256 curve25519-sha256@libssh.org
    diffie-hellman-group14-sha256 diffie-hellman-group14-sha1"

rm -f $OBJ/.dropbear/dbclient.log
for k in $kex; do
  verbose "$tid: kex $k"
  rm -f $COPY

  # dbclient does not have switch for kex, so force in server
  (
  cat $OBJ/sshd_proxy_bak
  echo "KexAlgorithms $k"
  ) > $OBJ/sshd_proxy

  dbclient -i $OBJ/.dropbear/id_ed25519 somehost \
    cat $DATA > $COPY 2>>$OBJ/.dropbear/dbclient.log
  if test $? -ne 0 ; then
    fail "ssh cat $DATA failed"
  fi
  cmp $DATA $COPY || fail "corrupted copy"
done
rm -f $COPY
