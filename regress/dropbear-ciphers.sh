#	$OpenBSD: dropbear-ciphers.sh,v 1.3 2024/06/20 08:23:18 dtucker Exp $
#	Placed in the Public Domain.

tid="dropbear ciphers"

$REGRESS_INTEROP_DROPBEAR || { RESULT=1; skip "dropbear interop tests are not enabled"; }

ciphers=`$DBCLIENT -c help somehost 2>&1 | awk '/ ciphers: /{print $4}' | tr ',' ' '`
macs=`$DBCLIENT -m help somehost 2>&1 | awk '/ MACs: /{print $4}' | tr ',' ' '`
if test -z "$macs" -o -z "$ciphers" ; then
	skip "dbclient query ciphers or macs failed"
fi

rm -f $OBJ/.dropbear/dbclient.log
for c in $ciphers ; do
  for m in $macs; do
    for i in $OBJ/.dropbear/id_* ; do
      kt=`echo $i | sed -e 's/.*id_//'`
      verbose "$tid: cipher $c mac $m kt $kt"
      rm -f $COPY

      dbclient -i $i -c $c -m $m somehost \
        cat $DATA > $COPY 2>>$OBJ/.dropbear/dbclient.log
      if test $? -ne 0 ; then
        fail "ssh cat $DATA failed"
      fi
      cmp $DATA $COPY || fail "corrupted copy"
    done
  done
done
rm -f $COPY
