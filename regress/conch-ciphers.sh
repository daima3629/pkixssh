#	$OpenBSD: conch-ciphers.sh,v 1.7 2023/10/26 12:44:07 dtucker Exp $
#	Placed in the Public Domain.

tid="conch ciphers"

$REGRESS_INTEROP_CONCH || { RESULT=1; skip "conch interop tests are not enabled"; }
echo "CONCH: $CONCH" >&2

start_sshd

for c in aes256-ctr aes256-cbc aes192-ctr aes192-cbc aes128-ctr aes128-cbc \
         cast128-cbc blowfish 3des-cbc ; do
	verbose "$tid: cipher $c"
	rm -f ${COPY}
	${CONCH} --identity $SSH_ID_CONCH --port $PORT --user $USER --escape none \
	    --known-hosts $OBJ/known_hosts --notty --noagent --nox11 --null \
	    127.0.0.1 "cat ${DATA}" > ${COPY}
	if [ $? -ne 0 ]; then
		fail "ssh cat $DATA failed"
		continue
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
done

stop_sshd

rm -f ${COPY}

