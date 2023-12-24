#	$OpenBSD: agent-pkcs11.sh,v 1.13 2023/10/30 23:00:25 djm Exp $
#	Placed in the Public Domain.

tid="pkcs11 agent test"

. ../tests/pkcs11-env
p11_find_module || skip "SoftHSM module not found"
p11_find_SOFTHSM2_TOOL || skip "SoftHSM tool not found"
p11_setup

# generate keys and loads them into the virtual token
# NOTE: require OpenSSL 1.0+ utility genpkey
RSA=$SSH_SOFTHSM_DIR/RSA
EC=$SSH_SOFTHSM_DIR/EC
p11_genkeys() {
	out=`$SOFTHSM2_TOOL --init-token --free --label token-slot-0 --pin "$TEST_SSH_PIN" --so-pin "$TEST_SSH_SOPIN"`
	slot=`echo -- $out | sed 's/.* //'`

	# RSA key
	RSAP8=$SSH_SOFTHSM_DIR/RSAP8
	$OPENSSL genpkey -algorithm rsa > $RSA 2>/dev/null || \
	    fatal "genpkey RSA fail"
	$OPENSSL pkcs8 -nocrypt -in $RSA > $RSAP8 || fatal "pkcs8 RSA fail"
	$SOFTHSM2_TOOL --slot "$slot" --label 01 --id 01 --pin "$TEST_SSH_PIN" \
	    --import $RSAP8 >/dev/null || fatal "softhsm import RSA fail"
	chmod 600 $RSA
	ssh-keygen -y -f $RSA > ${RSA}.pub

	# ECDSA key
	ECPARAM=$SSH_SOFTHSM_DIR/ECPARAM
	ECP8=$SSH_SOFTHSM_DIR/ECP8
	$OPENSSL genpkey -genparam -algorithm ec \
	    -pkeyopt ec_paramgen_curve:prime256v1 > $ECPARAM || \
	    fatal "param EC fail"
	$OPENSSL genpkey -paramfile $ECPARAM > $EC || \
	    fatal "genpkey EC fail"
	$OPENSSL pkcs8 -nocrypt -in $EC > $ECP8 || fatal "pkcs8 EC fail"
	$SOFTHSM2_TOOL --slot "$slot" --label 02 --id 02 --pin "$TEST_SSH_PIN" \
	    --import $ECP8 >/dev/null || fatal "softhsm import EC fail"
	chmod 600 $EC
	ssh-keygen -y -f $EC > ${EC}.pub
}


trace "start agent"
eval `${SSHAGENT} ${EXTRA_AGENT_ARGS} -s` > /dev/null
r=$?
if [ $r -ne 0 ]; then
	fail "could not start ssh-agent: exit code $r"
else
	trace "generating keys"
	p11_genkeys

	trace "add pkcs11 key to agent"
	p11_ssh_add -s ${TEST_SSH_PKCS11} > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -s failed: exit code $r"
	fi

	trace "pkcs11 list via agent"
	${SSHADD} -l > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -l failed: exit code $r"
	fi

	for k in $RSA $EC; do
		trace "testing $k"
		pub=$(cat $k.pub)
		${SSHADD} -L | grep -q "$pub" || \
			fail "key $k missing in ssh-add -L"
		${SSHADD} -T $k.pub || fail "ssh-add -T with $k failed"

		# add to authorized keys
		cat $k.pub > $OBJ/authorized_keys_$USER
		trace "pkcs11 connect via agent ($k)"
		${SSH} -F $OBJ/ssh_proxy somehost exit 5
		r=$?
		if [ $r -ne 5 ]; then
			fail "ssh connect failed (exit code $r)"
		fi
	done

	trace "remove pkcs11 keys"
	p11_ssh_add -e ${TEST_SSH_PKCS11} > /dev/null 2>&1
	r=$?
	if [ $r -ne 0 ]; then
		fail "ssh-add -e failed: exit code $r"
	fi

	trace "kill agent"
	${SSHAGENT} -k > /dev/null
fi
