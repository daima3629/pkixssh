#	$OpenBSD: forcecommand.sh,v 1.5 2023/05/12 06:36:27 djm Exp $
#	Placed in the Public Domain.

tid="forced command"

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

authorized_keys() {
	cmd=$1
	cp /dev/null $OBJ/authorized_keys_$USER
	for t in ${SSH_KEYTYPES}; do
		test -z "$cmd" || \
			printf "command=\"$cmd\" " >>$OBJ/authorized_keys_$USER
		cat $OBJ/$t.pub >> $OBJ/authorized_keys_$USER
	done
}

trace "forced command in key option"
authorized_keys true
${SSH} -F $OBJ/ssh_proxy somehost false || fail "forced command in key option"

cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
echo "ForceCommand true" >> $OBJ/sshd_proxy

trace "forced command in sshd_config overrides key option"
authorized_keys false
${SSH} -F $OBJ/ssh_proxy somehost false || fail "forced command config"

authorized_keys
cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
echo "ForceCommand false" >> $OBJ/sshd_proxy
echo "Match User $USER" >> $OBJ/sshd_proxy
echo "    ForceCommand true" >> $OBJ/sshd_proxy

trace "forced command with match"
${SSH} -F $OBJ/ssh_proxy somehost false || fail "forced command match"
