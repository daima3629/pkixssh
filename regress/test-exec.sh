#	$OpenBSD: test-exec.sh,v 1.127 2025/03/28 05:41:15 dtucker Exp $
#	Placed in the Public Domain.

#SUDO=sudo

# NOTE: OBJ is environment variable as well
OBJ="$1"
if test -z "$OBJ" ; then
	echo 'build directory is not specified'
	exit 2
fi
if test ! -d "$OBJ" ; then
	echo "not a directory: $OBJ"
	exit 2
fi
SCRIPT="$2"
if test -z "$SCRIPT" ; then
	echo 'test script is not specified'
	exit 2
fi
if test ! -f "$SCRIPT" ; then
	echo "not a file: $SCRIPT"
	exit 2
fi


. ../tests/compat
. $OBJ/../tests/env
TEST_SHELL=${TEST_SHELL-/bin/sh}

if test -n "$TEST_SSH_ELAPSED_TIME" ; then
	STARTTIME=`date -u '+%s'`
fi

PORT=${TEST_SSH_PORT-4242}

case $TEST_SHELL in
	*zsh*)	# turn on NULL_GLOB
		$TEST_SHELL -G -n $SCRIPT;;
	*)
		$TEST_SHELL -n $SCRIPT;;
esac
ret=$?
if test 0 -eq $ret; then
	:
else
	echo "syntax error in $SCRIPT"
	exit 2
fi
unset SSH_AUTH_SOCK || :

# Platform-specific settings.

if test -x "/usr/xpg4/bin/id" ; then
id() {
  /usr/xpg4/bin/id ${1+"$@"}
}
fi

if test -x /usr/ucb/whoami ; then
	USER=`/usr/ucb/whoami`
elif whoami >/dev/null 2>&1; then
	USER=`whoami`
elif logname >/dev/null 2>&1; then
	USER=`logname`
else
	USER=`id -un`
fi
if test -z "$LOGNAME"; then
	LOGNAME="$USER"
	export LOGNAME
fi

# Unbreak GNU head(1)
_POSIX2_VERSION=199209
export _POSIX2_VERSION

case `uname -s 2>/dev/null` in
OSF1*)
	BIN_SH=xpg4
	export BIN_SH
	;;
CYGWIN*)
	os=cygwin
	;;
esac


# wrappers to programs found by configure script
egrep() {
  $EGREP ${1+"$@"}
}

fgrep() {
  $FGREP ${1+"$@"}
}

awk() {
  $AWK ${1+"$@"}
}


SRC=`dirname ${SCRIPT}`

# defaults
SSH=ssh
SSHD=sshd
SSHAGENT=ssh-agent
SSHADD=ssh-add
SSHKEYGEN=ssh-keygen
SSHKEYSCAN=ssh-keyscan
SFTP=sftp
SFTPSERVER=/usr/libexec/openssh/sftp-server
SCP=scp

SSHD_PRIVSEP=${SSHD_PRIVSEP-yes no sandbox}
SCP_MODES=${SCP_MODES-scp sftp}

# Set by make_tmpdir() on demand (below).
SSH_REGRESS_TMP=

# Interop testing
PLINK=${PLINK-plink}
PUTTYGEN=${PUTTYGEN-puttygen}
CONCH=${CONCH-conch}
DROPBEAR=${DROPBEAR-dropbear}
DBCLIENT=${DBCLIENT-dbclient}
DROPBEARKEY=${DROPBEARKEY-dropbearkey}
DROPBEARCONVERT=${DROPBEARCONVERT-dropbearconvert}
PLINK=`which $PLINK 2>/dev/null`
PUTTYGEN=`which $PUTTYGEN 2>/dev/null`
CONCH=`which $CONCH 2>/dev/null`
DROPBEAR=`which $DROPBEAR 2>/dev/null`
DBCLIENT=`which $DBCLIENT 2>/dev/null`
DROPBEARKEY=`which $DROPBEARKEY 2>/dev/null`
DROPBEARCONVERT=`which $DROPBEARCONVERT 2>/dev/null`

# Tools used by multiple tests
NC=$OBJ/netcat
OPENSSL=${OPENSSL-openssl}
OPENSSL=`which $OPENSSL 2>/dev/null`
test -n "$OPENSSL" && export OPENSSL

if [ "x$TEST_SSH_SSH" != "x" ]; then
	SSH="${TEST_SSH_SSH}"
fi
if [ "x$TEST_SSH_SSHD" != "x" ]; then
	SSHD="${TEST_SSH_SSHD}"
fi
if [ "x$TEST_SSH_SSHAGENT" != "x" ]; then
	SSHAGENT="${TEST_SSH_SSHAGENT}"
fi
if [ "x$TEST_SSH_SSHADD" != "x" ]; then
	SSHADD="${TEST_SSH_SSHADD}"
fi
if [ "x$TEST_SSH_SSHKEYGEN" != "x" ]; then
	SSHKEYGEN="${TEST_SSH_SSHKEYGEN}"
fi
if [ "x$TEST_SSH_SSHKEYSCAN" != "x" ]; then
	SSHKEYSCAN="${TEST_SSH_SSHKEYSCAN}"
fi
if [ "x$TEST_SSH_SFTP" != "x" ]; then
	SFTP="${TEST_SSH_SFTP}"
fi
if [ "x$TEST_SSH_SFTPSERVER" != "x" ]; then
	SFTPSERVER="${TEST_SSH_SFTPSERVER}"
fi
if [ "x$TEST_SSH_SCP" != "x" ]; then
	SCP="${TEST_SSH_SCP}"
fi
if [ "x$TEST_SSH_SSHPKCS11HELPER" != "x" ]; then
	SSH_PKCS11_HELPER="${TEST_SSH_SSHPKCS11HELPER}"
fi

# Path to sshd must be absolute for rexec
case "$SSHD" in
/*) ;;
*) SSHD=`which $SSHD` ;;
esac

case "$SSH" in
/*) ;;
*) SSH=`which $SSH` ;;
esac

case "$SSHAGENT" in
/*) ;;
*) SSHAGENT=`which $SSHAGENT` ;;
esac

# Record the actual binaries used.
SSH_BIN=${SSH}
SSHD_BIN=${SSHD}
SSHAGENT_BIN=${SSHAGENT}
SSHADD_BIN=${SSHADD}
SSHKEYGEN_BIN=${SSHKEYGEN}
SSHKEYSCAN_BIN=${SSHKEYSCAN}
SFTP_BIN=${SFTP}
SFTPSERVER_BIN=${SFTPSERVER}
SCP_BIN=${SCP}

if [ "x$USE_VALGRIND" != "x" ]; then
	rm -rf $OBJ/valgrind-out $OBJ/valgrind-vgdb
	mkdir -p $OBJ/valgrind-out $OBJ/valgrind-vgdb
	# When using sudo ensure low-priv tests can write pipes and logs.
	if test -n "$SUDO" ; then
		chmod 777 $OBJ/valgrind-out $OBJ/valgrind-vgdb
	fi
	VG_TEST=`basename $SCRIPT .sh`

	# Some tests are difficult to fix.
	case "$VG_TEST" in
	reexec)
		VG_SKIP=1 ;;
	sftp-chroot)
		if test -n "$SUDO" ; then
			VG_SKIP=1
		fi ;;
	esac

	if [ x"$VG_SKIP" = "x" ]; then
		VG_LEAK="--leak-check=no"
		if [ x"$VALGRIND_CHECK_LEAKS" != "x" ]; then
			VG_LEAK="--leak-check=full"
		fi
		VG_IGNORE="/bin/*,/sbin/*,/usr/*,/var/*"
		VG_LOG="$OBJ/valgrind-out/${VG_TEST}."
		VG_OPTS="--track-origins=yes $VG_LEAK"
		VG_OPTS="$VG_OPTS --trace-children=yes"
		VG_OPTS="$VG_OPTS --trace-children-skip=${VG_IGNORE}"
		VG_OPTS="$VG_OPTS --vgdb-prefix=$OBJ/valgrind-vgdb/"
		VG_PATH="valgrind"
		if [ "x$VALGRIND_PATH" != "x" ]; then
			VG_PATH="$VALGRIND_PATH"
		fi
		VG="$VG_PATH $VG_OPTS"
		SSH="$VG --log-file=${VG_LOG}ssh.%p $SSH"
		SSHD="$VG --log-file=${VG_LOG}sshd.%p $SSHD"
		SSHAGENT="$VG --log-file=${VG_LOG}ssh-agent.%p $SSHAGENT"
		SSHADD="$VG --log-file=${VG_LOG}ssh-add.%p $SSHADD"
		SSHKEYGEN="$VG --log-file=${VG_LOG}ssh-keygen.%p $SSHKEYGEN"
		SSHKEYSCAN="$VG --log-file=${VG_LOG}ssh-keyscan.%p $SSHKEYSCAN"
		SFTP="$VG --log-file=${VG_LOG}sftp.%p ${SFTP}"
		SCP="$VG --log-file=${VG_LOG}scp.%p $SCP"
		cat > $OBJ/valgrind-sftp-server.sh << EOF
#! $TEST_SHELL
exec $VG --log-file=${VG_LOG}sftp-server.%p $SFTPSERVER \${1+"\$@"}
EOF
		chmod a+rx $OBJ/valgrind-sftp-server.sh
		SFTPSERVER="$OBJ/valgrind-sftp-server.sh"
	fi
fi

# Logfiles.
# SSH_LOGFILE should be the debug output of ssh(1) only
# SSHD_LOGFILE should be the debug output of sshd(8) only
# REGRESS_LOGFILE is the output of the test itself stdout and stderr
if [ "x$TEST_SSH_LOGFILE" = "x" ]; then
	TEST_SSH_LOGFILE=$OBJ/ssh.log
fi
if [ "x$TEST_SSHD_LOGFILE" = "x" ]; then
	TEST_SSHD_LOGFILE=$OBJ/sshd.log
fi
if [ "x$TEST_REGRESS_LOGFILE" = "x" ]; then
	TEST_REGRESS_LOGFILE=$OBJ/regress.log
fi

# If set, keep track of successful tests and skip them them if we've
# previously completed that test.
if test "x$TEST_REGRESS_CACHE_DIR" != "x" ; then
	$SRC/../install-sh -d "$TEST_REGRESS_CACHE_DIR"
	TEST="${SCRIPT##*/}"
	TEST="${TEST%.sh}"
	CACHE="$TEST_REGRESS_CACHE_DIR/$TEST.pass"
	for i in ${SSH} ${SSHD} ${SSHAGENT} ${SSHADD} ${SSHKEYGEN} ${SCP} \
	    ${SFTP} ${SFTPSERVER} ${SSHKEYSCAN}; do
		bin="`which $i`"
		if test "$bin" -nt "$CACHE" ; then
			rm -f "$CACHE"
		fi
	done
	if test -f "$CACHE" ; then
		echo "ok $TEST (cached) - $CACHE" >&2
		exit 0
	fi
fi

# truncate logfiles
echo "=== $SCRIPT ..." > $TEST_SSH_LOGFILE
>$TEST_SSHD_LOGFILE
>$TEST_REGRESS_LOGFILE

# Create wrapper ssh with logging.  We can not just specify "SSH=ssh -E..."
# because sftp and scp do not handle spaces in arguments.
# Some tests use -q so wrapper remove argument to preserve debug logging.
# In the rare instance where -q is desirable -qq is equivalent and is not
# removed.
SSHLOGWRAP=$OBJ/ssh-log-wrapper.sh
cat > $SSHLOGWRAP <<EOF
#! $TEST_SHELL

for o in \${1+"\$@"} ; do
  shift
  case "\$o" in
  -q) : ;;
  *) set -- \${1+"\$@"} "\$o" ;;
  esac
done

echo Executing: $SSH \${1+"\$@"} >>$TEST_SSH_LOGFILE
exec $SSH -E$TEST_SSH_LOGFILE \${1+"\$@"}
EOF
chmod a+rx $OBJ/ssh-log-wrapper.sh

REAL_SSH="$SSH"
REAL_SSHD="$SSHD"
SSH="$SSHLOGWRAP"

if "$REAL_SSHD" -? 2>&1 | grep 'PKIX-SSH' > /dev/null; then
  sshd_type=pkix
else
  sshd_type=other
fi

# Some test data.  We make a copy because some tests will overwrite it.
# The tests may assume that $DATA exists and is writable and $COPY does
# not exist.  Tests requiring larger data files can call increase_datafile_size
# [kbytes] to ensure the file is at least that large.
DATANAME=data
DATA=$OBJ/${DATANAME}
cat ${SSH_BIN} >${DATA}
chmod u+w ${DATA}
COPY=$OBJ/copy
rm -f ${COPY}

increase_datafile_size()
{
	while [ `du -k ${DATA} | cut -f1` -lt $1 ]; do
		cat ${SSH_BIN} >>${DATA}
	done
}

# these should be used in tests
export SSH SSHD SSHAGENT SSHADD SSHKEYGEN SSHKEYSCAN SFTP SFTPSERVER SCP
#echo $SSH $SSHD $SSHAGENT $SSHADD $SSHKEYGEN $SSHKEYSCAN $SFTP $SFTPSERVER $SCP
# these should be used by executables
export SSH_PKCS11_HELPER

# NOTE: always unset OPENSSL_FIPS even for build with FIPS
# capable OpenSSL library. It will be set latter only if
# fips test is requested.
unset OPENSSL_FIPS || :

# Portable specific functions
have_prog()
{
	which "$1" >/dev/null 2>&1
}

jot() {
	awk "BEGIN { for (i = $2; i < $2 + $1; i++) { printf \"%d\n\", i } exit }"
}

# cross-project configuration
# $1: ssh-keygen key type
keytype_compat() {
	keytype_val="-t $1"
	if test "$sshd_type" != "pkix" ; then
		case "$1" in
		*25519*) keytype_val="$keytype_val -m OpenSSH"
		esac
	fi
}

# Check whether preprocessor symbols are defined in config.h.
config_defined ()
{
	str=$1
	while test "x$2" != "x" ; do
		str="$str|$2"
		shift
	done
	egrep "^#define.*($str)" ${BUILDDIR}/config.h >/dev/null 2>&1
}

md5 () {
	if have_prog md5sum; then
		md5sum
	elif test -x "$OPENSSL" ; then
		$OPENSSL md5
	elif have_prog cksum; then
		cksum
	elif have_prog sum; then
		sum
	else
		wc -c
	fi
}

make_tmpdir ()
{
	SSH_REGRESS_TMP="`$OBJ/mkdtemp ssh-regress-XXXXXXXXXX`" || \
	    fatal "failed to create temporary directory"
}
# End of portable specific functions

stop_sshd ()
{
	test -f $PIDFILE || return

	pid=`$SUDO cat $PIDFILE`
	if test "X$pid" = "X" ; then
		echo "no sshd running" >&2
		return
	fi
	if test $pid -lt 2 ; then
		echo "bad pid for sshd: $pid" >&2
		return
	fi

	$SUDO kill $pid
	trace "wait for sshd to exit"
	i=0;
	while [ -f $PIDFILE -a $i -lt 5 ]; do
		i=`expr $i + 1`
		sleep $i
	done
	if test -f $PIDFILE; then
		if $SUDO kill -0 $pid; then
			echo "sshd didn't exit port $PORT pid $pid" >&2
		else
			echo "sshd died without cleanup" >&2
		fi
		exit 1
	fi
}

# helper
cleanup ()
{
	if [ "x$SSH_PID" != "x" ]; then
		if [ $SSH_PID -lt 2 ]; then
			echo bad pid for ssh: $SSH_PID
		else
			kill $SSH_PID
		fi
	fi
	if [ "x$SSH_REGRESS_TMP" != "x" ]; then
		rm -rf "$SSH_REGRESS_TMP"
	fi
	stop_sshd
	if test -n "$TEST_SSH_ELAPSED_TIME" ; then
		now=`date -u '+%s'`
		elapsed=$(($now - $STARTTIME))
		echo "- ${SCRIPT##*/} elapsed time: $elapsed"
	fi
}

start_debug_log ()
{
	echo "begin: $@" >$TEST_REGRESS_LOGFILE
	echo "begin: $@" >$TEST_SSH_LOGFILE
	echo "begin: $@" >$TEST_SSHD_LOGFILE
}

save_debug_log ()
{
	echo ${1+"$@"} >>$TEST_REGRESS_LOGFILE
	echo ${1+"$@"} >>$TEST_SSH_LOGFILE
	echo ${1+"$@"} >>$TEST_SSHD_LOGFILE
	(cat $TEST_REGRESS_LOGFILE; echo) >>$OBJ/failed-regress.log
	(cat $TEST_SSH_LOGFILE; echo) >>$OBJ/failed-ssh.log
	(cat $TEST_SSHD_LOGFILE; echo) >>$OBJ/failed-sshd.log
}

trace ()
{
	echo "trace: $@" >>$TEST_REGRESS_LOGFILE
	echo "trace: $@" >>$TEST_SSH_LOGFILE
	echo "trace: $@" >>$TEST_SSHD_LOGFILE
	if [ "X$TEST_SSH_TRACE" = "Xyes" ]; then
		echo ${1+"$@"}
	fi
}

verbose ()
{
	start_debug_log ${1+"$@"}
	if [ "X$TEST_SSH_QUIET" != "Xyes" ]; then
		echo ${1+"$@"}
	fi
}

fail ()
{
	save_debug_log "FAIL: $@"
	RESULT=1
	echo ${1+"$@"}
	if test "x$TEST_SSH_FAIL_FATAL" != "x" ; then
		cleanup
		exit $RESULT
	fi
}

fatal ()
{
	save_debug_log "FATAL: $@"
	printf "FATAL: "
	fail ${1+"$@"}
	cleanup
	exit $RESULT
}

# Skip remaining tests in script.
skip ()
{
	echo "SKIPPED: $@"
	cleanup
	exit $RESULT
}

RESULT=0
PIDFILE=$OBJ/pidfile

trap fatal 3 2

# create server config
cat << EOF > $OBJ/sshd_config
	StrictModes		no
	Port			$PORT
	AddressFamily		inet
	ListenAddress		127.0.0.1
	#ListenAddress		::1
	PidFile			$PIDFILE
	AuthorizedKeysFile	$OBJ/authorized_keys_%u
	LogLevel		DEBUG3
	AcceptEnv		_XXX_TEST_*
	AcceptEnv		_XXX_TEST
	Subsystem	sftp	$SFTPSERVER
EOF

if test -n "$TEST_SSH_MODULI_FILE" ; then
	trace "adding modulifile='$TEST_SSH_MODULI_FILE' to sshd_config"
	echo "	ModuliFile $TEST_SSH_MODULI_FILE" >> $OBJ/sshd_config
fi

if test -n "$TEST_SSH_SSHD_CONFOPTS" ; then
	trace "adding sshd_config option $TEST_SSH_SSHD_CONFOPTS"
	echo "$TEST_SSH_SSHD_CONFOPTS" >> $OBJ/sshd_config
fi

# server config for proxy connects
cp $OBJ/sshd_config $OBJ/sshd_proxy

# create client config
cat << EOF > $OBJ/ssh_config
Host *
	Hostname		127.0.0.1
	HostKeyAlias		localhost-with-alias
	Port			$PORT
	User			$USER
	GlobalKnownHostsFile	$OBJ/known_hosts
	UserKnownHostsFile	$OBJ/known_hosts
	PubkeyAuthentication	yes
	KbdInteractiveAuthentication	no
	HostbasedAuthentication	no
	PasswordAuthentication	no
	BatchMode		yes
	StrictHostKeyChecking	yes
	LogLevel		DEBUG3
EOF

if [ ! -z "$TEST_SSH_SSH_CONFOPTS" ]; then
	trace "adding ssh_config option $TEST_SSH_SSH_CONFOPTS"
	echo "$TEST_SSH_SSH_CONFOPTS" >> $OBJ/ssh_config
fi

rm -f $OBJ/known_hosts $OBJ/authorized_keys_$USER

SSH_KEYTYPES=`$SSH -Q key-plain | grep -v "^x509v3-"`
SSH_HOSTKEY_TYPES=`$SSH -Q key-plain | grep -v "^x509v3-"`

case $SCRIPT in
*/fips-*)
  OPENSSL_FIPS=1
  #do not export OPENSSL_FIPS here
  SSH_KEYTYPES="ssh-rsa"
  SSH_HOSTKEY_TYPES="ssh-rsa"
  SSHKEYGEN="$SSHKEYGEN -m PKCS8"
  ;;
esac

for t in ${SSH_KEYTYPES}; do
	# generate user key
	if test -n "$OPENSSL_FIPS" ; then
		rm -f $OBJ/$t
	fi
	if [ ! -f $OBJ/$t ] || [ ${SSHKEYGEN_BIN} -nt $OBJ/$t ]; then
		trace "generating key type $t"
		rm -f $OBJ/$t
		keytype_compat $t
		$SSHKEYGEN -q -N '' -t $t $keytype_val -f $OBJ/$t ||\
			fail "ssh-keygen for $t failed"
	else
		trace "using cached key type $t"
	fi

	# setup authorized keys
	cat $OBJ/$t.pub >> $OBJ/authorized_keys_$USER
	echo IdentityFile $OBJ/$t >> $OBJ/ssh_config
done

for t in ${SSH_HOSTKEY_TYPES}; do
	# known hosts file for client
	(
		printf 'localhost-with-alias,127.0.0.1,::1 '
		cat $OBJ/$t.pub
	) >> $OBJ/known_hosts

	if test ! -f $OBJ/host.$t || test $OBJ/$t -nt $OBJ/host.$t ; then
		# use key as host key, too
		cp $OBJ/$t $OBJ/host.$t
		case $t in
		*xmss*) rm -f $OBJ/host.$t.*;; # remove state
		esac
	fi
	echo HostKey $OBJ/host.$t >> $OBJ/sshd_config

	# don't use SUDO for proxy connect
	echo HostKey $OBJ/$t >> $OBJ/sshd_proxy
done
chmod 644 $OBJ/authorized_keys_$USER


# Activate Twisted Conch tests if the binary is present
REGRESS_INTEROP_CONCH=false

# If PuTTY is present and we are running a PuTTY test, prepare keys and
# configuration
REGRESS_INTEROP_PUTTY=false

# Activate Dropbear tests if the binary is present
REGRESS_INTEROP_DROPBEAR=false

case "$SCRIPT" in
*conch-*)
	if test -x "$CONCH" ; then
		REGRESS_INTEROP_CONCH=:
	fi
	;;
*putty-*)
	if test -x "$PUTTYGEN" -a -x "$PLINK" ; then
		REGRESS_INTEROP_PUTTY=:
	fi
	;;
*dropbear*)
	if test -x "$DROPBEARKEY" -a -x "$DBCLIENT" -a -x "$DROPBEARCONVERT"; then
		REGRESS_INTEROP_DROPBEAR=:
	fi
	;;
esac

if $REGRESS_INTEROP_CONCH ; then
	SSH_ID_CONCH_RSA=false
	if $SSH_ID_CONCH_RSA ; then
	# ensure that ssh key is PEM format
	cp $OBJ/ssh-rsa $OBJ/ssh-rsa_pem
	$SSHKEYGEN -p -N '' -m PEM -f $OBJ/ssh-rsa_pem >/dev/null
	$SSHKEYGEN -y -f $OBJ/ssh-rsa_pem > $OBJ/ssh-rsa_pem.pub
	else
	# ensure that ssh ed25519 key is in custom format
	# NOTE conch does not work with ed25519 in PKCS#8 format!
	SSH_ID_CONCH=$OBJ/ssh-ed25519-conch
	cp $OBJ/ssh-ed25519 $SSH_ID_CONCH
	$SSHKEYGEN -p -N '' -m OpenSSH -f $SSH_ID_CONCH >/dev/null
	$SSHKEYGEN -y -f $SSH_ID_CONCH > $SSH_ID_CONCH.pub
	fi
fi

puttysetup() {
	if ! $REGRESS_INTEROP_PUTTY ; then
		RESULT=1
		skip "putty interop tests are not enabled"
	fi
	echo "PLINK: $PLINK" >&2

	PUTTYDIR=$OBJ/.putty
	mkdir -p $PUTTYDIR
	export PUTTYDIR

	rm -f ${OBJ}/putty.rsa2
	if ! $PUTTYGEN -t rsa -o ${OBJ}/putty.rsa2 \
	    --random-device=/dev/urandom \
	    --new-passphrase /dev/null < /dev/null > /dev/null; then
		echo "Your installed version of PuTTY is too old to support --new-passphrase, skipping test" >&2
		exit 1
	fi

	# ensure that ssh key is PEM format
	cp $OBJ/ssh-rsa $OBJ/ssh-rsa_pem
	$SSHKEYGEN -p -N '' -m PEM -f $OBJ/ssh-rsa_pem >/dev/null

	# Add a PuTTY key to authorized_keys
	$PUTTYGEN -O public-openssh ${OBJ}/putty.rsa2 \
	    >> $OBJ/authorized_keys_$USER

	${SRC}/ssh2putty.sh 127.0.0.1 $PORT $OBJ/ssh-rsa_pem > \
	    $PUTTYDIR/sshhostkeys
	${SRC}/ssh2putty.sh 127.0.0.1 22 $OBJ/ssh-rsa_pem >> \
	    $PUTTYDIR/sshhostkeys

	# Setup proxied session
	mkdir -p $PUTTYDIR/sessions
	cat > $PUTTYDIR/sessions/localhost_proxy <<EOF
Protocol=ssh
HostName=127.0.0.1
PortNumber=$PORT
ProxyMethod=5
ProxyTelnetCommand=env $TEST_SSH_SSHD_ENV $TEST_SHELL $SRC/sshd-log-wrapper.sh $TEST_SSHD_LOGFILE $SSHD -i -f $OBJ/sshd_proxy
ProxyLocalhost=1
EOF
}

if $REGRESS_INTEROP_DROPBEAR ; then
	trace Create dropbear keys and add to authorized_keys
	mkdir -p $OBJ/.dropbear
	for t in $SSH_KEYTYPES ; do
		case $t in
		ssh-rsa) i=rsa;;
		ecdsa-sha2-nistp256) i=ecdsa;;
		ssh-ed25519) i=ed25519;;
		ssh-dss) i=dss;;
		*) continue;;
		esac
		# Note dropbear fail to convert from PKIX-SSH key formats.
		# As work-around let create dropbear keys and convert them.
		if test ! -f "$OBJ/.dropbear/id_$i" ; then
			(
			$DROPBEARKEY -t $i -f $OBJ/.dropbear/id_$i
			$DROPBEARCONVERT dropbear openssh \
			    $OBJ/.dropbear/id_$i \
			    $OBJ/.dropbear/ossh.id_$i
			) > /dev/null 2>&1
		fi
		printf "%s dropbear_$i\n" \
		    "`$SSHKEYGEN -y -f $OBJ/.dropbear/ossh.id_$i`" \
		    >>$OBJ/authorized_keys_$USER
	done
	mkdir -p $OBJ/.ssh
	awk '{print "somehost "$2" "$3}' $OBJ/known_hosts >$OBJ/.ssh/known_hosts
fi

# create a proxy version of the client config
(
	cat $OBJ/ssh_config
	echo proxycommand $SUDO env $TEST_SSH_SSHD_ENV $TEST_SHELL $SRC/sshd-log-wrapper.sh $TEST_SSHD_LOGFILE $SSHD -i -f $OBJ/sshd_proxy
) > $OBJ/ssh_proxy

if test -n "$OPENSSL_FIPS" ; then
  export OPENSSL_FIPS
fi

# check proxy config
${SSHD} -t -f $OBJ/sshd_proxy	|| fatal "sshd_proxy broken"

# extract proxycommand into separate shell script for use by Dropbear.
if $REGRESS_INTEROP_DROPBEAR ; then
	(
	echo "#! $TEST_SHELL"
	awk '/^proxycommand/' $OBJ/ssh_proxy | sed 's/^proxycommand//'
	) > $OBJ/ssh_proxy_dropbear
	chmod a+x $OBJ/ssh_proxy_dropbear
fi

dbclient() {
  env HOME=$OBJ \
  $DBCLIENT -y -J "$OBJ/ssh_proxy_dropbear" ${1+"$@"}
}

start_sshd ()
{
	# start sshd
	$SUDO env $TEST_SSH_SSHD_ENV \
	    $SSHD -f $OBJ/sshd_config ${1+"$@"} -t || fatal "sshd_config broken"
	$SUDO env $TEST_SSH_SSHD_ENV \
	    $SSHD -f $OBJ/sshd_config ${1+"$@"} -E$TEST_SSHD_LOGFILE

	trace "wait for sshd"
	i=0;
	while [ ! -f $PIDFILE -a $i -lt 10 ]; do
		i=`expr $i + 1`
		sleep $i
	done

	test -f $PIDFILE || fatal "no sshd running on port $PORT"
}

# source test body
. $SCRIPT

# kill sshd
cleanup

if [ "x$USE_VALGRIND" != "x" ]; then
	# wait for any running process to complete
	wait; sleep 1
	VG_RESULTS=$(find $OBJ/valgrind-out -type f -print)
	VG_RESULT_COUNT=0
	VG_FAIL_COUNT=0
	for i in $VG_RESULTS; do
		if grep "ERROR SUMMARY" $i >/dev/null; then
			VG_RESULT_COUNT=$(($VG_RESULT_COUNT + 1))
			if ! grep "ERROR SUMMARY: 0 errors" $i >/dev/null; then
				VG_FAIL_COUNT=$(($VG_FAIL_COUNT + 1))
				RESULT=1
				verbose valgrind failure $i
				cat $i
			fi
		fi
	done
	if [ x"$VG_SKIP" != "x" ]; then
		verbose valgrind skipped
	else
		verbose valgrind results $VG_RESULT_COUNT failures $VG_FAIL_COUNT
	fi
fi

if [ $RESULT -eq 0 ]; then
	verbose ok $tid
	if test "x$CACHE" != "x" ; then
		touch "$CACHE"
	fi
else
	echo failed $tid
fi
exit $RESULT
