#	$OpenBSD: rekey.sh,v 1.29 2024/08/22 10:21:02 dtucker Exp $
#	Placed in the Public Domain.

tid="rekey"

LOG=${TEST_SSH_LOGFILE}
COPY2=$OBJ/copy2

rm -f ${LOG}
cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

# Note all of the rekey tests must not use compression otherwise
# the encrypted byte counts would not match.
echo "Compression no" >> $OBJ/ssh_proxy
echo "RekeyLimit 256k" >> $OBJ/ssh_proxy
if config_defined HAVE_EVP_SHA256 ; then
	echo "KexAlgorithms curve25519-sha256" >> $OBJ/ssh_proxy
fi

# Test rekeying based on data volume only.
# Arguments: rekeylimit, kex method, optional remaining opts are passed to ssh.
ssh_data_rekeying()
{
	_bytes=$1 ; shift
	_kexopt=$1 ; shift
	_opts=${1+"$@"}
	if test -z "$_bytes"; then
		_bytes=32k
	fi
	if test -n "$_kexopt" ; then
		cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
		echo "$_kexopt" >> $OBJ/sshd_proxy
		_opts="$_opts -o$_kexopt"
		case "$_kexopt" in
		MACs=*)
			# if is used chacha20-poly1305 cipher by default
			# it has implicit MAC
			_opts="$_opts -oCiphers=aes128-ctr" ;;
		esac
	fi
	trace  bytes $_bytes kex $_kexopt opts $_opts
	rm -f $COPY $COPY2 $LOG
	# Create data file just big enough to reach rekey threshold.
	dd if=$DATA of=$COPY2 bs=$_bytes count=1 2>/dev/null

	$SSH <$COPY2 $_opts -vv \
	    -oRekeyLimit=$_bytes -F $OBJ/ssh_proxy somehost "cat > $COPY"
	if [ $? -ne 0 ]; then
		fail "ssh failed ($@)"
	fi
	cmp $COPY2 $COPY		|| fail "corrupted copy ($@)"
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if test -n "$_kexopt" ; then
		_want=`echo $_kexopt | cut -f2 -d=`
		_got=
		case "$_kexopt" in
		KexAlgorithms=*)
			_got=`awk '/kex: algorithm: /{print $4}' $LOG | \
			tr -d '\r' | sort -u` ;;
		Ciphers=*)
			_got=`awk '/kex: client->server cipher:/{print $5}' $LOG | \
			tr -d '\r' | sort -u` ;;
		MACs=*)
			_got=`awk '/kex: client->server cipher:/{print $7}' $LOG | \
			tr -d '\r' | sort -u` ;;
		esac
		if test "x$_want" != "x$_got" ; then
			fail "unexpected algorithm, want $_want, got $_got"
		fi
	fi
	if [ $n -lt 1 ]; then
		fail "no rekeying occurred ($@)"
	fi
}

increase_datafile_size 300

opts=""

# filter key exchange algorithm aliases
# Note curve25519-sha256@libssh.org is the pre-standardization name
# for the same curve25519-sha256.
kexs=`$SSH -Q kex | grep -v curve25519-sha256@libssh.org`

for i in $kexs; do
	opts="$opts KexAlgorithms=$i"
done
for i in `${SSH} -Q cipher`; do
	opts="$opts Ciphers=$i"
done
for i in `${SSH} -Q mac`; do
	opts="$opts MACs=$i"
done

for opt in $opts; do
	if $SSH -Q cipher-auth | sed 's/^/Ciphers=/' | \
	    grep $opt >/dev/null; then
		for kex in $kexs; do
			verbose "client rekey $opt $kex"
			ssh_data_rekeying "" "KexAlgorithms=$kex" "-o$opt"
		done
		continue
	fi
	verbose "client rekey $opt"
	ssh_data_rekeying "" "$opt"
done

# restore configuration to prevent impact from previous tests
cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy

for s in 16 1k 128k 256k; do
	verbose "client rekeylimit ${s}"
	ssh_data_rekeying "$s" ""
done

for s in 5 10; do
	verbose "client rekeylimit default ${s}"
	rm -f ${COPY} ${LOG}
	$SSH < $DATA -oRekeyLimit="default $s" -F \
		$OBJ/ssh_proxy somehost "cat >${COPY};sleep $s;sleep 10"
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occurred"
	fi
done

for s in 5 10; do
	verbose "client rekeylimit default ${s} no data"
	rm -f ${COPY} ${LOG}
	$SSH -oRekeyLimit="default $s" -F \
		$OBJ/ssh_proxy somehost "sleep $s;sleep 10"
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occurred"
	fi
done

for s in 16 1k 128k 256k; do
	verbose "server rekeylimit ${s}"
	cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
	echo "rekeylimit ${s}" >>$OBJ/sshd_proxy
	rm -f $COPY $COPY2 $LOG
	dd if=$DATA of=$COPY2 bs=$s count=1 2>/dev/null
	$SSH -F $OBJ/ssh_proxy somehost "cat $COPY2" > $COPY
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	cmp $COPY2 $COPY		|| fail "corrupted copy"
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occurred"
	fi
done

for s in 5 10; do
	verbose "server rekeylimit default ${s} no data"
	cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
	echo "rekeylimit default ${s}" >>$OBJ/sshd_proxy
	rm -f ${COPY} ${LOG}
	$SSH -F $OBJ/ssh_proxy somehost "sleep $s;sleep 10"
	if [ $? -ne 0 ]; then
		fail "ssh failed"
	fi
	n=`grep 'NEWKEYS sent' ${LOG} | wc -l`
	n=`expr $n - 1`
	trace "$n rekeying(s)"
	if [ $n -lt 1 ]; then
		fail "no rekeying occurred"
	fi
done

verbose "rekeylimit parsing: bytes"
for size in 16 1k 1K 1m 1M 1g 1G 4G 8G; do
	case $size in
		16)	bytes=16 ;;
		1k|1K)	bytes=1024 ;;
		1m|1M)	bytes=1048576 ;;
		1g|1G)	bytes=1073741824 ;;
		4g|4G)	bytes=4294967296 ;;
		8g|8G)	bytes=8589934592 ;;
	esac
	b=`$SSH -d -o "rekeylimit $size" -f $OBJ/ssh_proxy host | \
	    awk '/rekeylimit/{print $2}'`
	if test "$bytes" != "$b" ; then
		fatal "rekeylimit size: expected $bytes bytes got $b"
	fi
done

verbose "rekeylimit parsing: seconds"
for time in 1 1m 1M 1h 1H 1d 1D 1w 1W; do
	case $time in
		1)	seconds=1 ;;
		1m|1M)	seconds=60 ;;
		1h|1H)	seconds=3600 ;;
		1d|1D)	seconds=86400 ;;
		1w|1W)	seconds=604800 ;;
	esac
	s=`$SSH -d -o "rekeylimit default $time" -f $OBJ/ssh_proxy host | \
	    awk '/rekeylimit/{print $3}'`
	if test "$seconds" != "$s" ; then
		fatal "rekeylimit time: expected $time seconds got $s"
	fi
done

rm -f $COPY $COPY2 $DATA
