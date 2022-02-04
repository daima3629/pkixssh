#	$OpenBSD: cipher-speed.sh,v 1.14 2017/04/30 23:34:55 djm Exp $
#	Placed in the Public Domain.

tid="cipher speed"

ciphers=`$SSH -Q cipher`
macs=`$SSH -Q mac`

# Enable all supported ciphers and macs.
cat >>$OBJ/sshd_proxy <<EOF
Ciphers `echo $ciphers | sed 's/ /,/g'`
MACs `echo $macs | sed 's/ /,/g'`
EOF

increase_datafile_size 10000 # 10MB

getbytes ()
{
	sed -n -e '/transferred/s/.*secs (\(.* bytes.sec\).*/\1/p' \
	    -e '/copied/s/.*s, \(.* MB.s\).*/\1/p'
}

tries="1 2"

for c in $ciphers; do n=0; for m in $macs; do
	trace "cipher $c mac $m"
	for x in $tries; do
		printf "%-60s" "$c/$m:"
		( ${SSH} -o 'compression no' \
			-F $OBJ/ssh_proxy -m $m -c $c somehost \
			exec sh -c \'"dd of=/dev/null obs=32k"\' \
		< ${DATA} ) 2>&1 | getbytes

		if [ $? -ne 0 ]; then
			fail "ssh failed with mac $m cipher $c"
		fi
	done
	# No point trying all MACs for AEAD ciphers since they are ignored.
	if ${SSH} -Q cipher-auth | grep "^${c}\$" >/dev/null 2>&1 ; then
		break
	fi
	n=`expr $n + 1`
done; done
