#    Placed in the Public Domain.

tid="Comment extraction from private key"

S1="secret1"

check_fingerprint () {
	file="$1"
	comment="$2"
	trace "fingerprinting $file"
	if ! $SSHKEYGEN -l -E sha256 -f $file > $OBJ/$t-fgp ; then
		fail "ssh-keygen -l failed for $t-key"
	fi
	if ! egrep "^([0-9]+) SHA256:(.){43} $comment \(.*\)\$" \
	    $OBJ/$t-fgp >/dev/null 2>&1 ; then
		fail "comment is not correctly recovered for $t-key"
	fi
	rm -f $OBJ/$t-fgp
}

for fmt in RFC4716 PKCS8 PEM '' ; do
	for t in $SSH_KEYTYPES ; do
		trace "generating $t key in '$fmt' format"
		rm -f $OBJ/$t-key*
		customfmt=:
		case "$fmt" in
		RFC4716|PKCS8|PEM) customfmt=false ;;
		esac
		# ssh-ed25519 and *@openssh.com keys are stored only
		# in custom format
		case "$t" in
		ssh-ed25519|*openssh.com) $customfmt || continue ;;
		esac
		comment="foo bar"
		fmtarg=
		if test -z "$fmt" ; then
		  fmtarg="-o"
		else
		  fmtarg="-m $fmt"
		fi
		$SSHKEYGEN $fmtarg -N '' -C "$comment" \
		    -t $t -f $OBJ/$t-key >/dev/null 2>&1 || \
			fatal "keygen of $t in format $fmt failed"
		check_fingerprint $OBJ/$t-key "$comment"
		check_fingerprint $OBJ/$t-key.pub "$comment"
		# Output fingerprint using only private file
		trace "fingerprinting $t key using private key file"
		rm -f $OBJ/$t-key.pub
		if $customfmt ; then
			# as well comment can be extracted from
			# private stored in custom format
			:
		else
			comment="no comment"
		fi
		check_fingerprint $OBJ/$t-key "$comment"
		rm -f $OBJ/$t-key*
	done
done
