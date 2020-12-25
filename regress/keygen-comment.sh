#    Placed in the Public Domain.

tid="Comment extraction from private key"

S1="secret1"

if config_defined HAVE_EVP_SHA256 ; then
keygen_hash_opt=sha256
keygen_hash_res="SHA256:(.){43}"
else
keygen_hash_opt=md5
keygen_hash_res="MD5:(.){47}"
fi

check_fingerprint () {
	file="$1"
	comment="$2"
	trace "fingerprinting $file"
	if ! $SSHKEYGEN -l -E $keygen_hash_opt -f $file > $OBJ/$t-fgp ; then
		fail "ssh-keygen -l failed for $t-key"
	fi
	if ! egrep "^([0-9]+) "$keygen_hash_res" $comment \(.*\)\$" \
	    $OBJ/$t-fgp >/dev/null 2>&1 ; then
		fail "comment is not correctly recovered for $t-key"
	fi
	rm -f $OBJ/$t-fgp
}

for fmt in RFC4716 PKCS8 PEM OpenSSH ; do
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
		$SSHKEYGEN -m $fmt -N '' -C "$comment" \
		    -t $t -f $OBJ/$t-key >/dev/null || \
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
