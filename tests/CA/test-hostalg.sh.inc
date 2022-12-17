#
# Copyright (c) 2012-2022 Roumen Petrov, Sofia, Bulgaria
# All rights reserved.
#
# Redistribution and use of this script, with or without modification, is
# permitted provided that the following conditions are met:
#
# 1. Redistributions of this script must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
#  EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# DESCRIPTION: Test client authentication:
#  - "IdentityFile" contain private key and optional X.509 certificate;
#  - "AuthorizedKeysFile" contain encoded client public key;
#  - user "KnownHostsFile" contain records for each host key;
#  - client accept certain hostkey algorithm.
#


USERKNOWNHOSTSFILE="$USERDIR/known_hosts-HostsTests"
for RSA_DGST in $SSH_SIGN_TYPES; do
  # get first key rsa....
  break
done


# ===

HOSTKEYtestBREAK() {
  echo
  rm -f $USERKNOWNHOSTSFILE
  rm -f $SSHD_CFG.tmp
  testBREAK
}

trap HOSTKEYtestBREAK HUP INT QUIT ABRT TERM || exit 1


# ===

do_test () {
  echo "* with ${extd}different ${attn}hostkey${norm} algorithms:"

  creTestSSHDcfgFile

  cat >> "$SSHD_CFG" <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  mv $SSHD_CFG $SSHD_CFG.tmp
  grep -v HostKey $SSHD_CFG.tmp > $SSHD_CFG
  rm $SSHD_CFG.tmp

if test -n "$SSH_ALGS_X509_RSA" ; then
(
  echo "# x509v3-*-rsa (legacy or RFC6187)"
  echo "HostKey \"$CWD/testhostkey_rsa-$RSA_DGST\""
) >> "$SSHD_CFG"
fi
if test -n "$SSH_ALGS_X509_DSA" ; then
(
  echo "# x509v3-*-dss (legacy or RFC6187)"
  echo "HostKey \"$CWD/testhostkey_dsa-dsa\""
) >> "$SSHD_CFG"
fi
if test -n "$SSH_ALGS_X509_EC" ; then
(
  echo "# x509v3-ecdsa-sha2-* (RFC6187)"
  for alg in $SSH_ALGS_X509_EC ; do
    case $alg in
    x509v3-ecdsa-sha2-*)
      curve=`echo $alg | sed 's/^.*ecdsa-sha2-//'`
      hostkey=ecc$curve-$RSA_DGST
      echo "HostKey \"$CWD/testhostkey_$hostkey\""
      ;;
    esac
  done
) >> "$SSHD_CFG"
fi
if test -n "$SSH_ALGS_X509_ED25519" ; then
(
  echo "# x509v3-ssh-ed25519"
  echo "HostKey \"$CWD/testhostkey_ed25519-$RSA_DGST\""
) >> "$SSHD_CFG"
fi

  runSSHdaemon || return $?
  (
    identity_file="testid_rsa-$RSA_DGST"
    "$TEST_SSH_SSHKEYGEN" -f "$identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || exit $?

    printSeparator

    for alg in \
      $SSH_ALGS_X509 \
      $SSH_ALGS_PLAIN \
    ; do

      plainkey=:
      expr $alg : 'x509v3-' >/dev/null && plainkey=false

      case $alg in
      x509v3-*-rsa|\
      rsa-sha2-*|\
      ssh-rsa)         hostkey=rsa;;
      *ecdsa-sha2-*)
                       curve=`echo $alg | sed 's/^.*ecdsa-sha2-//'`
                       hostkey=ecc$curve;;
      x509v3-*-dss|\
      ssh-dss)         hostkey=dsa;;
      x509v3-*-ed25519|\
      ssh-ed25519)     hostkey=ed25519;;
      *)
        echo "${warn}unsupported public key algorithm : $alg${norm}" >&2
        exit 1;;
      esac

      TEST_CLIENT_CFG="\
HostKeyAlgorithms $alg
"

      typemsg="$alg"
      mustfail=no
      errmsg=

      infomsg=".../testhostkey_$hostkey.pub ${extd}plain${norm}"
      cat > $USERKNOWNHOSTSFILE <<EOF
[$SSHD_LISTENADDRESS]:$SSHD_PORT `cat "$CWD"/testhostkey_$hostkey.pub`
EOF
      runTest "$typemsg" "$identity_file" "$infomsg" $mustfail "$errmsg" || exit $?

      case $alg in
      x509v3-*-dss|\
      ssh-dss) hostkey=$hostkey-dsa;;
      *)       hostkey=$hostkey-$RSA_DGST;;
      esac

      infomsg=".../testhostkey_$hostkey.pub ${extd}X.509${norm}"
      cat > $USERKNOWNHOSTSFILE <<EOF
[$SSHD_LISTENADDRESS]:$SSHD_PORT `cat "$CWD"/testhostkey_$hostkey.pub`
EOF
      runTest "$typemsg" "$identity_file" "$infomsg" $mustfail "$errmsg" || exit $?


      if $plainkey; then
        typemsg="$typemsg ${warn}!${norm}"
        mustfail=yes
        errmsg="Host key verification failed"
      fi

      subject=`getSubject "$CWD"/testhostkey_$hostkey` || return $?
      infomsg=".../testhostkey_$hostkey ${extd}Distinguished Name${norm}"
      cat > $USERKNOWNHOSTSFILE <<EOF
[$SSHD_LISTENADDRESS]:$SSHD_PORT $alg Subject:$subject
EOF
      runTest "$typemsg" "$identity_file" "$infomsg" $mustfail "$errmsg" || exit $?

    done

  ); retval=$?
  killSSHdaemon

  rm -f $USERKNOWNHOSTSFILE

  return $retval
}
