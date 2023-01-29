#
# Copyright (c) 2023 Roumen Petrov, Sofia, Bulgaria
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
#  - "IdentityFile" using Store API to access PKCS#12 file;
#  - "AuthorizedKeysFile" contain encoded X.509 certificate.
#
#  NOTE:
#  Requires OpenSSL >= 1.1.1(Store2 API).
#


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testX509autorization () {
  identity_file="$SSH_CLIENTKEY-$type"
  if test ! -r "$identity_file" ; then
    error_file_not_readable "$identity_file"; return $?
  fi

  "$TEST_SSH_SSHKEYGEN" -f "$identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || return $?
  runTest "${norm}store:${extd}$SSH_CLIENTKEY${norm}..." \
    store:"$identity_file".p12 "$type" || return $?
}


# ===

do_test () {
  retval=0
  if $USE_OPENSSL_STORE2 ; then :
  else
    echo "* ${extd}STORE${norm} is ${attn}not supported${norm}"
    return 1
  fi
  echo "* ${extd}with ${attn}CACertificateFile${norm} using ${attn}\"store\"${norm}"

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  cat > ssh_askpass-p12 <<EOF
#! /bin/sh

echo $P12_PASS
EOF
  chmod +x ssh_askpass-p12

  runSSHdaemon || return $?
  (
    export SSH_ASKPASS=`pwd`/ssh_askpass-p12

    for type in $SSH_SIGN_TYPES; do

      for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do

        testX509autorization || exit $?

      done

    done
  ); retval=$?
  killSSHdaemon
  return $retval
}
