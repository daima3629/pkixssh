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
# DESCRIPTION: Test client authentication using keys from pkcs#11 token:
#  - "IdentityFile" is not used.
#  - "PubkeyAlgorithms" selects either X.509 or plain key.
#  - "AuthorizedKeysFile" contain encoded public key.
# NOTE: Requires OpenSSL 1.0+


# === common PKCS#11 setup:
. ${SCRIPTDIR}../pkcs11-env

#load X.509 certificate to token:
load_cert=:
#load_cert=false

SSH_MODULE_LOG="$CWD/.ssh-module.log"
create_empty_file "$SSH_MODULE_LOG" || exit $?


# ===
#env. vars:
#  TEST_SSH_PKCS11 - pkcs#11 module
#  $1 - userpin
pkcs11_module_write() {
  OPENSC_DEBUG=1 \
  $PKCS11_TOOL --module $TEST_SSH_PKCS11 --verbose \
    --login --pin $userpin \
    ${1+"$@"} \
  >> $SSH_MODULE_LOG 2>&1
}


# ===
#env. vars:
#  $1 - userpin
#  $2 - key_file
#  $3 - key_id
#  $4 - key_label
pkcs11_write() {
  userpin=$1
  key_file=$2
  key_id=$3
  key_label=$4

  echo "write ${extd}$key_label${norm} ..." >&2

  echo "= prepare $key_id ..." >> $SSH_MODULE_LOG
  $OPENSSL x509 -in $key_file -outform DER -out pkcs11_tool-$key_id-cert.der || return $?

  key_type=privkey
  echo "== write $key_id-$key_type" >> $SSH_MODULE_LOG
  $OPENSSL pkey -in $key_file -outform DER -out pkcs11_tool-$key_id-$key_type.der || return $?
  pkcs11_module_write \
    --write-object pkcs11_tool-$key_id-$key_type.der --type $key_type \
    --id $key_id --label "$key_label" \
    --attr-from pkcs11_tool-$key_id-cert.der \
  || return $?
  rm -f pkcs11_tool-$key_id-$key_type.der

  key_type=pubkey
  echo "== write $key_id-$key_type" >> $SSH_MODULE_LOG
  $OPENSSL pkey -in $key_file -outform DER -pubout -out pkcs11_tool-$key_id-$key_type.der || return $?
  pkcs11_module_write \
    --write-object pkcs11_tool-$key_id-$key_type.der --type $key_type \
    --id $key_id --label "$key_label" \
  || return $?
  rm -f pkcs11_tool-$key_id-$key_type.der

if $load_cert ; then
  key_type=cert
  echo "== write $key_id-$key_type" >> $SSH_MODULE_LOG
  pkcs11_module_write \
    --write-object pkcs11_tool-$key_id-$key_type.der --type $key_type \
    --id $key_id --label "$key_label" \
  || return $?
fi

  rm -f pkcs11_tool-$key_id-cert.der
}


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testPUBKEYautorization () {
  base_identity_file="$SSH_CLIENTKEY"
  if test ! -r "$base_identity_file" ; then
    error_file_not_readable "$base_identity_file"; return $?
  fi
  identity_file="$base_identity_file-$type"
  if test ! -r "$identity_file" ; then
    error_file_not_readable "$identity_file"; return $?
  fi

  "$TEST_SSH_SSHKEYGEN" -f "$base_identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || return $?

  SSH_EXTRA_OPTIONS="-I $TEST_SSH_PKCS11 -i /dev/null"

if $load_cert ; then
  case "$SSH_CLIENTKEY" in
  *rsa*)         PubkeyAlgorithms='x509v3-*rsa*';;
  *eccnistp256*) PubkeyAlgorithms='x509v3-ecdsa*256';;
  *eccnistp384*) PubkeyAlgorithms='x509v3-ecdsa*384';;
  *eccnistp521*) PubkeyAlgorithms='x509v3-ecdsa*521';;
  *)
    echo "error: unknown key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
(
  SSH_EXTRA_OPTIONS="$SSH_EXTRA_OPTIONS -o PubkeyAlgorithms=$PubkeyAlgorithms"

  runTest $base_identity_file "" "X.509"
) || return $?
fi

  case "$SSH_CLIENTKEY" in
  *rsa*)         PubkeyAlgorithms='rsa-sha2*,ssh-rsa';;
  *eccnistp256*) PubkeyAlgorithms='ecdsa*256';;
  *eccnistp384*) PubkeyAlgorithms='ecdsa*384';;
  *eccnistp521*) PubkeyAlgorithms='ecdsa*521';;
  *)
    echo "error: unknown key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
(
  SSH_EXTRA_OPTIONS="$SSH_EXTRA_OPTIONS -o PubkeyAlgorithms=$PubkeyAlgorithms"

  runTest $base_identity_file "" "plain"
)
}


# ===

test_pkcs11 () {
  echo "* ${extd}pkcs#11 token${norm} direct:"

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  (
    SSH_ASKPASS_REQUIRE=force
    SSH_ASKPASS=$P11_ASKPASS
    cre_ssh_p11_askpass
    export SSH_ASKPASS SSH_ASKPASS_REQUIRE

    for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do
      case $SSH_CLIENTKEY in
      *eccnistp256*|\
      *eccnistp384*|\
      *eccnistp521*|\
      *rsa*);;
      *) continue;;
      esac
      testPUBKEYautorization || exit $?
    done
  ); retval=$?
  killSSHdaemon
  return $retval
}


# ===

do_test () {
  if p11_find_module ; then :
  else
    echo "warning: ${extd}SoftHSM module not found${norm}" >&2
    return 1
  fi
  if p11_find_SOFTHSM2_TOOL ; then :
  else
    echo "warning: ${extd}SoftHSM tool not found${norm}" >&2
    return 1
  fi
  if p11_find_PKCS11_TOOL ; then :
  else
    echo "warning: ${extd}PKCS#11 tool not found${norm}" >&2
    return 1
  fi
  p11_setup

  # stop on first rsa digest
  for type in $SSH_SIGN_TYPES; do
    case $type in
    *rsa*);;
    *) continue;;
    esac
    break;
  done

  # setup token and load X.509 certificates and keys
  (
    echo "create ${extd}test0${norm} token ..." >&2
    echo "=== create token" >> $SSH_MODULE_LOG
    $SOFTHSM2_TOOL --init-token --label test0 --slot free \
      --so-pin $TEST_SSH_SOPIN --pin $TEST_SSH_PIN \
      >> $SSH_MODULE_LOG 2>&1 \
    || exit $?

    for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do
      case $SSH_CLIENTKEY in
      *rsa*)         key_id='0001'; key_label=p11-rsa;;
      *eccnistp256*) key_id='0002'; key_label=p11-ec256;;
      *eccnistp384*) key_id='0003'; key_label=p11-ec384;;
      *eccnistp521*) key_id='0004'; key_label=p11-ec521;;
      *) continue;;
      esac
      pkcs11_write $TEST_SSH_PIN $SSH_CLIENTKEY-$type $key_id $key_label \
      || exit $?
    done
    echo "=== write end" >> $SSH_MODULE_LOG
  ) || return $?

  test_pkcs11
}
