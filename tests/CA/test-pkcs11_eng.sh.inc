#
# Copyright (c) 2023-2025 Roumen Petrov, Sofia, Bulgaria
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
# DESCRIPTION: Test client authentication using keys from pkcs#11 engine:
#  - "IdentityFile" is not used.
#  - "PubkeyAlgorithms" selects either X.509 or plain key.
#  - "AuthorizedKeysFile" contain encoded public key.
# NOTE: Engine requires pkcs#11 module.


# === common PKCS#11 setup:
. ${SCRIPTDIR}../pkcs11-env

SSH_MODULE_LOG="$CWD/.ssh-module.log"
> "$SSH_MODULE_LOG" || exit $?

SSH_ENGINE="$CWD/ssh_engine"
OPENSSL_CONF="$CWD/openssl_engine.cnf"


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testPUBKEYautorization () {
  case "$SSH_CLIENTKEY" in
  *rsa*)         key_id='0001';;
  *eccnistp256*) key_id='0002';;
  *eccnistp384*) key_id='0003';;
  *eccnistp521*) key_id='0004';;
  *)
    echo "error: unknown key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac

  base_identity_file="$SSH_CLIENTKEY"
  if test ! -r "$base_identity_file" ; then
    error_file_not_readable "$base_identity_file"; return $?
  fi
  identity_file="$base_identity_file-$type"
  if test ! -r "$identity_file" ; then
    error_file_not_readable "$identity_file"; return $?
  fi

  "$TEST_SSH_SSHKEYGEN" -f "$base_identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || return $?

  typemsg="$base_identity_file"
  must_fail=

  SSH_EXTRA_OPTIONS="-G $SSH_ENGINE -o IdentityFile=engine:pkcs11:$key_id"

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

  runTest "$typemsg" "" "X.509" "$must_fail"
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

  runTest "$typemsg" "" "plain" "$must_fail"
)
}


# ===

test_pkcs11 () {
  echo "* ${extd}pkcs#11 engine${norm}:"

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

    OPENSSL_CONF=$OPENSSL_CONF
    export OPENSSL_CONF

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
  if p11_find_engine ; then :
  else
    echo "warning: ${extd}PKCS#11 engine not found${norm}" >&2
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

  p11_setup_token || return $?

  (
    cat > $SSH_ENGINE << EOF
Engine pkcs11
# debug if libp11 <= 0.4.13
#VERBOSE
# debug if libp11 > 0.4.13, NOTE without backward compatibility!
#DEBUG_LEVEL = 7
MODULE_PATH = $TEST_SSH_PKCS11
EOF
    cat > $OPENSSL_CONF << EOF
openssl_conf = config

[ config ]
engines = engine_section

[ engine_section ]
engine1 = engine1_section

[engine1_section]
dynamic_path = $TEST_SSH_PKCS11_ENGINE
EOF
  ) || return $?

  test_pkcs11
}
