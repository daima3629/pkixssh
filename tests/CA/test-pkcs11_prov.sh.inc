#
# Copyright (c) 2025 Roumen Petrov, Sofia, Bulgaria
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
# DESCRIPTION: Test client authentication using keys from pkcs#11 provider:
#  - "IdentityFile" is not used.
#  - "PubkeyAlgorithms" selects either X.509 or plain key.
#  - "AuthorizedKeysFile" contain encoded public key.
# NOTE: Requires OpenSSL 3.0+ with installed pkcs#11 provider.
# Also provider requires pkcs#11 module.


# === common PKCS#11 setup:
. ${SCRIPTDIR}../pkcs11-env

SSH_MODULE_LOG="$CWD/.ssh-module.log"
> "$SSH_MODULE_LOG" || exit $?

OPENSSL_CONF="$CWD/openssl_provider.cnf"


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testPUBKEYautorization () {
  case "$SSH_CLIENTKEY" in
  *rsa*)         key_id='%%00%%01';;
  *eccnistp256*) key_id='%%00%%02';;
  *eccnistp384*) key_id='%%00%%03';;
  *eccnistp521*) key_id='%%00%%04';;
  *ed25519*)     key_id='%%00%%05';;
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

if $load_cert ; then
  case "$SSH_CLIENTKEY" in
  *rsa*)         algs='x509v3-rsa2048-sha256 x509v3-ssh-rsa x509v3-sign-rsa';;
  *eccnistp256*) algs='x509v3-ecdsa-sha2-nistp256';;
  *eccnistp384*) algs='x509v3-ecdsa-sha2-nistp384';;
  *eccnistp521*) algs='x509v3-ecdsa-sha2-nistp521';;
  *ed25519*)     algs='x509v3-ssh-ed25519';;
  *)
    echo "error: unknown key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
  for PubkeyAlgorithms in $algs ; do
(
  SSH_EXTRA_OPTIONS="$SSH_EXTRA_OPTIONS -o PubkeyAlgorithms=$PubkeyAlgorithms"

  runTest "$typemsg" "store:pkcs11:id=$key_id" "X.509 - $PubkeyAlgorithms" "$must_fail"
) || return $?
  done
fi

  case "$SSH_CLIENTKEY" in
  *rsa*)         algs='rsa-sha2-256 rsa-sha2-512 ssh-rsa';;
  *eccnistp256*) algs='ecdsa-sha2-nistp256';;
  *eccnistp384*) algs='ecdsa-sha2-nistp384';;
  *eccnistp521*) algs='ecdsa-sha2-nistp521';;
  *ed25519*)     algs='ssh-ed25519';;
  *)
    echo "error: unknown key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
  for PubkeyAlgorithms in $algs ; do
(
  SSH_EXTRA_OPTIONS="$SSH_EXTRA_OPTIONS -o PubkeyAlgorithms=$PubkeyAlgorithms"

  runTest "$typemsg" "store:pkcs11:id=$key_id" "plain - $PubkeyAlgorithms" "$must_fail"
) || return $?
  done
}


# ===

test_pkcs11 () {
  echo "* ${extd}pkcs#11 provider${norm}:"

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
      *ed25519*|\
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
  if p11_find_provider ; then :
  else
    echo "warning: ${extd}PKCS#11 provider not found${norm}" >&2
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
    cat > $OPENSSL_CONF << EOF
openssl_conf = config

[ config ]
providers = provider_section

[ provider_section ]
default = default_section
provider1 = provider1_section

[default_section]
activate = 1

[provider1_section]
module = $TEST_SSH_PKCS11_PROVIDER
#pkcs11-module-path = \${ENV::PKCS11_PROVIDER_MODULE}
pkcs11-module-path = $TEST_SSH_PKCS11
#?#pkcs11-module-cache-keys = false
# NOTE: Do not cache session, otherwise "digest sign update" will fail!
pkcs11-module-cache-sessions = 0
activate = 1
EOF
  ) || return $?

  test_pkcs11
}
