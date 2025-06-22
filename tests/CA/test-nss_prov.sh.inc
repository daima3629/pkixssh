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
# DESCRIPTION: Test client authentication using keys from NSS provider
#  - "IdentityFile" is not used.
#  - "PubkeyAlgorithms" selects either X.509 or plain key.
#  - "AuthorizedKeysFile" contain encoded public key.
# NOTE: Requires OpenSSL 3.0+ with installed NSS provider.


# === common NSS setup:
. ${SCRIPTDIR}../nss-env

SSH_MODULE_LOG="$CWD/.ssh-module.log"
> "$SSH_MODULE_LOG" || exit $?

OPENSSL_CONF="$CWD/openssl_provider.cnf"


# ===
#env. vars:
#  SSH_CLIENTKEY
#  type
testPUBKEYautorization () {
  case "$SSH_CLIENTKEY" in
  *rsa*) key_type_name="$SSH_DN_KEY_TYPE_RSA";;
  *eccnistp256*) key_type_name="$SSH_DN_KEY_TYPE_EC256";;
  *eccnistp384*) key_type_name="$SSH_DN_KEY_TYPE_EC384";;
  *eccnistp521*) key_type_name="$SSH_DN_KEY_TYPE_EC521";;
  *)
    echo "error: unsupported key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
  nss_key_id="SSH $key_type_name test certificate($NSS_SIGN) - $SSH_DN_O"

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

  case "$SSH_CLIENTKEY" in
  *rsa*)         PubkeyAlgorithms='x509v3-*rsa*';;
  *eccnistp256*) PubkeyAlgorithms='x509v3-ecdsa*256';;
  *eccnistp384*) PubkeyAlgorithms='x509v3-ecdsa*384';;
  *eccnistp521*) PubkeyAlgorithms='x509v3-ecdsa*521';;
  *)
    echo "error: unsupported key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
(
  SSH_EXTRA_OPTIONS="$SSH_EXTRA_OPTIONS -o PubkeyAlgorithms=$PubkeyAlgorithms"
  export nss_key_id
  runTest "$typemsg" "store:nss:\${nss_key_id}" "X.509" "$must_fail"
) || return $?

  case "$SSH_CLIENTKEY" in
  *rsa*)         PubkeyAlgorithms='rsa-sha2*,ssh-rsa';;
  *eccnistp256*) PubkeyAlgorithms='ecdsa*256';;
  *eccnistp384*) PubkeyAlgorithms='ecdsa*384';;
  *eccnistp521*) PubkeyAlgorithms='ecdsa*521';;
  *)
    echo "error: unsupported key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
(
  SSH_EXTRA_OPTIONS="$SSH_EXTRA_OPTIONS -o PubkeyAlgorithms=$PubkeyAlgorithms"
  export nss_key_id
  runTest "$typemsg" "store:nss:\${nss_key_id}" "plain" "$must_fail"
)
}


# ===

test_nss () {
  echo "* ${extd}nss provider${norm}:"

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
    SSH_ASKPASS=$NSS_ASKPASS
    cre_ssh_nss_askpass
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
  if nss_find_provider ; then :
  else
    echo "warning: ${extd}NSS provider not found${norm}" >&2
    return 1
  fi
  if nss_find_CERTUTIL ; then :
  else
    echo "warning: ${extd}CERTUTIL not found${norm}" >&2
    return 1
  fi
  if nss_find_PK12UTIL ; then :
  else
    echo "warning: ${extd}PK12UTIL not found${norm}" >&2
    return 1
  fi

  nss_setup_db || return $?

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
module = $TEST_SSH_NSS_PROVIDER
#DEBUG = 3
CONFIG_DIR = $NSS_DB_DIR
activate = 1
EOF
  ) || return $?

  test_nss
}
