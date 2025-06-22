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
# DESCRIPTION: Test client authentication using keys from TPM2 provider
#  - "IdentityFile" is not used.
#  - "PubkeyAlgorithms" selects either X.509 or plain key.
#  - "AuthorizedKeysFile" contain encoded public key.
# NOTE: Requires OpenSSL 3.0+ with installed TPM2 provider.
# Tested with tpm2-openssl 1.3. Previous releases has "RSA size bug".
# Work-around is to set environment variable TPM2_RSA_SIZE_BUG.


# === common TPM2 setup:
TPM2_SCHEME=handle
TPM2_SUBDIR=tpm2

TPM2_PASS=TBD
TPM2_ASKPASS=$CWD/ssh_askpass-tpm2

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
  *)
    echo "error: unknown key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
  tpm2_key_id="SSH $key_type_name test certificate($TPM2_SIGN) - $SSH_DN_O"

  base_identity_file="$SSH_CLIENTKEY"
  if test ! -r "$base_identity_file" ; then
    error_file_not_readable "$base_identity_file"; return $?
  fi
  identity_file="$base_identity_file-$type"
  if test ! -r "$identity_file" ; then
    error_file_not_readable "$identity_file"; return $?
  fi

  "$TEST_SSH_SSHKEYGEN" -f "$base_identity_file" -y 2>/dev/null > "$AUTHORIZEDKEYSFILE" || return $?

  # load the key
( cd $TPM2_SUBDIR
  $TPM2_IMPORT -C primary.ctx -G $alg -i ../$identity_file \
    -r key-$alg.priv -u key-$alg.pub

  $TPM2_LOAD -C primary.ctx -u key-$alg.pub -r key-$alg.priv -c testkey-$alg.ctx
)
  # make the key persistent
  tpm2_key_id=`$TPM2_EVICTCONTROL -c $TPM2_SUBDIR/testkey-$alg.ctx | head -n 1 | cut -d ' ' -f 2`
  if test -z "$tpm2_key_id" ; then
    echo "error: fail to get tpm2 handle for $SSH_CLIENTKEY" >&2
    exit 33
  fi

  typemsg="$base_identity_file"
  must_fail=

# TODO X.509 certificate tests
: || {
  case "$SSH_CLIENTKEY" in
  *rsa*)         PubkeyAlgorithms='x509v3-*rsa*';;
  *eccnistp256*) PubkeyAlgorithms='x509v3-ecdsa*256';;
  *eccnistp384*) PubkeyAlgorithms='x509v3-ecdsa*384';;
  *)
    echo "error: unknown key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
(
  SSH_EXTRA_OPTIONS="$SSH_EXTRA_OPTIONS -o PubkeyAlgorithms=$PubkeyAlgorithms"

  runTest "$typemsg" "store:$TPM2_SCHEME:$tpm2_key_id" "X.509" "$must_fail"
) || return $?
}

  case "$SSH_CLIENTKEY" in
  *rsa*)         PubkeyAlgorithms='rsa-sha2*,ssh-rsa';;
  *eccnistp256*) PubkeyAlgorithms='ecdsa*256';;
  *eccnistp384*) PubkeyAlgorithms='ecdsa*384';;
  *)
    echo "error: unknown key $SSH_CLIENTKEY" >&2
    exit 33;;
  esac
(
  SSH_EXTRA_OPTIONS="$SSH_EXTRA_OPTIONS -o PubkeyAlgorithms=$PubkeyAlgorithms"

  runTest "$typemsg" "store:$TPM2_SCHEME:$tpm2_key_id" "plain" "$must_fail"
)

  # release the persistent key
  $TPM2_EVICTCONTROL -c $tpm2_key_id

( cd $TPM2_SUBDIR
  rm key-$alg.priv key-$alg.pub testkey-$alg.ctx
)
}


# ===

test_tpm2 () {
  echo "* ${extd}tpm2 provider${norm}:"

  creTestSSHDcfgFile
  cat >> "$SSHD_CFG" <<EOF
CACertificateFile $SSH_CAROOT/$CACERTFILE
CACertificatePath /path/not/found
CARevocationFile  /crlfile/not/found
CARevocationPath  /crlpath/not/found
EOF

  runSSHdaemon || return $?
  ( set -e
    SSH_ASKPASS_REQUIRE=force
    SSH_ASKPASS=$TPM2_ASKPASS
    export SSH_ASKPASS SSH_ASKPASS_REQUIRE

    OPENSSL_CONF=$OPENSSL_CONF
    export OPENSSL_CONF

    mkdir -p $TPM2_SUBDIR || :

    # create primary key
    $TPM2_CREATEPRIMARY -c $TPM2_SUBDIR/primary.ctx

    for SSH_CLIENTKEY in $TEST_SSH_CLIENTKEYS; do
      case $SSH_CLIENTKEY in
      *rsa*) alg=rsa;;
      *eccnistp256*) alg=ecc;;
      *eccnistp384*) alg=ecc;;
      *) continue;;
      esac
      testPUBKEYautorization || exit $?
    done

    rm $TPM2_SUBDIR/primary.ctx
  ); retval=$?
  killSSHdaemon
  return $retval
}


# ===

do_test () {
  TPM2_CREATEPRIMARY=`which tpm2_createprimary 2>/dev/null`
  TPM2_IMPORT=`which tpm2_import 2>/dev/null`
  TPM2_LOAD=`which tpm2_load 2>/dev/null`
  TPM2_EVICTCONTROL=`which tpm2_evictcontrol 2>/dev/null`

  if test -z "$TPM2_CREATEPRIMARY" || \
    test -z "$TPM2_IMPORT" ||
    test -z "$TPM2_LOAD" ||
    test -z "$TPM2_EVICTCONTROL" ; then
    echo "warning: ${extd}tpm2 utilities not found${norm}" >&2
    return 1
  fi
  # NOTE: Configuration belows assumes that TPM2 provider module is
  # installed in OpenSSL provider search path.
  ( cat > $OPENSSL_CONF << EOF
openssl_conf = config

[ config ]
providers = provider_section

[ provider_section ]
default = default_section
tpm2 = tpm2_section

[default_section]
activate = 1

[tpm2_section]
activate = 1
EOF
  ) || return $?

  ( cat > $TPM2_ASKPASS <<EOF
#! $TEST_SHELL
echo $TPM2_PASS
EOF
    chmod 0700 $TPM2_ASKPASS
  ) || return $?

  test_tpm2
}
