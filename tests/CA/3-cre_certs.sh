#! /bin/sh
# Copyright (c) 2002-2021 Roumen Petrov, Sofia, Bulgaria
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
# DESCRIPTION: Create test certificate(s).
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/3-cre_certs.sh$//'`
. "${SCRIPTDIR}shell.rc"
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"

usage () {
  cat <<EOF
${warn}usage${norm}: $0 keytype category filename
EOF
  exit 1
}

test "x$TEST_SSH_SSHKEYGEN" = "x" && { echo "${warn}Please define ${attn}TEST_SSH_SSHKEYGEN${norm}" >&2 ; exit 1; }


test -z "$1" && usage
case "$1" in
rsa)	key_type_name="RSA";;
dsa)	key_type_name="DSA";;
ec256)	key_type_name="ECDSA(nistp256)";;
ec384)	key_type_name="ECDSA(nistp384)";;
ec521)	key_type_name="ECDSA(nistp521)";;
*)	echo "${warn}unsupported key type: ${attn}$1${norm}" >&2
	exit 1
  ;;
esac
msg="${extd}$key_type_name${norm}"

shift
test -z "$1" && usage
SSH_SELFCERT=no
case $1 in
client)
  SSH_X509V3_EXTENSIONS=usr_cert
  SSH_BASE_DN_CN="SSH $key_type_name test certificate"
  msg="$msg ${attn}client${norm}"
  ;;
server)
  SSH_X509V3_EXTENSIONS=srv_cert
  SSH_BASE_DN_CN="localhost $key_type_name"
  msg="$msg ${attn}server${norm}"
  ;;
self)
  SSH_SELFCERT=yes
  SSH_X509V3_EXTENSIONS=self_cert
  SSH_BASE_DN_CN="SSH $key_type_name test self-issued certificate"
  msg="$msg ${attn}client self-issued${norm}"
  ;;
ocsp)
  if $SSH_OCSP_ENABLED ; then :
  else
    echo "${warn}unsupported category: ${attn}$1${norm}" >&2
    usage
  fi
  SSH_X509V3_EXTENSIONS=ocsp_cert
  SSH_BASE_DN_CN="validator $key_type_name"
  msg="$msg ${attn}ocsp responder${norm}"
  ;;
*)
  echo "${warn}wrong category: ${attn}$1${norm}" >&2
  usage
  ;;
esac

shift
test -z "$1" && usage
SSH_BASE_KEY="$1"
test ! -r "${SSH_BASE_KEY}" && { error_file_not_readable; exit 1; }


CA_LOG="$CWD/ca-3.$SSH_BASE_KEY.$SSH_X509V3_EXTENSIONS.log"
create_empty_file "$CA_LOG" > /dev/null || exit $?


# ===
cre_crt () {
  TMP_CRT_FILE="$TMPDIR/$SSH_X509V3_EXTENSIONS-$type$subtype.crt"
  TMP_CSR_FILE="$TMPDIR/$SSH_X509V3_EXTENSIONS-$type$subtype.csr"

  echo "=== create a new CSR ===" >> "$CA_LOG"
  (
    if test "$SSH_X509V3_EXTENSIONS" != "usr_cert"; then
      SSH_DN_EM="."
    fi

    cat <<EOF
$SSH_DN_C
$SSH_DN_ST
$SSH_DN_L
$SSH_DN_O
${SSH_DN_OU}-2
${SSH_DN_OU}-1
${SSH_DN_OU}-3
$SSH_BASE_DN_CN(${type}${subtype})
$SSH_DN_EM
.
EOF
  ) |
  $OPENSSL req -config "$SSH_CACFGFILE" \
    -new \
    -key "$SSH_BASE_KEY" -passin pass: \
    -out "$TMP_CSR_FILE" \
    2>> "$CA_LOG" \
  ; show_status $? "- ${extd}CSR${norm}" ||
    return $?

  echo "=== create a new CRT ===" >> "$CA_LOG"
  $OPENSSL ca -config "$SSH_CACFGFILE" \
    -batch \
    -in "$TMP_CSR_FILE" \
    -name "ca_test_$type" \
    -passin pass:$KEY_PASS \
    -out "$TMP_CRT_FILE" \
    -extensions $SSH_X509V3_EXTENSIONS \
    2>> "$CA_LOG" \
  ; show_status $? "- ${extd}CRT${norm}" ||
  { retval=$?
    printf '%s' "${warn}"
    grep 'ERROR:' "$CA_LOG"
    printf '%s' "${norm}"
    return $retval
  }

  sync
  $OPENSSL verify \
    -CAfile "$SSH_CAROOT/$CACERTFILE" \
    "$TMP_CRT_FILE" ||
  { retval=$?
    rm -f "$TMP_CSR_FILE"
    return $retval
  }
  rm -f "$TMP_CSR_FILE"

  # openssl verify exit always with zero :(

  printf '%s' '- ' &&
  update_file \
    "$TMP_CRT_FILE" \
    "$SSH_BASE_KEY-$type$subtype.crt" ||
    return $?

  # openssl ca command does not support name option
  F="$SSH_BASE_KEY-$type$subtype.crt"
  mv "$F" t-"$F" &&
  $OPENSSL x509 \
    -in t-"$F" \
    -text $OPENSSL_NAMEOPT \
    > "$F" &&
  rm t-"$F"
}


# ===
cre_self () {
  TMP_CRT_FILE="$TMPDIR/$SSH_X509V3_EXTENSIONS-$type.crt"

  echo "=== create a new self-CRT ===" >> "$CA_LOG"
  (
    cat <<EOF
$SSH_DN_C
$SSH_DN_ST
$SSH_DN_L
$SSH_DN_O
${SSH_DN_OU}-2
${SSH_DN_OU}-1
${SSH_DN_OU}-3
$SSH_BASE_DN_CN(${type}-self)
$SSH_DN_EM
.
EOF
  ) |
  $OPENSSL req -config "$SSH_CACFGFILE" \
    -new -x509 \
    -days $SSH_CACERTDAYS \
    -key "$SSH_BASE_KEY" -passin pass: \
    -out "$TMP_CRT_FILE" \
    -extensions $SSH_X509V3_EXTENSIONS \
    2>> "$CA_LOG" \
  ; show_status $? "- ${extd}self-CRT${norm}" \
  || return $?

  update_file \
    "$TMP_CRT_FILE" \
    "$SSH_BASE_KEY-$type.crt"
}


# ===
cre_ssh_crt () {
  printf '%s' "- ${extd}PKIX-SSH certificate${norm}"
  ( cat "$SSH_BASE_KEY"

    $OPENSSL x509 \
     -in "$SSH_BASE_KEY-$type$subtype.crt" \
     -subject -issuer -alias $OPENSSL_NAMEOPT
  ) > "$SSH_BASE_KEY-$type$subtype" &&
  chmod 600 "$SSH_BASE_KEY-$type$subtype" \
  ; show_status $?
}


cre_ssh_pubkey () {
  printf '%s' "- ${extd}PKIX-SSH public key${norm}"
  "$TEST_SSH_SSHKEYGEN" -y -f "${SSH_BASE_KEY}-${type}${subtype}" \
    > "${SSH_BASE_KEY}-${type}${subtype}.pub" \
  ; show_status $?
}


cre_p12 () {
  P12_OPT=
  if test -n "$OPENSSL_FIPS"; then
    P12_OPT="$P12_OPT -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES"
  fi
  printf '%s' "- ${extd}PKCS #12${norm} file"
  ( cat "$SSH_BASE_KEY-$type$subtype"
    cat "$SSH_CAROOT/crt/$CAKEY_PREFIX-$type.crt.pem"
  ) | \
  $OPENSSL pkcs12 $P12_OPT \
    -passin pass: \
    -passout pass: \
    -out "$SSH_BASE_KEY-$type$subtype".p12 \
    -export \
  ; show_status $?
}


revoke_crt () {
  echo "=== revoke a CRT ===" >> "$CA_LOG"
  printf '%s' "- ${extd}revoke${norm} certificate"
  $OPENSSL ca -config "$SSH_CACFGFILE" \
    -name "ca_test_$type" \
    -passin pass:$KEY_PASS \
    -revoke "$SSH_BASE_KEY-$type$subtype.crt" \
    2>> "$CA_LOG" \
  ; show_status $?
}


# ===
cre_all2 () {
  printf '%s\n' "creating ${extd}${SSH_X509V3_EXTENSIONS}${norm} for ${extd}${SSH_BASE_DN_CN}${norm}(${attn}${type}${norm}${warn}${subtype}${norm}) ..."

  if test "$SSH_SELFCERT" = "yes"; then
    cre_self
  else
    cre_crt
  fi || return $?

  test "$SSH_X509V3_EXTENSIONS" = "ocsp_cert" && return 0

  cre_ssh_crt &&
  cre_ssh_pubkey &&
  cre_p12
}


# ===
cre_all () {
(
  subtype=
  if test "$SSH_SELFCERT" = "yes" ; then
    # NOTE self-issued use name in format "selfid_${keytype}"
    keytype=`echo $SSH_BASE_KEY | sed 's/^selfid_//'`
    if test "$SSH_BASE_KEY" = "$keytype" ; then
      echo "For self-issued ${warn}cannot obtain keytype from keyname - ${attn}$SSH_BASE_KEY${norm}" >&2
      exit 1
    fi
    type=$keytype
    cre_all2 || exit $?
  else
    for type in $SSH_SIGN_TYPES ; do
      cre_all2 || exit $?
    done
  fi

  if test "$SSH_X509V3_EXTENSIONS" = "srv_cert" || \
     test "$SSH_SELFCERT" = "yes" \
  ; then
    create_empty_file $SSH_BASE_KEY.certstamp
    exit $?
  fi

  subtype="-revoked"
  for type in ${SSH_SIGN_TYPES}; do
    cre_all2 &&
    revoke_crt || exit $?
  done

  create_empty_file $SSH_BASE_KEY.certstamp
)
}

# ===
echo
echo "Generating $msg certificates, keys, etc..."

cre_all; retval=$?

show_status $retval "Creation of ${extd}$SSH_BASE_DN_CN${norm} certificates, keys, etc."
echo
