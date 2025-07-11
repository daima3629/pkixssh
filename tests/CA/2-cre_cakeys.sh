#! /bin/sh
# Copyright (c) 2002-2025 Roumen Petrov, Sofia, Bulgaria
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
# DESCRIPTION: Create "Test Certificate Authority" private keys and certificates.
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/2-cre_cakeys.sh$//'`
. "${SCRIPTDIR}config"
. "${SCRIPTDIR}functions"


CA_LOG="$CWD/ca-2.log"
> "$CA_LOG" || exit $?

rsa_bits=2048
dsa_bits=1024   # match secsh algorithm specification
dsa_qbits=160   # NOTE OpenSSL 1.0.2+ default q to 224 bits
ec_curve=prime256v1

if $openssl_use_pkey ; then
  cipher=aes-128-cbc
else
  cipher=des3
fi
pkcs5v1=PBE-SHA1-3DES
pkcs5v2=aes256


# ===
top_srcdir=`cd $SCRIPTDIR/../..; pwd`

install_sh () {
  $top_srcdir/install-sh ${1+"$@"}
}


# ===
echo_SSH_CA_DN () {
cat <<EOF
$SSH_DN_C
$SSH_DN_ST
$SSH_DN_L
$SSH_DN_O
$SSH_DN_OU
$SSH_DN_OU $1 keys
.
SSH TestCA $1 key
.
.
EOF
}


# ===
echo_SSH_CAROOT_DN () {
cat <<EOF
$SSH_DN_C
$SSH_DN_ST
$SSH_DN_L
$SSH_DN_O
$SSH_DN_OU
$SSH_DN_OU level $1
.
SSH TestCA level $1
.
EOF
}


# ===
#args:
#  $1 - X.509 file in pem format
format_trusted_x509() {
(
  X509CMD="$OPENSSL x509 -inform PEM $OPENSSL_NAMEOPT"

  $X509CMD -in "$1" -fingerprint -noout || exit $?
  echo PEM data:
  $X509CMD -in "$1" -trustout           || exit $?
  echo Certificate Ingredients:
  $X509CMD -in "$1" -text -noout        || exit $?

  exit 0
)
}


# ===
#args:
#  $1 - existing X.509 file in pem format
#  $2 - name of X.509 file to store in pretty pem format
move_as_trusted_x509() {
  printf '%s' "creating file ${attn}$2${norm}"
  format_trusted_x509 "$1" > "$2"
  show_status $? || return $?

  rm -f "$1"
  return 0
}


# ===
#args:
#  $1 - key file
#  $2 - key algorithm
# NOTE: available in OpenSSL >= 1.0.0
gen_pkey () {
( umask 077

  rm -f "$1" 2>/dev/null

  if $openssl_nopkcs8_keys ; then
    rm -f "$1"-trad 2>/dev/null
    $OPENSSL genpkey -algorithm $2 \
      -out "$1"-trad &&
    $OPENSSL pkcs8 -topk8 -v2 $pkcs5v2 -in "$1"-trad \
      -out "$1" -passout pass:$KEY_PASS &&
    rm "$1"-trad
  else
    $OPENSSL genpkey -algorithm $2 \
      -out "$1" -pass pass:$KEY_PASS -$cipher
  fi
) 2>> "$CA_LOG"
}


# ===
#args:
#  $1 - rsa keyfile
gen_rsa_key () {
( umask 077

  rm -f "$1" 2>/dev/null

  if $openssl_use_pkey ; then
    $OPENSSL genpkey -algorithm RSA \
      -out "$1" -pass pass:$KEY_PASS -$cipher \
      -pkeyopt rsa_keygen_bits:$rsa_bits
    return $?
  fi

  if $openssl_nopkcs8_keys ; then
    rm -f "$1"-trad 2>/dev/null
    $OPENSSL genrsa \
      -out "$1"-trad $rsa_bits &&
    $OPENSSL pkcs8 -topk8 \
      -in "$1"-trad \
      -out "$1" -passout pass:$KEY_PASS \
      -v1 $pkcs5v1 &&
    rm "$1"-trad
  else
    $OPENSSL genrsa -$cipher \
      -passout pass:$KEY_PASS \
      -out "$1" $rsa_bits
  fi
) 2>> "$CA_LOG"
}


# ===
#args:
#  $1 - dsa parameter file
get_dsa_prm () {
( umask 077

  rm -f "$1" 2>/dev/null

  if $openssl_use_pkey ; then
    $OPENSSL genpkey -genparam -algorithm DSA \
      -out "$1" \
        -pkeyopt dsa_paramgen_bits:$dsa_bits \
        -pkeyopt dsa_paramgen_q_bits:$dsa_qbits
  else
    $OPENSSL dsaparam $DSA_OPT \
      -out "$1" $dsa_bits
  fi
) 2>> "$CA_LOG"
}

# ===
#args:
#  $1 - dsa keyfile
#  $2 - dsa parameter file
gen_dsa_key () {
( umask 077

  rm -f "$1" 2>/dev/null

  if $openssl_use_pkey ; then
    $OPENSSL genpkey -paramfile "$2" \
      -out "$1" -pass pass:$KEY_PASS -$cipher
    return $?
  fi

  if $openssl_nopkcs8_keys ; then
    rm -f "$1"-trad 2>/dev/null
    $OPENSSL gendsa \
      -out "$1"-trad "$2" &&
    $OPENSSL pkcs8 -topk8 \
      -in "$1"-trad \
      -out "$1" -passout pass:$KEY_PASS \
      -v1 $pkcs5v1 &&
    rm "$1"-trad
  else
    $OPENSSL gendsa -$cipher \
      -passout pass:$KEY_PASS \
      -out "$1" "$2"
  fi
) 2>> "$CA_LOG"
}


# ===
#args:
#  $1 - ec parameter file
get_ec_prm () {
( umask 077

  rm -f "$1" 2>/dev/null

  if $openssl_use_pkey ; then
    $OPENSSL genpkey -genparam -algorithm EC \
      -out "$1" -pkeyopt ec_paramgen_curve:$ec_curve
  else
    $OPENSSL ecparam \
      -out "$1" -name $ec_curve
  fi
) 2>> "$CA_LOG"
}

# ===
#args:
#  $1 - ec keyfile
#  $2 - ec parameter file
gen_ec_key () {
( umask 077

  rm -f "$1" 2>/dev/null

  if $openssl_use_pkey ; then
    $OPENSSL genpkey -paramfile "$2" \
      -out "$1" -pass pass:$KEY_PASS -$cipher
    return $?
  fi

  if $openssl_nopkcs8_keys ; then
    rm -f "$1"-trad 2>/dev/null
    $OPENSSL ecparam \
      -genkey -in "$2" \
      -out "$1"-trad &&
    $OPENSSL pkcs8 -topk8 \
      -in "$1"-trad \
      -out "$1" -passout pass:$KEY_PASS \
      -v1 $pkcs5v1 &&
    rm "$1"-trad
  else
    $OPENSSL ecparam \
      -genkey -in "$2" \
      -out "$1"-tmp &&
    $OPENSSL ec -$cipher \
      -in "$1"-tmp \
      -passout pass:$KEY_PASS \
      -out "$1" &&
    rm "$1"-tmp
  fi
) 2>> "$CA_LOG"
}


# ===
cre_root () {
  gen_rsa_key "$TMPDIR/$CAKEY_PREFIX"-root0.key \
  ; show_status $? "generating ${extd}TEST ROOT CA${norm} ${attn}rsa${norm} private key" \
  || return $?

  echo_SSH_CAROOT_DN "0" | \
  $OPENSSL req -config "$SSH_CACFGFILE" \
    -new -x509 \
    -days $SSH_CACERTDAYS \
    -key "$TMPDIR/$CAKEY_PREFIX-root0.key" -passin pass:$KEY_PASS \
    -out "$TMPDIR/$CAKEY_PREFIX-root0.crt" \
    -extensions ca_root_cert \
    2>> "$CA_LOG" \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}root${norm} certificate" \
  || return $?

  F="$CAKEY_PREFIX"-root0.key
  update_file "$TMPDIR/$F" "$SSH_CAROOT/keys/$F"

  F="$CAKEY_PREFIX"-root0.crt
  move_as_trusted_x509 "$TMPDIR/$F" "$SSH_CAROOT/crt/$F.pem"
}


# ===
check_cakey_type () {
  for type in $SSH_CAKEY_TYPES ; do
    if test "x$type" = "x$1" ; then
      return 0
    fi
  done
  return 1
}

gen_rsa () {
  gen_rsa_key "$TMPDIR/$CAKEY_PREFIX"-rsa.key \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}rsa${norm} private key"
}

gen_dsa () {
  check_cakey_type dsa || return 0
  get_dsa_prm \
    "$TMPDIR/$CAKEY_PREFIX-dsa.prm" \
  ; show_status $? "generating ${extd}DSA parameter file${norm}" \
  || return $?

  gen_dsa_key \
    "$TMPDIR/$CAKEY_PREFIX"-dsa.key \
    "$TMPDIR/$CAKEY_PREFIX"-dsa.prm \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}dsa${norm} private key"
}

gen_ec256 () {
  check_cakey_type ec256 || return 0
  get_ec_prm \
    "$TMPDIR/$CAKEY_PREFIX-ec256.prm" \
  ; show_status $? "generating ${extd}EC (nistp256) parameter file${norm}" \
  || return $?

  gen_ec_key \
    "$TMPDIR/$CAKEY_PREFIX"-ec256.key \
    "$TMPDIR/$CAKEY_PREFIX"-ec256.prm \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}ec(nistp256)${norm} private key"
}

gen_ed25519 () {
  check_cakey_type ed25519 || return 0
  gen_pkey "$TMPDIR/$CAKEY_PREFIX"-ed25519.key ED25519 \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}ed25519${norm} private key"
}

gen_ed448() {
  check_cakey_type ed448 || return 0
  gen_pkey "$TMPDIR/$CAKEY_PREFIX"-ed448.key ED448 \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}ed448${norm} private key"
}


# ===
cre_crt () {
for type in $SSH_SIGN_TYPES; do
  TMP_CRT_FILE="$TMPDIR/$CAKEY_PREFIX-$type.crt"
  TMP_CSR_FILE="$TMPDIR/$CAKEY_PREFIX-$type.csr"

  rm -f "$TMP_CRT_FILE" 2>/dev/null

  case $type in
  rsa*)
    keyfile="$TMPDIR/$CAKEY_PREFIX"-rsa.key;;
  dsa|ec256|ed25519|ed448)
    keyfile="$TMPDIR/$CAKEY_PREFIX"-$type.key;;
  *) return 99;;
  esac

  echo_SSH_CA_DN "$type" |
  $OPENSSL req -config "$SSH_CACFGFILE" \
    -new \
    -key "$keyfile" -passin pass:$KEY_PASS \
    -out "$TMP_CSR_FILE" \
    2>> "$CA_LOG" \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}${type}${norm} request" \
  || return $?

  $OPENSSL ca -config "$SSH_CACFGFILE" \
    -batch \
    -in "$TMP_CSR_FILE" \
    -name "ca_test_root" \
    -passin pass:$KEY_PASS \
    -out "$TMP_CRT_FILE" \
    -extensions ca_cert \
    2>> "$CA_LOG" \
  ; show_status $? "generating ${extd}TEST CA${norm} ${attn}${type}${norm} certificate" || \
  { retval=$?
    printf '%s' "${warn}"
    grep 'ERROR:' "$CA_LOG"
    printf '%s' "${norm}"
    rm -f "$TMP_CSR_FILE"
    rm -f "$TMP_CRT_FILE"
    return $retval
  }

  sync
  $OPENSSL verify \
    -CAfile "$SSH_CAROOT/crt/$CAKEY_PREFIX-root0.crt.pem" \
    "$TMP_CRT_FILE" \
  ; retval=$?
  # exit code always is 0 :(

  rm -f "$TMP_CSR_FILE"

done
  return $retval
}


# ===
crt2bundle () {
(
  val="$1"
  test -z "$val" && { echo ${warn}missing DN${norm} >&2; return 1; }

  echo
  echo $val
  echo $val | sed -e 's/./=/g'
  cat "$2"
)
}


# ===
cre_dirs () {
  install_sh -d "$SSH_CAROOT" &&
  install_sh -d -m 700 "$SSH_CAROOT/keys" &&
  install_sh -d "$SSH_CAROOT/crt"
}


install () {
(
  for type in $SSH_CAKEY_TYPES; do
    case $type in
    dsa|ec256)
      update_file "$TMPDIR/$CAKEY_PREFIX-$type.prm" "$SSH_CAROOT/$CAKEY_PREFIX-$type.prm" || exit $?
    esac
    F="$CAKEY_PREFIX-$type.key"
    update_file "$TMPDIR/$F" "$SSH_CAROOT/keys/$F" || exit $?
  done

  for type in $SSH_SIGN_TYPES; do
    F="$CAKEY_PREFIX-$type.crt"
    move_as_trusted_x509 "$TMPDIR/$F" "$SSH_CAROOT/crt/$F.pem" || exit $?
  done

  > "$TMPDIR/$CACERTFILE" &&
  for level in 0; do
    F="$SSH_CAROOT/crt/$CAKEY_PREFIX-root${level}.crt.pem"
    crt2bundle "$SSH_DN_O level $level" "$F" >> "$TMPDIR/$CACERTFILE" || exit $?
  done
  for type in ${SSH_SIGN_TYPES}; do
    F="$SSH_CAROOT/crt/$CAKEY_PREFIX-$type.crt.pem"
    crt2bundle "${SSH_DN_O}-${type}" "${F}" >> "${TMPDIR}/${CACERTFILE}" || exit $?
  done

  update_file "${TMPDIR}/${CACERTFILE}" "${SSH_CAROOT}/${CACERTFILE}"
)
}


cre_hashs () {
#(!) openssl script "c_rehash" is missing in some installations :-(
#  c_rehash "$SSH_CAROOT/crt"
(
  cd "$SSH_CAROOT/crt" || exit $?

  for F in [0-9a-f]*.[0-9]; do
    # we must use test -L, but on ?-OSes ... :-(
    if test -h "$F"; then
      rm -f "$F" || exit $?
    fi
  done

  for level in 0; do
    cre_hash_link -log "$CAKEY_PREFIX-root$level.crt.pem" || exit $?
  done

  for type in ${SSH_SIGN_TYPES}; do
    cre_hash_link -log "$CAKEY_PREFIX-$type.crt.pem" || exit $?
  done

  exit 0
)
}


# ===

cre_dirs &&
cre_root &&
gen_rsa &&
gen_dsa &&
gen_ec256 &&
gen_ed25519 &&
gen_ed448 &&
cre_crt &&
install &&
cre_hashs; retval=$?

show_status $retval "${extd}Creating${norm} ${warn}TEST${norm} ${attn}Certificate Authority${norm}"
echo "${warn}password for all private keys is ${attn}${KEY_PASS}${norm}"
exit $retval
