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
# DESCRIPTION: Test client and server with x509 certificates.
#


CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/ssh_x509tests.sh//'`
. "${SCRIPTDIR}config"
. "${SCRIPTDIR}functions"

test "x$TEST_SSH_SSH"       = "x" && { echo "${warn}Please define ${attn}TEST_SSH_SSH${norm}" >&2       ; exit 1; }
test "x$TEST_SSH_SSHD"      = "x" && { echo "${warn}Please define ${attn}TEST_SSH_SSHD${norm}" >&2      ; exit 1; }
test "x$TEST_SSH_SSHAGENT"  = "x" && { echo "${warn}Please define ${attn}TEST_SSH_SSHAGENT${norm}" >&2  ; exit 1; }
test "x$TEST_SSH_SSHADD"    = "x" && { echo "${warn}Please define ${attn}TEST_SSH_SSHADD${norm}" >&2    ; exit 1; }
test "x$TEST_SSH_SSHKEYGEN" = "x" && { echo "${warn}Please define ${attn}TEST_SSH_SSHKEYGEN${norm}" >&2 ; exit 1; }
#TEST_SSH_SSHKEYSCAN
#TEST_SSH_SFTP
#TEST_SSH_SFTPSERVER

cat <<EOF
ssh commands:
	ssh		$TEST_SSH_SSH
	sshd		$TEST_SSH_SSHD
	ssh-agent	$TEST_SSH_SSHAGENT
	ssh-add		$TEST_SSH_SSHADD
	ssh-keygen	$TEST_SSH_SSHKEYGEN
EOF

# prevent user environment influence
unset SSH_AGENT_PID || :
unset SSH_AUTH_SOCK || :

# regression test files
SSHD_LOG="${CWD}/sshd_x509.log"
SSHD_PID="${CWD}/.sshd_x509.pid"
SSHD_CFG="${CWD}/sshd_config-certTests"
SSH_CFG="${CWD}/ssh_config-certTests"

SSH_ERRLOG="${CWD}/.ssh_x509.err.log"
SSH_REPLY="${CWD}/.ssh_x509.reply"
SSH_EXTRA_OPTIONS=""


TEST_SSH_CLIENTKEYS=
TEST_OCSP_RESPKEYS=

SSH_ALGS_PLAIN_RSA=
SSH_ALGS_X509_RSA=
SSH_ALGS_PLAIN_DSA=
SSH_ALGS_X509_DSA=
# some vendor specific openssl libraries does not support nistp521
SSH_EC_CURVES=
SSH_ALGS_PLAIN_EC=
SSH_ALGS_X509_EC=
SSH_ALGS_PLAIN_ED25519=
SSH_ALGS_X509_ED25519=

HAVE_EVP_SHA256=false

for a in `$TEST_SSH_SSH -Q key` ; do
  case $a in
  x509v3-*-rsa)
    SSH_ALGS_X509_RSA="$SSH_ALGS_X509_RSA $a"
    ;;
  x509v3-rsa2048-sha256)
    # TODO: SSH_ALGS_X509_RSA="$SSH_ALGS_X509_RSA $a"
    HAVE_EVP_SHA256=:
    ;;
  x509v3-*-dss)
    SSH_ALGS_X509_DSA="$SSH_ALGS_X509_DSA $a"
    ;;
  x509v3-ecdsa-sha2-*)
    curve=`echo $a | sed 's/x509v3-ecdsa-sha2-//'`
    case $curve in
    nistp256);;
    nistp384);;
    nistp521);;
    *)
      # makefile create keys only for curves above
      echo "${warn}test does not support curve ${attn}${curve}${norm}" >&2
      continue
      ;;
    esac
    SSH_EC_CURVES="$SSH_EC_CURVES $curve"
    SSH_ALGS_PLAIN_EC="$SSH_ALGS_PLAIN_EC `echo $a | sed 's/x509v3-//'`"
    SSH_ALGS_X509_EC="$SSH_ALGS_X509_EC $a"
    ;;
  x509v3-*-ed25519)
    SSH_ALGS_X509_ED25519="$SSH_ALGS_X509_ED25519 $a"
    ;;
  esac
done

# if exist X.509 algorithm must exist corresponding plain-key
if test -n "$SSH_ALGS_X509_RSA" ; then
  TEST_SSH_CLIENTKEYS="$TEST_SSH_CLIENTKEYS testid_rsa"
  TEST_OCSP_RESPKEYS="$TEST_OCSP_RESPKEYS testocsp_rsa"
  SSH_ALGS_PLAIN_RSA=ssh-rsa
fi
if test -n "$SSH_ALGS_X509_DSA" ; then
  TEST_SSH_CLIENTKEYS="$TEST_SSH_CLIENTKEYS testid_dsa"
  TEST_OCSP_RESPKEYS="$TEST_OCSP_RESPKEYS testocsp_dsa"
  SSH_ALGS_PLAIN_DSA=ssh-dss
fi
for curve in $SSH_EC_CURVES "" ; do
  test -z "$curve" && break
  TEST_SSH_CLIENTKEYS="$TEST_SSH_CLIENTKEYS testid_ecc$curve"
  TEST_OCSP_RESPKEYS="$TEST_OCSP_RESPKEYS testocsp_ecc$curve"
done
if test -n "$SSH_ALGS_X509_ED25519" ; then
  TEST_SSH_CLIENTKEYS="$TEST_SSH_CLIENTKEYS testid_ed25519"
  SSH_ALGS_PLAIN_ED25519=ssh-ed25519
fi

# if SHA-256 is supported must exist RSA RFC8332 algorithms
if $HAVE_EVP_SHA256 ; then
  SSH_ALGS_PLAIN_RSA="$SSH_ALGS_PLAIN_RSA rsa-sha2-256 rsa-sha2-512"
fi

SSH_ALGS_PLAIN="\
  $SSH_ALGS_PLAIN_RSA \
  $SSH_ALGS_PLAIN_DSA \
  $SSH_ALGS_PLAIN_EC \
  $SSH_ALGS_PLAIN_ED25519 \
"
SSH_ALGS_X509="\
  $SSH_ALGS_X509_RSA \
  $SSH_ALGS_X509_DSA \
  $SSH_ALGS_X509_EC \
  $SSH_ALGS_X509_ED25519 \
"

# OpenSSL OCSP limitation: only rsa keys for versions before 1.x
# OCSP tests are slow as OpenSSL OCSP sample responder does not reuse
# socked address. So each test has to wait timeout to expire ~ 60 sec.
# Lets use only rsa for now.
TEST_OCSP_RESPKEYS="testocsp_rsa"

#TEST_SSHD_HOSTKEY="$CWD/testhostkey_rsa-rsa_sha1"
TEST_SSHD_HOSTKEY="$CWD/testhostkey_rsa"


USERDIR="${HOME}/.ssh"
if test ! -d "${USERDIR}"; then
  mkdir "${USERDIR}" || exit 1
  chmod 700 "${USERDIR}" || exit 1
fi

AUTHORIZEDKEYSFILE="${USERDIR}/authorized_keys-certTests"
USERKNOWNHOSTSFILE="${USERDIR}/known_hosts-certTests"


# ===
# remove unsupported tests

if $SSH_LDAP_ENABLED ; then
  echo "LDAP: enabled"
else
  echo "LDAP: disabled"
  SSH_X509TESTS=`echo "${SSH_X509TESTS}" | sed -e 's|by_ldap||g'`
fi
if $SSH_OCSP_ENABLED ; then
  echo "OCSP: enabled"
else
  echo "OCSP: disabled"
  SSH_X509TESTS=`echo "${SSH_X509TESTS}" | sed -e 's|ocsp||g'`
fi
if $USE_OPENSSL_STORE2 ; then
  echo "STORE: enabled"
else
  echo "STORE: disabled"
  SSH_X509TESTS=`echo "${SSH_X509TESTS}" | sed -e 's|store_file||g'`
fi
echo SSH_X509TESTS: $SSH_X509TESTS


# ===
runSSHdaemon() {
  echo "=======================================================================" >> "${SSHD_LOG}"

  if test -f "${SSHD_PID}"; then
    echo "${warn}sshd pid file exist!${norm}" >&2
  fi

  #NOTES:
  #- without -d option sshd run in daemon mode and this command always return 0 !!!
  #- bug or ?: with option -e no log to stderr in daemon mode
  $SUDO "$TEST_SSH_SSHD" -f "${SSHD_CFG}" \
    -o PidFile="${SSHD_PID}" \
    -o SyslogFacility="${SSHSERVER_SYSLOGFACILITY}" \
    -o LogLevel="${SSHSERVER_LOGLEVEL}" \
  >> "${SSHD_LOG}" 2>&1

  sleep 1
  test -f "$SSHD_PID" || sleep 1
  test -f "$SSHD_PID" || sleep 1
  if test ! -f "$SSHD_PID" ; then
    printf "${warn}cannot start sshd:${norm} " >&2
    error_file_not_readable "${SSHD_PID}"
    return 33
  fi
}


# ===
killSSHdaemon() {
(
  $SUDO kill `$SUDO cat "$SSHD_PID" 2>/dev/null` > /dev/null 2>&1
  K=0
  while test $K -le 9; do
    if test ! -f "${SSHD_PID}"; then
      break
    fi
    sleep 1
    K=`expr $K + 1`
  done
  rm -f "${SSHD_CFG}"
  if test -f "${SSHD_PID}"; then
    $SUDO kill -9 `$SUDO cat "$SSHD_PID" 2>/dev/null` > /dev/null 2>&1
    sleep 1
    $SUDO rm -f "${SSHD_PID}" > /dev/null 2>&1
  fi
  exit 0
)
}


# ===
testEND() {
  ( echo
    echo "*=- The END -=*"
  ) >> "${SSHD_LOG}"

  rm -f "${SSH_ERRLOG}"
  rm -f "${SSH_REPLY}"
  rm -f "${AUTHORIZEDKEYSFILE}"
  rm -f "${USERKNOWNHOSTSFILE}"
  rm -f "${SSH_CFG}"
}

testBREAK() {
  ( echo
    echo "*=- BREAK -=*"
  ) >> "${SSHD_LOG}"
  killSSHdaemon
}

trap testBREAK HUP INT QUIT ABRT TERM || exit 1
trap testEND EXIT || exit 1


# ===
creTestSSHDcfgFile() {
  cat > "$SSHD_CFG" <<EOF
Port $SSHD_PORT
#obsolete#Protocol 2
ListenAddress $SSHD_LISTENADDRESS

AuthorizedKeysFile $AUTHORIZEDKEYSFILE
EOF
  if test -n "$TEST_SSH_MODULI_FILE" ; then
    echo "ModuliFile $TEST_SSH_MODULI_FILE" >> "$SSHD_CFG"
  fi
  cat >> "$SSHD_CFG" <<EOF

KbdInteractiveAuthentication no
HostbasedAuthentication no
PasswordAuthentication no
PubkeyAuthentication yes
#conditional#GSSAPIAuthentication no
#conditional#KerberosAuthentication no

StrictModes no

UsePrivilegeSeparation $SSHSERVER_USEPRIVILEGESEPARATION

HostKey $TEST_SSHD_HOSTKEY

#AllowedCertPurpose sslclient
EOF
}

creTestSSHcfgFile() {
  cat > "${SSH_CFG}" <<EOF
Host *
Port ${SSHD_PORT}
PreferredAuthentications publickey
Protocol 2
StrictHostKeyChecking yes
UserKnownHostsFile ${USERKNOWNHOSTSFILE}

#AllowedCertPurpose sslserver
$TEST_CLIENT_CFG

CACertificatePath /path/not/found/global
CACertificateFile ${SSH_CAROOT}/${CACERTFILE}
UserCACertificatePath /path/not/found/user
UserCACertificateFile /file/not/found/user

CARevocationPath  /crlpath/not/found/global
CARevocationFile  /crlfile/not/found/global
UserCARevocationPath  /crlpath/not/found/user
UserCARevocationFile  /crlfile/not/found/user
EOF
}


# ===
#args:
#  $1 - type
#  $2 - identity_file or empty
#  $3 - info
#  $4 - request to fail flag
#  $5 - optional error text to search for if fail
runTest () {
(
  printf '%s' "  * ${extd}${1}${norm} ${3}"

  msg="A X.509 CertIficaTe TeSt-${1}"

  sshopts=
  #sshopts='-o LogLevel=VERBOSE'
  #sshopts='-o LogLevel=DEBUG1'
  #sshopts='-o LogLevel=DEBUG2'
  #sshopts='-o LogLevel=DEBUG3'

  test -n "$2" && sshopts="${sshopts} -i $2"
  #assignment to variable "identity_file" crash ksh :-(
  #identity_file="value_without_significance"

  case $4 in
    Y|y|Yes|yes|YES|1)
      must_fail=1;;
    *)
      must_fail=0;;
  esac
  if test -n "$5"; then
    must_fail_err_txt="$5"
  else
    must_fail_err_txt='Permission denied (publickey)'
  fi

  creTestSSHcfgFile || exit $?

  "$TEST_SSH_SSH" -F "${SSH_CFG}" ${sshopts} \
    ${SSH_EXTRA_OPTIONS} \
    ${SSHD_LISTENADDRESS} "echo \"${msg}\"" \
    2> "${SSH_ERRLOG}" > "${SSH_REPLY}"; retval=$?

  if test "x$must_fail" = "x1"; then
    if test $retval -ne 0; then
      retval=0
    else
      retval=1
    fi
  fi

  show_status $retval
  if test $retval -ne 0; then
    printf '%s' "${warn}"
    cat "${SSH_ERRLOG}"; printf '%s' "${norm}"
  else
    if test "x$must_fail" = "x1"; then
      if fgrep "$must_fail_err_txt" "$SSH_ERRLOG" > /dev/null; then
        printf '%s' "${done}"
      else
        retval=33
        printf '%s' "${warn}"
      fi
      cat "${SSH_ERRLOG}"; printf '%s' "${norm}"
    else
      if fgrep "$msg" "${SSH_REPLY}" > /dev/null; then
        :
      else
        retval=33
        printf '%s' "${warn}"
        cat "${SSH_REPLY}"; printf '%s' "${norm}"
      fi
    fi
  fi

  exit $retval
)
}


# ===
do_all () {
  > "$AUTHORIZEDKEYSFILE" &&
  chmod 644 "$AUTHORIZEDKEYSFILE" || return $?

  > "$SSHD_LOG" || return $?

  if test ! -f "${TEST_SSHD_HOSTKEY}.pub"; then
    echo "${warn}Public host file ${attn}$TEST_SSHD_HOSTKEY.pub${warn} not found !${norm}" >72
    return 3
  fi
  ( printf '%s' "${SSHD_LISTENADDRESS} "
    cat "${TEST_SSHD_HOSTKEY}.pub"
  ) > "${USERKNOWNHOSTSFILE}" &&
  chmod 644 "${USERKNOWNHOSTSFILE}" || return $?

  # call the test scripts
  for LTEST in ${SSH_X509TESTS}; do
  (
    echo
    echo "using: ${attn}${SCRIPTDIR}test-${LTEST}.sh.inc${norm}"
    . ${SCRIPTDIR}test-${LTEST}.sh.inc &&
    do_test
  ) || return $?
  done

  printSeparator
  return 0
}


# ===
echo
printSeparator
echo "${extd}Testing client and server with X.509 certificates:${norm}"
printSeparator

do_all; retval=$?

echo
printSeparator
echo "${extd}Testing client and server with X.509 certificates finished.${norm}"
show_status $retval "  ${extd}status${norm}:"
printSeparator
echo

exit $retval
