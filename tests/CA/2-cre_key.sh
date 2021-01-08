#! /bin/sh
# Copyright (c) 2011-2021 Roumen Petrov, Sofia, Bulgaria
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
SCRIPTDIR=`echo $0 | sed 's/2-cre_key.sh$//'`
. "${SCRIPTDIR}shell.rc"
. "${SCRIPTDIR}functions"
. "${SCRIPTDIR}config"

test "x$TEST_SSH_SSHKEYGEN" = "x" && { echo "${warn}Please define ${attn}TEST_SSH_SSHKEYGEN${norm}" >&2 ; exit 1; }

usage() {
  cat <<EOF
${warn}usage${norm}: $0 keytype category filename
EOF
  exit 1
}

opts=

test -z "$1" && usage
case "$1" in
rsa)	opts="$opts -t rsa -b $RSAKEYBITS"
	typemsg="RSA"
  ;;
dsa)	opts="$opts -t dsa"
	typemsg="DSA"
  ;;
ec256)	opts="$opts -t ecdsa -b 256"
	typemsg="ECDSA(nistp256)"
  ;;
ec384)	opts="$opts -t ecdsa -b 384"
	typemsg="ECDSA(nistp384)"
  ;;
ec521)	opts="$opts -t ecdsa -b 521"
	typemsg="ECDSA(nistp521)"
  ;;
*)	echo "${warn}unsupported key type: ${attn}$1${norm}" >&2
	exit 1
  ;;
esac

shift
test -z "$1" && usage
case $1 in
client)
  infomsg="'Identity'"
  ;;
server)
  infomsg="host-key"
  ;;
self)
  infomsg="'Identity' for self-issued"
  ;;
ocsp)
  if $SSH_OCSP_ENABLED ; then :
  else
    echo "${warn}unsupported category: ${attn}$1${norm}" >&2
    usage
  fi
  infomsg="ocsp-key"
  ;;
*)
  echo "${warn}wrong category: ${attn}$1${norm}" >&2
  usage
  ;;
esac

shift
test -z "$1" && usage


echo
echo "Generating ${extd}$typemsg${norm} ${attn}$infomsg${norm} ..."

# X.509 keys require portable PKCS#8 format instead proprietary
$TEST_SSH_SSHKEYGEN $opts -m PKCS8 -N "" -f "$1"
