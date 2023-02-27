#! /bin/sh
# Copyright (c) 2004-2023 Roumen Petrov, Sofia, Bulgaria
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
# DESCRIPTION: Create LDAP files.
#

CWD=`pwd`
SCRIPTDIR=`echo $0 | sed 's/5-cre_ldap.sh$//'`
. "${SCRIPTDIR}config"
. "${SCRIPTDIR}functions"


if test ! -d ldap/data; then
  mkdir -p ldap/data || exit $?
fi


# ===
cre_base_ldif() {
(
  cat <<EOF
dn: ${SSH_LDAP_DC}
changetype: add
objectClass: dcObject
objectClass: organization
dc: example
o: Example Corporation
description: The Example Corporation

dn: cn=Manager,${SSH_LDAP_DC}
changetype: add
objectClass: inetOrgPerson
cn: Manager
sn: Manager
title: the world's most famous manager
mail: manager@example.com
uid: manager


# The organization 'SSH Test Team':
# "O=${SSH_DN_O},${SSH_LDAP_DC}"
dn:`utf8base64 "O=${SSH_DN_O},${SSH_LDAP_DC}"`
changetype: add
objectclass: organization
o:`utf8base64 "${SSH_DN_O}"`
st: ${SSH_DN_ST}


# The 'SSH Testers' organizational units:
# "OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"
dn:`utf8base64 "OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"`
changetype: add
objectclass: organizationalUnit
ou:`utf8base64 "${SSH_DN_OU}"`
l:`utf8base64 "${SSH_DN_L}"`
st: ${SSH_DN_ST}
EOF


  for level in 0; do
    cat <<EOF

# "OU=${SSH_DN_OU} level ${level},OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"
dn:`utf8base64 "OU=${SSH_DN_OU} level ${level},OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"`
changetype: add
objectclass: organizationalUnit
ou:`utf8base64 "$SSH_DN_OU level ${level}"`
l:`utf8base64 "${SSH_DN_L}"`
st: ${SSH_DN_ST}
EOF
  done


  for type in ${SSH_SIGN_TYPES}; do
    cat <<EOF

# "OU=${SSH_DN_OU} $type keys,OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"
dn:`utf8base64 "OU=${SSH_DN_OU} $type keys,OU=${SSH_DN_OU},O=${SSH_DN_O},${SSH_LDAP_DC}"`
changetype: add
objectclass: organizationalUnit
ou:`utf8base64 "$SSH_DN_OU $type keys"`
l:`utf8base64 "${SSH_DN_L}"`
st: ${SSH_DN_ST}
EOF
  done
) > ldap/base.ldif
}


# ===

cre_base_ldif &&
: ; retval=$?

show_status $retval "${extd}Creating${norm} ${warn}LDAP${norm} ${attn}files${norm}"
