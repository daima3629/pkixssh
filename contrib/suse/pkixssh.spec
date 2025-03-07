#
# spec file for pkixssh package
#
# This is free software; see Copyright file in the source
# distribution for precise wording.
#
# Copyright (c) 2019-2024 Roumen Petrov
#

# Do we want to enable building with ldap? (1=yes 0=no)
%global enable_ldap 1

# Do we want to enable test with ldap? (1=yes 0=no)
%global enable_ldap_test 1

# Do we use FIPS capable OpenSSL library ? (1=yes 0=no)
%global enable_openssl_fips 1

# Do we want to enable FIPS test? (1=yes 0=no)
%global enable_fips_test 1

# Do we want to use fipscheck? (1=yes 0=no)
%global use_fipscheck 1

# Do we want to use Linux auditing? (1=yes 0=no)
%global enable_audit_module 1

# Do we want to enable Kerberos 5 support? (1=yes 0=no)
%global enable_kerberos5 1

# Do we want to enable DSA publickey algorithms? (1=yes 0=no)
%global enable_dsa 0

# Do we want to enable Intermediate CA with DSA key? (1=yes 0=no)
# Note applicable if OpenSSL < 1.1
%global enable_dsa_ca 1

# Do we want to enable OpenSSL engine support? (1=yes 0=no)
%global enable_ssl_engine 1

# Do we want to enable integration with systemd? (1=yes 0=no)
%global enable_systemd 1


# Development builds
%if 0%{?suse_version} >= 1699
# Tumbleweed ...
# OpenSSL 3+ FIPS model is not supported yet
%undefine enable_openssl_fips
%global enable_openssl_fips 0
%endif


# Disable non-working configurations
%if 0%{?sle_version} >= 0150600
# OpenSSL 3+ FIPS model is not supported yet
%undefine enable_openssl_fips
%global enable_openssl_fips 0
%endif

%if !%{enable_openssl_fips}
%undefine enable_fips_test
%global enable_fips_test 0
%endif

%if 0%{?sle_version} >= 120000 && 0%{?sle_version} < 120200
# NOTE: Exclude fipscheck on SLE 12 releases before SP2 due to
# missing package with header files (fipscheck-devel). Why?
%undefine use_fipscheck
%global use_fipscheck 0
%endif
%if 0%{?sles_version} == 11
%undefine use_fipscheck
%global use_fipscheck 0
%endif
%if !%{enable_openssl_fips}
%undefine use_fipscheck
%global use_fipscheck 0
%endif


# NOTE: do not use systemd on SUSE Linux Enterprise Server 11
%if 0%{?sles_version} == 11
%undefine enable_systemd
%global enable_systemd 0
%endif


# NOTE: On SUSE Linux Enterprise Server 11 SP4 test keygen-convert.sh
# crash when imports PKCS#8 DSA keys. It pass on SLE 11 SP3.
# The difference:
#   SLE 11 SP4: libopenssl0_9_8-0.9.8j-0.70.1
#   SLE 11 SP3: libopenssl0_9_8-0.9.8j-0.50.1

# In addition creation of X.509 certificate for DSA Intermediate CA
# fails on SLE 11 SP4 with message:
#   "Signature did not match the certificate request".
# Remark: OpenSSL ca utility exits with success!
# Exclude DSA CA on both as cannot distinguish OS releases.
%if 0%{?sles_version} == 11
%undefine enable_dsa_ca
%global enable_dsa_ca 0
%endif
# Exclude DSA CA on openSUSE 11.* as is expected to fail on some releases.
# Remark: openSUSE 11.1 is basis for SLE 11.
%if 0%{?suse_version} >= 1100 && 0%{?suse_version} < 1200
%undefine enable_dsa_ca
%global enable_dsa_ca 0
%endif


# Conditional configurations
# Note openSUSE Tumbleweed:
#  {?suse_version} > 1500 - current upcoming release (changing)
%if 0%{?sle_version} >= 150000 || 0%{?suse_version} > 1500
%define ldap_libexecdir		/usr/sbin
%define ldap_moduledir		%{_libdir}/openldap
%else
%define ldap_libexecdir		/usr/lib/openldap
%define ldap_moduledir		/usr/lib/openldap/modules
%endif


# norootforbuild

Url:		https://roumenpetrov.info/secsh/

Name:		pkixssh
Summary:	PKIX-SSH, Advanced secure shell implementation
Version:	16.0
Release:	1
License:	BSD-2-Clause
Group:		Productivity/Networking/SSH

PreReq:		permissions
%if %{enable_systemd}
Requires(post):	%fillup_prereq
%else
Requires(post):	%insserv_prereq %fillup_prereq
%endif

BuildRequires:	libselinux-devel
BuildRequires:	zlib-devel
BuildRequires:	pam-devel
BuildRequires:	libopenssl-devel openssl
%if %{enable_ldap}
BuildRequires:	openldap2-devel openldap2-client
%endif
%if %{enable_ldap_test}
BuildRequires:	openldap2
%endif
%if %{use_fipscheck}
BuildRequires:	fipscheck-devel fipscheck
%endif
BuildRequires:	groff
%if %{enable_audit_module}
BuildRequires:	audit-devel
%if 0%{?sle_version} >= 120000
Requires:	libaudit1
%else
Requires:	audit-libs
%endif
%endif
%if %{enable_kerberos5}
BuildRequires:	krb5-devel
Requires:	krb5
%endif
BuildRoot:	%{_tmppath}/%{name}-%{version}-build

%if 0%{?sle_version} >= 120000
Source0:	https://roumenpetrov.info/secsh/src/%{name}-%{version}.tar.xz
%else
Source0:	https://roumenpetrov.info/secsh/src/%{name}-%{version}.tar.gz
%endif


# Default values for additional components

%define ssh_sysconfdir		%{_sysconfdir}/ssh
%define ssh_libexecdir		%{_libexecdir}/ssh
%define ssh_privsep_path	/var/lib/sshd

# Define the UID/GID to use for privilege separation
%define sshd_gid	475
%define sshd_uid	472

%define systemd_servicedir	/usr/lib/systemd/system

%if %{defined _distconfdir}
  %define pam_sysconfdir 	%{_distconfdir}/pam.d
%else
  %define pam_sysconfdir 	%{_sysconfdir}/pam.d
%endif

%if !%{defined _fillupdir}
 %define _fillupdir /var/adm/fillup-templates
%endif


%description
Ssh (Secure Shell) is a program for logging into a remote machine and for
executing commands in a remote machine.  It is intended to replace
rlogin and rsh, and provide secure encrypted communications between
two untrusted hosts over an insecure network.


%prep
%setup -q


%build
%configure \
  --prefix=/usr \
  --libexecdir=%{ssh_libexecdir} \
  --sysconfdir=%{ssh_sysconfdir} \
  --mandir=%{_mandir} \
%if %{enable_ldap}
  --enable-ldap --with-ldap-libexecdir=%{ldap_libexecdir} \
%else
  --disable-ldap \
%endif
%if %{enable_openssl_fips}
  --enable-openssl-fips \
%else
  --disable-openssl-fips \
%endif
%if %{enable_audit_module}
  --with-audit=linux \
%endif
%if %{enable_kerberos5}
  --with-kerberos5 \
%else
  --without-kerberos5 \
%endif
%if %{enable_dsa}
  --enable-dsa \
%else
  --disable-dsa \
%endif
%if %{enable_ssl_engine}
  --with-ssl-engine \
%else
  --without-ssl-engine \
%endif
%if %{enable_systemd}
  --with-systemd \
%else
  --without-systemd \
%endif
  --with-pie \
  --with-pam \
  --with-privsep-path=%{ssh_privsep_path}
make


%check
%if !0%{enable_dsa_ca}
SSH_CAKEY_TYPE_DSA= \
%endif
TERM=dumb \
make check

%if %{enable_ldap_test}
%if 0%{?sle_version} < 120000 && !0%{?is_opensuse}
SSH_LDAP_DB=hdb \
%endif
LDAP_MODULEDIR=%{ldap_moduledir} \
%if !0%{enable_dsa_ca}
SSH_CAKEY_TYPE_DSA= \
%endif
TERM=dumb \
SSH_X509TESTS="by_ldap" \
make check-certs
%endif

TERM=dumb \
make t-exec LTESTS=percent || :

TERM=dumb \
make t-exec LTESTS=multiplex || :

%if %{enable_fips_test}
# ignore failures as tests are sensitive to used sandbox
TERM=dumb \
make t-exec LTESTS=fips-connect-privsep || :
TERM=dumb \
make t-exec LTESTS=fips-try-ciphers || :
%endif


%install
make install DESTDIR=%{buildroot}

install -d %{buildroot}%{pam_sysconfdir}
install -m644 contrib/sshd.pam.generic %{buildroot}%{pam_sysconfdir}/sshd

%if !%{enable_systemd}
install -d %{buildroot}%{_sysconfdir}/init.d
install -m744 contrib/suse/rc.sshd %{buildroot}%{_sysconfdir}/init.d/sshd
%endif

%if %{enable_systemd}
install -d %{buildroot}%{systemd_servicedir}
install -m644 contrib/suse/sshd.service.out %{buildroot}%{systemd_servicedir}/sshd.service
%endif

install -d %{buildroot}%{_fillupdir}
install -m744 contrib/suse/sysconfig.ssh %{buildroot}%{_fillupdir}


#obsolete#%clean


%pre
/usr/sbin/groupadd -g %{sshd_gid} -o -r sshd 2> /dev/null || :
/usr/sbin/useradd -r -o -g sshd -u %{sshd_uid} -s /bin/false -c "SSH daemon" -d %{ssh_privsep_path} sshd 2> /dev/null || :


%post
/usr/bin/ssh-keygen -A
%if 0%{?sles_version} == 11
%run_permissions %{ssh_sysconfdir}/ssh_config
%run_permissions %{ssh_sysconfdir}/sshd_config
%run_permissions %{ssh_sysconfdir}/moduli
%run_permissions %{ssh_libexecdir}/ssh-keysign
%else
%set_permissions %{ssh_sysconfdir}/ssh_config
%set_permissions %{ssh_sysconfdir}/sshd_config
%set_permissions %{ssh_sysconfdir}/moduli
%set_permissions %{ssh_libexecdir}/ssh-keysign
%endif
%if %{enable_systemd}
%{fillup_only -n ssh sshd}
%else
%{fillup_and_insserv -n -y ssh sshd}
%endif


%verifyscript
%verify_permissions -e %{ssh_sysconfdir}/ssh_config
%verify_permissions -e %{ssh_sysconfdir}/sshd_config
%verify_permissions -e %{ssh_sysconfdir}/moduli
%verify_permissions -e %{ssh_libexecdir}/ssh-keysign


%preun
%stop_on_removal sshd
%if %{enable_systemd}
%service_del_preun sshd.service
%endif


%postun
%restart_on_update sshd
%if %{enable_systemd}
%service_del_postun sshd.service
%endif
%if !%{enable_systemd}
%{insserv_cleanup}
%endif


%files
%defattr(-,root,root)
%if 0%{?suse_version} >= 1500
%license LICENCE
%endif
%doc CREDITS LICENCE OVERVIEW PROTOCOL* README*
%doc TODO
%attr(0755,root,root) %dir %{ssh_sysconfdir}
%attr(0644,root,root) %verify(not mode) %config(noreplace) %{ssh_sysconfdir}/ssh_config
%if 0%{?sles_version} == 11
%attr(0640,root,root) %verify(not mode) %config(noreplace) %{ssh_sysconfdir}/sshd_config
%else
%attr(0600,root,root) %verify(not mode) %config(noreplace) %{ssh_sysconfdir}/sshd_config
%endif
%attr(0600,root,root) %verify(not mode) %config(noreplace) %{ssh_sysconfdir}/moduli
%attr(0755,root,root) %dir %{pam_sysconfdir}
%attr(0644,root,root) %config(noreplace) %{pam_sysconfdir}/sshd
%if !%{enable_systemd}
%attr(0755,root,root) %config %{_sysconfdir}/init.d/sshd
%endif
%if %{enable_systemd}
%attr(0644,root,root) %config(noreplace) %{systemd_servicedir}/sshd.service
%endif
%if %{use_fipscheck}
# TODO: installation into fipscheck "lib" directory?
%attr(0644,root,root) %{_bindir}/.ssh.hmac
%attr(0644,root,root) %{_bindir}/.ssh-agent.hmac
%attr(0644,root,root) %{_bindir}/.ssh-keygen.hmac
%attr(0644,root,root) %{_sbindir}/.sshd.hmac
%endif
%attr(0755,root,root) %{_bindir}/scp
%attr(0755,root,root) %{_bindir}/sftp
%attr(0755,root,root) %{_bindir}/ssh
%attr(0755,root,root) %{_bindir}/ssh-add
%attr(0755,root,root) %{_bindir}/ssh-agent
%attr(0755,root,root) %{_bindir}/ssh-keygen
%attr(0755,root,root) %{_bindir}/ssh-keyscan
%attr(0755,root,root) %{_sbindir}/sshd
%attr(0755,root,root) %dir %{ssh_libexecdir}
%attr(0755,root,root) %{ssh_libexecdir}/sftp-server
%if 0
#TODO setuid
%attr(4711,root,root) %verify(not mode) %{ssh_libexecdir}/ssh-keysign
%else
%attr(0755,root,root) %verify(not mode) %{ssh_libexecdir}/ssh-keysign
%endif
%attr(0755,root,root) %{ssh_libexecdir}/ssh-pkcs11-helper
%attr(0644,root,root) %doc %{_mandir}/man1/scp.1*
%attr(0644,root,root) %doc %{_mandir}/man1/sftp.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh-add.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh-agent.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh-keygen.1*
%attr(0644,root,root) %doc %{_mandir}/man1/ssh-keyscan.1*
%attr(0644,root,root) %doc %{_mandir}/man5/moduli.5*
%attr(0644,root,root) %doc %{_mandir}/man5/ssh_config.5*
%attr(0644,root,root) %doc %{_mandir}/man5/ssh_engine.5*
%attr(0644,root,root) %doc %{_mandir}/man5/sshd_config.5*
%attr(0644,root,root) %doc %{_mandir}/man8/sftp-server.8*
%attr(0644,root,root) %doc %{_mandir}/man8/ssh-keysign.8*
%attr(0644,root,root) %doc %{_mandir}/man8/ssh-pkcs11-helper.8*
%attr(0644,root,root) %doc %{_mandir}/man8/sshd.8*
%if 0%{?sles_version} != 11
%attr(0755,root,root) %dir %{_fillupdir}
%endif
%attr(0644,root,root) %{_fillupdir}/sysconfig.ssh

%changelog
#See pkixssh.changes
