#
# spec file for pkixssh package
#
# This is free software; see Copyright file in the source
# distribution for precise wording.
#
# Copyright (c) 2019-2020 Roumen Petrov
#

# Do we want to enable building with ldap? (1=yes 0=no)
%global enable_ldap 1

# Do we want to enable test with ldap? (1=yes 0=no)
%global enable_ldap_test 1

# Do we use FIPS capable OpenSSL library ? (1=yes 0=no)
%global enable_openssl_fips 1

# TODO: do not produce debug package(temporary)
%global debug_package %{nil}


# Disable non-working configurations
%if 0%{?centos_version} >= 800
# No more openldap server package on CentOS 8
%undefine enable_ldap_test
%global enable_ldap_test 0
%endif

%if 0%{?rhel_version} > 0
#TODO 0%{?rhel_version} > 700 ?
%undefine enable_openssl_fips
%global enable_openssl_fips 0
%endif

%global use_fipscheck 1
%if 0%{?fedora} >= 33
%undefine use_fipscheck
%global use_fipscheck 0
%endif


# norootforbuild

Url:		https://roumenpetrov.info/secsh/

Name:		pkixssh
Summary:	PKIX-SSH, Advanced secure shell implementation
Version:	13.1
Release:	1
License:	BSD
Group:		Productivity/Networking/SSH

BuildRequires:	zlib-devel
BuildRequires:	pam-devel
BuildRequires:	openssl-devel openssl
%if %{enable_ldap}
BuildRequires:	openldap-devel openldap openldap-clients
%endif
%if %{enable_ldap_test}
BuildRequires: openldap-servers
%endif
%if %{enable_openssl_fips} && %{use_fipscheck}
BuildRequires:	fipscheck-devel fipscheck
%endif
%if 0%{?centos_version} && 0%{?centos_version} < 700
BuildRequires:	groff
%else
BuildRequires:	groff-base
%endif
BuildRoot:	%{_tmppath}/%{name}-%{version}-build

Source0:	https://roumenpetrov.info/secsh/src/%{name}-%{version}.tar.xz


# Default values for additional components

%define ssh_sysconfdir	%{_sysconfdir}/ssh
%define ssh_libexecdir	%{_libexecdir}/ssh

# Define the UID/GID to use for privilege separation
%define sshd_gid	74
%define sshd_uid	74


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
  --enable-ldap --with-ldap-libexecdir=/usr/sbin \
%else
  --disable-ldap \
%endif
%if %{enable_openssl_fips}
  --enable-openssl-fips \
%else
  --disable-openssl-fips \
%endif
  --with-pie \
  --with-pam \
  --with-privsep-path=%{_var}/empty/sshd
make


%check
TERM=dumb \
make check
%if %{enable_ldap_test}
TERM=dumb \
SSH_X509TESTS="by_ldap" \
make check-certs
%endif


%install
make install DESTDIR=%{buildroot}

install -d %{buildroot}/etc/pam.d/
install -m644 contrib/redhat/sshd.pam %{buildroot}/etc/pam.d/sshd

install -d %{buildroot}/etc/rc.d/init.d/
install -m744 contrib/redhat/sshd.init %{buildroot}/etc/rc.d/init.d/sshd


%clean


%pre
/usr/sbin/groupadd -g %{sshd_gid} -o -r sshd 2> /dev/null || :
/usr/sbin/useradd -r -o -g sshd -u %{sshd_uid} -s /bin/false -c "SSH Privilege Separation User" -d /var/lib/sshd sshd 2> /dev/null || :


%post
/usr/bin/ssh-keygen -A
%{fillup_and_insserv -n -y ssh sshd}
%run_permissions


%verifyscript
%verify_permissions \
  -e %{ssh_sysconfdir}/sshd_config \
  -e %{ssh_sysconfdir}/ssh_config \
  -e %{_bindir}/ssh


%preun
%stop_on_removal sshd


%postun
%restart_on_update sshd
%{insserv_cleanup}


%files
%defattr(-,root,root)
%doc CREDITS LICENCE OVERVIEW PROTOCOL* README*
%doc TODO
%attr(0755,root,root) %dir %{ssh_sysconfdir}
%attr(0644,root,root) %config(noreplace) %{ssh_sysconfdir}/ssh_config
%attr(0600,root,root) %config(noreplace) %{ssh_sysconfdir}/sshd_config
%attr(0600,root,root) %config(noreplace) %{ssh_sysconfdir}/moduli
%attr(0644,root,root) %config(noreplace) /etc/pam.d/sshd
%attr(0755,root,root) %config /etc/rc.d/init.d/sshd
%if %{use_fipscheck}
# TODO: installation into fipscheck "lib" directory
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
#FIXME setuid
%attr(4711,root,root) %{ssh_libexecdir}/ssh-keysign
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


%changelog
# Not managed, please see source repository for changes.
