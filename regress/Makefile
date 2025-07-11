#	$OpenBSD: Makefile,v 1.136 2025/03/11 07:50:20 dtucker Exp $

tests: unit file-tests t-exec
check-core: tests

REGRESS_TARGETS=	t1 t2 t3 t4 t5 t6 t7 t8 t9 t10 t11 t12

# File based tests
file-tests: $(REGRESS_TARGETS)

# Interop tests are not run by default
interop interop-tests: t-exec-interop

extra extra-tests: t-extra

clean:
	rm -rf $(OBJ)copy.dd $(OBJ)copy.dd2 $(OBJ)copy.dd.glob[456]
	for F in $(CLEANFILES); do rm -f $(OBJ)$$F; done
	rm -rf $(OBJ)softhsm
	rm -rf $(OBJ).putty
	rm -rf $(OBJ).dropbear
	rm -rf $(OBJ).ssh

distclean:	clean

LTESTS=		connect \
		proxy-connect \
		connect-privsep \
		connect-uri \
		proto-version \
		proto-mismatch \
		exit-status \
		exit-status-signal \
		envpass \
		transfer \
		banner \
		rekey \
		dhgex \
		stderr-data \
		stderr-after-eof \
		broken-pipe \
		try-ciphers \
		yes-head \
		login-timeout \
		agent \
		agent-getpeereid \
		agent-timeout \
		agent-ptrace \
		agent-subprocess \
		keyscan \
		keygen-change \
		keygen-comment \
		keygen-convert \
		keygen-knownhosts \
		keygen-moduli \
		keygen-sshfp \
		key-options \
		scp \
		scp3 \
		scp-uri \
		sftp \
		sftp-chroot \
		sftp-cmds \
		sftp-badcmds \
		sftp-batch \
		sftp-glob \
		sftp-perm \
		sftp-resume \
		sftp-uri \
		reconfigure \
		dynamic-forward \
		forwarding \
		multiplex \
		reexec \
		brokenkeys \
		sshcfgparse \
		cfgparse \
		cfgmatch \
		cfgmatchlisten \
		addrmatch \
		localcommand \
		forcecommand \
		portnum \
		keytype \
		kextype \
		cert-hostkey \
		cert-userkey \
		host-expand \
		keys-command \
		forward-control \
		integrity \
		krl \
		multipubkey \
		limit-keytype \
		hostkey-agent \
		hostkey-rotate \
		principals-command \
		cert-file \
		cfginclude \
		servcfginclude \
		allow-deny-users \
		authinfo \
		knownhosts \
		knownhosts-command \
		channel-timeout \
		connection-timeout \
		match-subsystem

# portability:
#		percent \
# extra setup:
#		hostbased - see comment in regression test

FIPS_LTESTS=\
	fips-connect-privsep \
	fips-try-ciphers

INTEROP_TESTS=	putty-transfer putty-ciphers putty-kex conch-ciphers
INTEROP_TESTS+=	dropbear-ciphers dropbear-kex
#INTEROP_TESTS+=ssh-com ssh-com-client ssh-com-keygen ssh-com-sftp

EXTRA_TESTS=
#EXTRA_TESTS+=	agent-pkcs11
#EXTRA_TESTS+=	cipher-speed

CLEAN_KEYGEN_CONVERT=	*-key *-key.only-pub *-key-nocomment.pub \
		*-key-rfc *-key-rfc.pub *-rfc-imported \
		*-key-pk8 *-key-pk8.pub *-pk8-imported
CLEANFILES=	*.core actual agent-ca agent-ca.pub agent-key.* authkeys_orig \
		$(CLEAN_KEYGEN_CONVERT) \
		authorized_keys_* \
		authorized_principals_* \
		banner.in banner.out cert_host_key* cert_user_key* \
		batch copy copy.* copy2 data \
		ssh-dss-agent* ssh-dss ssh-dss.pub \
		ssh-ed25519-agent* ssh-ed25519-conch* ssh-ed25519 ssh-ed25519.pub empty.in \
		ecdsa-sha2-nistp256-agent* ecdsa-sha2-nistp256 ecdsa-sha2-nistp256.pub \
		ecdsa-sha2-nistp384-agent* ecdsa-sha2-nistp384 ecdsa-sha2-nistp384.pub \
		ecdsa-sha2-nistp521-agent* ecdsa-sha2-nistp521 ecdsa-sha2-nistp521.pub \
		expect failed-regress.log failed-ssh.log failed-sshd.log \
		finished.* \
		hkr.* host.ecdsa-sha2-nistp256 host.ecdsa-sha2-nistp384 \
		host.ecdsa-sha2-nistp521 host.ssh-dss host.ssh-ed25519 \
		host.ssh-rsa host.ssh-xmss@openssh.com* \
		host_ca_key* host_krl_* host_revoked_* key.* \
		key.dsa-* key.ecdsa-* key.ed25519-512 \
		key.ed25519-512.pub key.rsa-* keys-command-args kh.* askpass \
		known_hosts known_hosts.old known_hosts-cert knownhosts_command \
		krl-* ls.copy no_identity_config \
		pidfile putty.rsa2 ready regress.log remote_pid \
		revoked-* ssh-rsa-agent* ssh-rsa ssh-rsa.pub ssh-rsa_pem ssh-rsa_pem.pub \
		ssh-xmss@openssh.com ssh-xmss@openssh.com.pub \
		rsa_ssh2_cr.prv rsa_ssh2_crnl.prv scp-ssh-wrapper.exe \
		scp-ssh-wrapper.scp sftp-server.log \
		sftp-server.sh sftp.log ssh-log-wrapper.sh ssh.log \
		ssh-agent.log ssh-add.log slow-sftp-server.sh \
		ssh_askpass-pkcs11 \
		ssh-rsa_oldfmt knownhosts_command \
		ssh_config ssh_config.* ssh_proxy ssh_proxy.orig ssh_proxy_* \
		sshd.log sshd_config sshd_config_minimal \
		sshd_config.* sshd_proxy sshd_proxy.* sshd_proxy_bak \
		sshd_proxy_orig t10.out t10.out.pub t12.out t12.out.pub \
		t2.out t3.out t6.out1 t6.out2 t7.out t7.out.pub \
		t8.out t8.out.pub t9.out t9.out.pub testdata \
		unix-*.fwd user_*key* user_ca* user_key*

# Enable all malloc(3) randomisations and checks
TEST_ENV=      "MALLOC_OPTIONS=CFGJRSUX"

TEST_SSH_SSHKEYGEN?=ssh-keygen
TEST_SHELL?=sh
SHELL=$(TEST_SHELL)

DEF_CHECK_ALG=check_alg() { $(TEST_SSH_SSH) -Q key-alg | grep "^$$1" >/dev/null; }

CPPFLAGS=-I..

t1:
	${TEST_SSH_SSHKEYGEN} -if ${.CURDIR}/rsa_ssh2.prv | diff - ${.CURDIR}/rsa_openssh.prv
	tr '\n' '\r' <${.CURDIR}/rsa_ssh2.prv > ${.OBJDIR}/rsa_ssh2_cr.prv
	${TEST_SSH_SSHKEYGEN} -if ${.OBJDIR}/rsa_ssh2_cr.prv | diff - ${.CURDIR}/rsa_openssh.prv
	awk '{print $$0 "\r"}' ${.CURDIR}/rsa_ssh2.prv > ${.OBJDIR}/rsa_ssh2_crnl.prv
	${TEST_SSH_SSHKEYGEN} -if ${.OBJDIR}/rsa_ssh2_crnl.prv | diff - ${.CURDIR}/rsa_openssh.prv

t2:
	cat ${.CURDIR}/rsa_openssh.prv > $(OBJ)/t2.out
	chmod 600 $(OBJ)/t2.out
	${TEST_SSH_SSHKEYGEN} -yf $(OBJ)/t2.out | diff - ${.CURDIR}/rsa_openssh.pub

t3:
	${TEST_SSH_SSHKEYGEN} -ef ${.CURDIR}/rsa_openssh.pub >$(OBJ)/t3.out
	${TEST_SSH_SSHKEYGEN} -if $(OBJ)/t3.out | diff - ${.CURDIR}/rsa_openssh.pub

t4:
	OPENSSL_FIPS=; unset OPENSSL_FIPS || :; \
	${TEST_SSH_SSHKEYGEN} -E md5 -lf ${.CURDIR}/rsa_openssh.pub |\
		awk '{print $$2}' | diff - ${.CURDIR}/t4.ok

t5:
	${TEST_SSH_SSHKEYGEN} -Bf ${.CURDIR}/rsa_openssh.pub |\
		awk '{print $$2}' | diff - ${.CURDIR}/t5.ok

t6:
	$(DEF_CHECK_ALG); if check_alg ssh-dss ; then set -e; \
	${TEST_SSH_SSHKEYGEN} -if ${.CURDIR}/dsa_ssh2.prv > $(OBJ)/t6.out1 ; \
	${TEST_SSH_SSHKEYGEN} -if ${.CURDIR}/dsa_ssh2.pub > $(OBJ)/t6.out2 ; \
	chmod 600 $(OBJ)/t6.out1 ; \
	${TEST_SSH_SSHKEYGEN} -yf $(OBJ)/t6.out1 | diff - $(OBJ)/t6.out2 ; \
	else echo "*** skipped $@ ***" ; fi

$(OBJ)/t7.out:
	${TEST_SSH_SSHKEYGEN} -q -t rsa -N '' -f $@

t7: $(OBJ)/t7.out
	${TEST_SSH_SSHKEYGEN} -lf $(OBJ)/t7.out > /dev/null
	${TEST_SSH_SSHKEYGEN} -Bf $(OBJ)/t7.out > /dev/null

$(OBJ)/t8.out:
	$(DEF_CHECK_ALG); if check_alg ssh-dss ; then \
	${TEST_SSH_SSHKEYGEN} -q -t dsa -N '' -f $@ ; \
	fi

t8: $(OBJ)/t8.out
	$(DEF_CHECK_ALG); if check_alg ssh-dss ; then set -e; \
	${TEST_SSH_SSHKEYGEN} -lf $(OBJ)/t8.out > /dev/null ; \
	${TEST_SSH_SSHKEYGEN} -Bf $(OBJ)/t8.out > /dev/null ; \
	else echo "*** skipped $@ ***" ; fi

$(OBJ)/t9.out:
	$(DEF_CHECK_ALG); if check_alg ecdsa-sha2- ; then \
	${TEST_SSH_SSHKEYGEN} -q -t ecdsa -N '' -f $@ ; \
	fi

t9: $(OBJ)/t9.out
	$(DEF_CHECK_ALG); if check_alg ecdsa-sha2- ; then set -e; \
	${TEST_SSH_SSHKEYGEN} -lf $(OBJ)/t9.out > /dev/null ; \
	${TEST_SSH_SSHKEYGEN} -Bf $(OBJ)/t9.out > /dev/null ; \
	else echo "*** skipped $@ ***" ; fi

$(OBJ)/t10.out:
	${TEST_SSH_SSHKEYGEN} -q -t ed25519 -N '' -f $@

t10: $(OBJ)/t10.out
	${TEST_SSH_SSHKEYGEN} -lf $(OBJ)/t10.out > /dev/null
	${TEST_SSH_SSHKEYGEN} -Bf $(OBJ)/t10.out > /dev/null

t11:
	$(DEF_CHECK_ALG); if check_alg rsa-sha2- ; then \
	${TEST_SSH_SSHKEYGEN} -E sha256 -lf ${.CURDIR}/rsa_openssh.pub |\
		awk '{print $$2}' | diff - ${.CURDIR}/t11.ok ; \
	else echo "*** skipped $@ ***" ; fi

$(OBJ)/t12.out:
	${TEST_SSH_SSHKEYGEN} -q -t ed25519 -N '' -C 'test-comment-1234' -f $@

t12: $(OBJ)/t12.out
	${TEST_SSH_SSHKEYGEN} -lf $(OBJ)/t12.out.pub | grep test-comment-1234 >/dev/null

t-exec:	${LTESTS:=.sh}
	@if [ "x$?" = "x" ]; then exit 0; fi; \
	start_from=false; test -n "$$LTESTS_FROM" && start_from=:; \
	for TEST in ""$?; do \
		if $$start_from ; then \
			test "x$$TEST" != "x$$LTESTS_FROM.sh" && continue; \
			start_from=false; \
		fi ; \
		do_test=:; \
		for t in ""$$SKIP_LTESTS; do \
			if test "$$t.sh" = "$$TEST" ; then do_test=false; break; fi; \
		done; \
		if $$do_test ; then \
			echo "=== run test $$TEST" ... >&2; \
			(env SUDO="${SUDO}" TEST_ENV=${TEST_ENV} ${TEST_SHELL} ${.CURDIR}/test-exec.sh ${.OBJDIR} ${.CURDIR}/$${TEST}) || exit $$?; \
		else \
			echo "=== test $$TEST skipped!" >&2; \
		fi; \
	done

f-exec:	${FIPS_LTESTS:=.sh}
	@if [ "x$?" = "x" ]; then exit 0; fi; \
	for TEST in ""$?; do \
		echo "=== run test $$TEST" ... >&2; \
		(env SUDO="${SUDO}" TEST_ENV=${TEST_ENV} ${TEST_SHELL} ${.CURDIR}/test-exec.sh ${.OBJDIR} ${.CURDIR}/$${TEST}) || exit $$?; \
	done

t-exec-interop:	${INTEROP_TESTS:=.sh}
	@if [ "x$?" = "x" ]; then exit 0; fi; \
	for TEST in ""$?; do \
		echo "=== run test $$TEST" ... >&2; \
		(env SUDO="${SUDO}" TEST_ENV=${TEST_ENV} ${TEST_SHELL} ${.CURDIR}/test-exec.sh ${.OBJDIR} ${.CURDIR}/$${TEST}) || exit $$?; \
	done

t-extra:	${EXTRA_TESTS:=.sh}
	@if [ "x$?" = "x" ]; then exit 0; fi; \
	for TEST in ""$?; do \
		echo "=== run test $$TEST" ... >&2; \
		(env SUDO="${SUDO}" TEST_ENV=${TEST_ENV} ${TEST_SHELL} ${.CURDIR}/test-exec.sh ${.OBJDIR} ${.CURDIR}/$${TEST}) || exit $$?; \
	done

# Not run by default
interop: ${INTEROP_TARGETS}

# Unit tests, built by top-level Makefile
unit:
	set -e ; if test -z "${SKIP_UNIT}" ; then \
		V="" ; \
		test "x${USE_VALGRIND}" = "x" || \
		    V=${.CURDIR}/valgrind-unit.sh ; \
		ARGS="${UNITTEST_ARGS}"; \
	test "x$$UNITTEST_SSHBUF" = "xskip" || \
		$$V ${.OBJDIR}/unittests/sshbuf/test_sshbuf $$ARGS; \
	test "x$$UNITTEST_SSHKEY" = "xskip" || \
		$$V ${.OBJDIR}/unittests/sshkey/test_sshkey \
			-d ${.CURDIR}/unittests/sshkey/testdata $$ARGS; \
	test "x$$UNITTEST_AUTHOPT" = "xskip" || \
		$$V ${.OBJDIR}/unittests/authopt/test_authopt \
			-d ${.CURDIR}/unittests/authopt/testdata $$ARGS; \
	test "x$$UNITTEST_BITMAP" = "xskip" || \
		$$V ${.OBJDIR}/unittests/bitmap/test_bitmap $$ARGS; \
	test "x$$UNITTEST_CONVERSION" = "xskip" || \
		$$V ${.OBJDIR}/unittests/conversion/test_conversion $$ARGS; \
	test "x$$UNITTEST_KEX" = "xskip" || \
		$$V ${.OBJDIR}/unittests/kex/test_kex $$ARGS; \
	test "x$$UNITTEST_HOSTKEYS" = "xskip" || \
		$$V ${.OBJDIR}/unittests/hostkeys/test_hostkeys \
			-d ${.CURDIR}/unittests/hostkeys/testdata $$ARGS; \
	test "x$$UNITTEST_MATCH" = "xskip" || \
		$$V ${.OBJDIR}/unittests/match/test_match $$ARGS; \
	test "x$$UNITTEST_MISC" = "xskip" || \
		$$V ${.OBJDIR}/unittests/misc/test_misc $$ARGS; \
	test "x$$UNITTEST_UTF8" = "xskip" || \
		if test "x${TEST_SSH_UTF8}" = "xyes"  ; then \
			$$V ${.OBJDIR}/unittests/utf8/test_utf8 $$ARGS; \
		fi ; \
	fi
