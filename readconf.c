/* $OpenBSD: readconf.c,v 1.394 2024/12/06 16:21:48 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for reading the configuration files.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2002-2025 Roumen Petrov.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif
#include <limits.h>
#include <netdb.h>
#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#ifdef USE_SYSTEM_GLOB
# include <glob.h>
#else
# include "openbsd-compat/glob.h"
#endif
#ifdef HAVE_UTIL_H
#include <util.h>
#endif
#if defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#include "xmalloc.h"
#include "ssh.h"
#include "cipher.h"
#include "pathnames.h"
#include "log.h"
#include "sshkey.h"
#include "misc.h"
#include "readconf.h"
#include "match.h"
#include "kex.h"
#include "ssh-xkalg.h"
#include "mac.h"
#include "myproposal.h"
#include "digest.h"

/* Format of the configuration file:

   # Configuration data is parsed as follows:
   #  1. command line options
   #  2. user-specific file
   #  3. system-wide file
   # Any configuration value is only changed the first time it is set.
   # Thus, host-specific definitions should be at the beginning of the
   # configuration file, and defaults at the end.

   # Host-specific declarations.  These may override anything above.  A single
   # host may match multiple declarations; these are processed in the order
   # that they are given in.

   Host *.ngs.fi ngs.fi
     User foo

   Host fake.com
     Hostname another.host.name.real.org
     User blaah
     Port 34289
     ForwardX11 no
     ForwardAgent no

   Host books.com
     RemoteForward 9999 shadows.cs.hut.fi:9999
     Ciphers 3des-cbc

   Host fascist.blob.com
     Port 23123
     User tylonen
     PasswordAuthentication no

   Host puukko.hut.fi
     User t35124p
     ProxyCommand ssh-proxy %h %p

   Host *.fr
     PublicKeyAuthentication no

   Host *.su
     Ciphers aes128-ctr
     PasswordAuthentication no

   Host vpn.fake.com
     Tunnel yes
     TunnelDevice 3

   # Defaults for various options
   Host *
     ForwardAgent no
     ForwardX11 no
     PasswordAuthentication yes
     StrictHostKeyChecking yes
     TcpKeepAlive no
     IdentityFile ~/.ssh/identity
     Port 22
     EscapeChar ~

*/

/* used in ssh-rsa.c */
extern int required_rsa_size;

static int read_config_file_depth(const char *filename, struct passwd *pw,
    const char *host, const char *original_host, Options *options,
    int flags, int *activep, int *want_final_pass, int depth);
static int process_config_line_depth(Options *options, struct passwd *pw,
    const char *host, const char *original_host, char *line,
    const char *filename, int linenum, int *activep, int flags,
    int *want_final_pass, int depth);

/* Keyword tokens. */

typedef enum {
	oBadOption,
	/* X.509 Standard Options */
	oHostbasedAlgorithms,
	oPubkeyAlgorithms,
	oX509KeyAlgorithm,
	oAllowedServerCertPurpose,
	oMandatoryCRL,
	oCACertificateFile, oCACertificatePath,
	oCARevocationFile, oCARevocationPath,
	oCAStoreURI,
	oCAldapVersion, oCAldapURL,
	oUserCACertificateFile, oUserCACertificatePath,
	oUserCARevocationFile, oUserCARevocationPath,
	oVAType, oVACertificateFile,
	oVAOCSPResponderURL,
	/* Standard Options */
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, oAddKeysToAgent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, oStrictHostKeyChecking, oCompression,
	oTCPKeepAlive, oNumberOfPasswordPrompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, oHostKeyAlias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	oHostKeyAlgorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, oVerifyHostKeyDNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, oServerAliveCountMax, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	oVisualHostKey,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, oRevokedHostKeys,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	oSecurityKeyProvider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oChannelTimeout,
	oVersionAddendum,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

static struct {
	const char *name;
	OpCodes opcode;
} keywords[] = {
	/* Deprecated options */
	{ "protocol", oIgnore }, /* NB. silently ignored */
	{ "cipher", oDeprecated },
	{ "fallbacktorsh", oDeprecated },
	{ "globalknownhostsfile2", oDeprecated },
	{ "rhostsauthentication", oDeprecated },
	{ "userknownhostsfile2", oDeprecated },
	{ "useroaming", oDeprecated },
	{ "usersh", oDeprecated },
	{ "useprivilegedport", oDeprecated },
	{ "rsaauthentication", oDeprecated },
	{ "rhostsrsaauthentication", oDeprecated },
	{ "skeyauthentication", oDeprecated },
	{ "tisauthentication", oDeprecated },
	{ "compressionlevel", oDeprecated },

	/* Unsupported options */
	{ "afstokenpassing", oUnsupported },
	{ "kerberosauthentication", oUnsupported },
	{ "kerberostgtpassing", oUnsupported },

	/* Sometimes-unsupported options */
#if defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# else
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "smartcarddevice", oDeprecated },
	{ "pkcs11provider", oPKCS11Provider },
# else
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#endif
	{ "securitykeyprovider", oSecurityKeyProvider },

	/* X.509 Standard Options */
	{ "hostbasedalgorithms", oHostbasedAlgorithms },
	{ "pubkeyalgorithms", oPubkeyAlgorithms },
	{ "x509keyalgorithm", oX509KeyAlgorithm },
	{ "allowedcertpurpose", oAllowedServerCertPurpose },
	{ "mandatorycrl", oMandatoryCRL },
	{ "cacertificatefile", oCACertificateFile },
	{ "cacertificatepath", oCACertificatePath },
	{ "carevocationfile", oCARevocationFile },
	{ "carevocationpath", oCARevocationPath },
	{ "castoreuri", oCAStoreURI }, /* experimental, i.e. no documentation */
	{ "caldapversion", oCAldapVersion },
	{ "caldapurl", oCAldapURL },
	{ "usercacertificatefile", oUserCACertificateFile },
	{ "usercacertificatepath", oUserCACertificatePath },
	{ "usercarevocationfile", oUserCARevocationFile },
	{ "usercarevocationpath", oUserCARevocationPath },
	{ "usercaldapversion", oCAldapVersion },
	{ "usercaldapurl", oCAldapURL },
	{ "vatype", oVAType },
	{ "vacertificatefile", oVACertificateFile },
	{ "vaocspresponderurl", oVAOCSPResponderURL },
	/* Standard Options */
	{ "forwardagent", oForwardAgent },
	{ "forwardx11", oForwardX11 },
	{ "forwardx11trusted", oForwardX11Trusted },
	{ "forwardx11timeout", oForwardX11Timeout },
	{ "exitonforwardfailure", oExitOnForwardFailure },
	{ "xauthlocation", oXAuthLocation },
	{ "gatewayports", oGatewayPorts },
	{ "passwordauthentication", oPasswordAuthentication },
	{ "kbdinteractiveauthentication", oKbdInteractiveAuthentication },
	{ "kbdinteractivedevices", oKbdInteractiveDevices },
	{ "challengeresponseauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "pubkeyauthentication", oPubkeyAuthentication },
	{ "dsaauthentication", oPubkeyAuthentication },		    /* alias */
	{ "hostbasedauthentication", oHostbasedAuthentication },
	{ "identityfile", oIdentityFile },
	{ "identityfile2", oIdentityFile },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", oAddKeysToAgent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", oHostKeyAlias },
	{ "proxycommand", oProxyCommand },
	{ "port", oPort },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", oMatch },
	{ "tag", oTag },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", oGlobalKnownHostsFile },
	{ "userknownhostsfile", oUserKnownHostsFile },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", oBatchMode },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", oStrictHostKeyChecking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", oNumberOfPasswordPrompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", oHostKeyAlgorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", oVerifyHostKeyDNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", oServerAliveCountMax },
	{ "sendenv", oSendEnv },
	{ "setenv", oSetEnv },
	{ "controlpath", oControlPath },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", oHashKnownHosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", oVisualHostKey },
	{ "kexalgorithms", oKexAlgorithms },
	{ "ipqos", oIPQoS },
	{ "requesttty", oRequestTTY },
	{ "sessiontype", oSessionType },
	{ "stdinnull", oStdinNull },
	{ "forkafterauthentication", oForkAfterAuthentication },
	{ "proxyusefdpass", oProxyUseFdpass },
	{ "canonicaldomains", oCanonicalDomains },
	{ "canonicalizefallbacklocal", oCanonicalizeFallbackLocal },
	{ "canonicalizehostname", oCanonicalizeHostname },
	{ "canonicalizemaxdots", oCanonicalizeMaxDots },
	{ "canonicalizepermittedcnames", oCanonicalizePermittedCNAMEs },
	{ "streamlocalbindmask", oStreamLocalBindMask },
	{ "streamlocalbindunlink", oStreamLocalBindUnlink },
	{ "revokedhostkeys", oRevokedHostKeys },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },

	{ NULL, oBadOption }
};

static const char *lookup_opcode_name(OpCodes code);

char *
ssh_connection_hash(const char *thishost, const char *host, const char *portstr,
    const char *user, const char *jumphost)
{
	struct ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	if ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == NULL ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, sizeof(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	return tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

void
add_local_forward(Options *options, const struct Forward *newfwd)
{
	struct Forward *fwd;
	int i;

	/* Don't add duplicates */
	for (i = 0; i < options->num_local_forwards; i++) {
		if (forward_equals(newfwd, options->local_forwards + i))
			return;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->num_local_forwards + 1,
	    sizeof(*options->local_forwards));
	fwd = &options->local_forwards[options->num_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

void
add_remote_forward(Options *options, const struct Forward *newfwd)
{
	struct Forward *fwd;
	int i;

	/* Don't add duplicates */
	for (i = 0; i < options->num_remote_forwards; i++) {
		if (forward_equals(newfwd, options->remote_forwards + i))
			return;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->num_remote_forwards + 1,
	    sizeof(*options->remote_forwards));
	fwd = &options->remote_forwards[options->num_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

static void
clear_forwardings(Options *options)
{
	int i;

	for (i = 0; i < options->num_local_forwards; i++) {
		free(options->local_forwards[i].listen_host);
		free(options->local_forwards[i].listen_path);
		free(options->local_forwards[i].connect_host);
		free(options->local_forwards[i].connect_path);
	}
	if (options->num_local_forwards > 0) {
		free(options->local_forwards);
		options->local_forwards = NULL;
	}
	options->num_local_forwards = 0;
	for (i = 0; i < options->num_remote_forwards; i++) {
		free(options->remote_forwards[i].listen_host);
		free(options->remote_forwards[i].listen_path);
		free(options->remote_forwards[i].connect_host);
		free(options->remote_forwards[i].connect_path);
	}
	if (options->num_remote_forwards > 0) {
		free(options->remote_forwards);
		options->remote_forwards = NULL;
	}
	options->num_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

void
add_certificate_file(Options *options, const char *path, int userprovided)
{
	int i;

	if (options->num_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	for (i = 0; i < options->num_certificate_files; i++) {
		if (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			return;
		}
	}

	options->certificate_file_userprovided[options->num_certificate_files] =
	    userprovided;
	options->certificate_files[options->num_certificate_files++] =
	    xstrdup(path);
}

void
add_identity_file(Options *options, const char *dir, const char *filename,
    int userprovided)
{
	char *path;
	int i;

	if (options->num_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	if (dir == NULL) /* no dir, filename is absolute */
		path = xstrdup(filename);
	else if (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	for (i = 0; i < options->num_identity_files; i++) {
		if (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			free(path);
			return;
		}
	}

	options->identity_file_userprovided[options->num_identity_files] =
	    userprovided;
	options->identity_files[options->num_identity_files++] = path;
}

int
default_ssh_port(void)
{
	static int port;
	struct servent *sp;

	if (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	return port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
static int
execute_in_shell(const char *cmd)
{
	char *shell;
	pid_t pid;
	int status;

	if ((shell = getenv("SHELL")) == NULL)
		shell = _PATH_BSHELL;

	if (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	if ((pid = fork()) == 0) {
		char *argv[4];

		if (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = NULL;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	if (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	while (waitpid(pid, &status, 0) == -1) {
		if (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	if (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		return -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	return WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
static int
check_match_ifaddrs(const char *addrlist)
{
#ifdef HAVE_GETIFADDRS
	struct ifaddrs *ifa, *ifaddrs = NULL;
	int r, found = 0;
	char addr[NI_MAXHOST];
	socklen_t salen;

	if (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		return 0;
	}
	for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_name == NULL ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			continue;
		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			salen = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			salen = sizeof(struct sockaddr_in6);
			break;
#ifdef AF_LINK
		case AF_LINK:
			/* ignore */
			continue;
#endif /* AF_LINK */
		default:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			continue;
		}
		if ((r = getnameinfo(ifa->ifa_addr, salen, addr, sizeof(addr),
		    NULL, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			continue;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		if (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			break;
		}
	}
	freeifaddrs(ifaddrs);
	return found;
#else /* HAVE_GETIFADDRS */
	UNUSED(addrlist);
	error("match localnetwork: not supported on this platform");
	return 0;
#endif /* HAVE_GETIFADDRS */
}

/*
 * Expand client "TOKENS", caller must free returned value.
 */
static char*
expand_tokens(const char *arg, Options *options,
    struct passwd *pw, const char *host_arg, const char *original_host,
    int final_pass, int is_include_path)
{
	char thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	char uidstr[32];
	const char *ruser, *host, *conn_hash_hex, *keyalias, *jmphost;
	char *ret;
	int port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == NULL ? pw->pw_name : options->user;
	if (final_pass) {
		host = xstrdup(options->hostname);
	} else if (options->hostname != NULL) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (char *)NULL);
	} else {
		host = xstrdup(host_arg);
	}
	if (gethostname(thishost, sizeof(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, sizeof(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, sizeof(portstr), "%d", port);
	snprintf(uidstr, sizeof(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_key_alias ? options->host_key_alias : host;

	/* keep synchronised with sshconnect.h */
	ret = (is_include_path ? percent_dollar_expand : percent_expand)(arg,
	    "C", conn_hash_hex,
	    "L", shorthost,
	    "i", uidstr,
	    "k", keyalias,
	    "l", thishost,
	    "n", original_host,
	    "p", portstr,
	    "h", host,
	    "r", ruser,
	    "d", pw->pw_dir,
	    "u", pw->pw_name,
	    "j", jmphost,
	    (char *)NULL);
	free((void*)host);
	free((void*)conn_hash_hex);
	return ret;
}

/*
 * Parse and execute a Match directive.
 */
static int
match_cfg_line(Options *options, char **condition, struct passwd *pw,
    const char *host_arg, const char *original_host, int final_pass,
    int *want_final_pass, const char *filename, int linenum)
{
	char *arg, *oattrib, *attrib, *cp = *condition, *host;
	const char *ruser;
	int r, result = 1, attributes = 0;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == NULL ? pw->pw_name : options->user;
	if (final_pass) {
		host = xstrdup(options->hostname);
	} else if (options->hostname != NULL) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (char *)NULL);
	} else {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    cp, host, original_host);
	while ((oattrib = attrib = strdelim(&cp)) && *attrib != '\0') {
		char *criteria = NULL;
		int this_result = 1;
		int negate = attrib[0] == '!';

		if (negate)
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		if (strcasecmp(attrib, "all") == 0) {
			if (attributes > 1 || ((arg = strdelim(&cp)) != NULL &&
			    *arg != '\0')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				goto out;
			}
			if (result)
				result = negate ? 0 : 1;
			goto out;
		}
		attributes++;
		/* Criteria "final" and "canonical" have no argument */
		if (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" then remember
			 * this so we can perform a second pass later.
			 */
			if (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != NULL)
				*want_final_pass = 1;
			r = !!final_pass;  /* force bitmask member to boolean */
			if (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			continue;
		}
		/* All other criteria require an argument */
		if ((arg = strdelim(&cp)) == NULL ||
		    *arg == '\0') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			goto out;
		}
		if (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			if (r == (negate ? 1 : 0))
				this_result = result = 0;
		} else if (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			if (r == (negate ? 1 : 0))
				this_result = result = 0;
		} else if (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			if (r == (negate ? 1 : 0))
				this_result = result = 0;
		} else if (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			if (r == (negate ? 1 : 0))
				this_result = result = 0;
		} else if (strcasecmp(attrib, "localnetwork") == 0) {
			if (addr_match_cidr_list(NULL, arg) == -1) {
				/* Error already printed */
				result = -1;
				goto out;
			}
			r = check_match_ifaddrs(arg) == 1;
			if (r == (negate ? 1 : 0))
				this_result = result = 0;
		} else if (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == NULL ? "" :
			    options->tag);
			r = match_pattern_list(criteria, arg, 0) == 1;
			if (r == (negate ? 1 : 0))
				this_result = result = 0;
		} else if (strcasecmp(attrib, "exec") == 0) {
			char *cmd = expand_tokens(arg, options, pw, host_arg,
			    original_host, final_pass, 0);
			if (cmd == NULL) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			if (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				free(cmd);
				continue;
			}
			r = execute_in_shell(cmd);
			if (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			free(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			if (r == (negate ? 1 : 0))
				this_result = result = 0;
		} else {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			goto out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s'",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == NULL ? "" : " \"",
		    criteria == NULL ? "" : criteria,
		    criteria == NULL ? "" : "\"");
		free(criteria);
	}
	if (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		goto out;
	}
 out:
	if (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	*condition = cp;
	free(host);
	return result;
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
static OpCodes
parse_token(const char *cp, const char *filename, int linenum,
    const char *ignored_unknown)
{
	int i;

	for (i = 0; keywords[i].name; i++)
		if (strcmp(cp, keywords[i].name) == 0)
			return keywords[i].opcode;
	if (ignored_unknown != NULL &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		return oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	return oBadOption;
}

static int
parse_time(const char *arg, const char *filename, int linenum)
{
	long t = convtime(arg);

	if (t == -1) {
		error("%s line %d: invalid time value.", filename, linenum);
		return -1;
	}
#if SIZEOF_LONG_INT > SIZEOF_INT
	if (t > INT_MAX) {
		error("%s line %d: too high time value.", filename, linenum);
		return -1;
	}
#endif
	return (int)t;  /*safe cast*/
}

static void
free_canon_cnames(struct allowed_cname *cnames, u_int n)
{
	u_int i;

	if (cnames == NULL || n == 0)
		return;
	for (i = 0; i < n; i++) {
		free(cnames[i].source_list);
		free(cnames[i].target_list);
	}
	free(cnames);
}

/* Multistate option parsing */
struct multistate {
	const char *key;
	int value;
};
/* use true and false at end for compatibility */
static const struct multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ "true",			1 },
	{ "false",			0 },
	{ NULL, -1 }
};
static const struct multistate multistate_yesnoask[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "true",			1 },
	{ "false",			0 },
	{ NULL, -1 }
};
static const struct multistate multistate_strict_hostkey[] = {
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ NULL, -1 }
};
static const struct multistate multistate_yesnoaskconfirm[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ "true",			1 },
	{ "false",			0 },
	{ NULL, -1 }
};
static const struct multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ NULL, -1 }
};
static const struct multistate multistate_controlmaster[] = {
	{ "yes",			SSHCTL_MASTER_YES },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ "true",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ NULL, -1 }
};
static const struct multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "no",				SSH_TUNMODE_NO },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ NULL, -1 }
};
static const struct multistate multistate_requesttty[] = {
	{ "yes",			REQUEST_TTY_YES },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ "true",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ NULL, -1 }
};
static const struct multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ NULL, -1 }
};
static const struct multistate multistate_canonicalizehostname[] = {
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ NULL, -1 }
};

static int
parse_multistate_value(const char *arg, const struct multistate *multistate_ptr,
    const char *filename, int linenum, const char* keyword)
{
	int i;

	if (arg == NULL || *arg == '\0') {
		error("%s line %d: %s missing argument.",
		    filename, linenum, keyword);
		return -1;
	}
	for (i = 0; multistate_ptr[i].key != NULL; i++) {
		if (strcasecmp(arg, multistate_ptr[i].key) == 0)
			return multistate_ptr[i].value;
	}
	return -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
int
process_config_line(Options *options, struct passwd *pw, const char *host,
    const char *original_host, char *line, const char *filename,
    int linenum, int *activep, int flags)
{
	return process_config_line_depth(options, pw, host, original_host,
	    line, filename, linenum, activep, flags, NULL, 0);
}

#define WHITESPACE " \t\r\n"
static int
process_config_line_depth(Options *options, struct passwd *pw, const char *host,
    const char *original_host, char *line, const char *filename,
    int linenum, int *activep, int flags, int *want_final_pass, int depth)
{
	char *str, **charptr, *endofnumber, *keyword, *arg, *arg2;
	char **oav = NULL, **av;
	int oac = 0, ac;
	char **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	int r, oactive, negated, opcode, *intptr, value, value2, cmdline = 0, found;
	int remotefwd, dynamicfwd, ca_only;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	struct Forward fwd;
	const struct multistate *multistate_ptr;
	glob_t gl;
	const char *errstr;
	int ret = -1;
	struct allowed_cname *cnames = NULL;
	u_int ncnames = 0;
	char **strs = NULL; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	if (activep == NULL) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	if ((len = strlen(line)) == 0)
		return 0;
	for (len--; len > 0; len--) {
		if (strchr(WHITESPACE "\f", line[len]) == NULL)
			break;
		line[len] = '\0';
	}

	str = line;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	if ((keyword = strdelim(&str)) == NULL)
		return 0;
	/* Ignore leading whitespace. */
	if (*keyword == '\0')
		keyword = strdelim(&str);
	if (keyword == NULL || *keyword == '\0' || *keyword == '\n' || *keyword == '#')
		return 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	if (str != NULL)
		str += strspn(str, WHITESPACE);
	if (str == NULL || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		return -1;
	}

	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);

	if (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		return -1;
	}
	ac = oac;
	av = oav;
	ca_only = 0;

	switch (opcode) {
	case oBadOption:
		/* don't panic, but count bad options */
		goto out;
	case oIgnore:
		argv_consume(&ac);
		break;
	case oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		break;
	/* X.509 Standard Options */
	case oHostbasedAcceptedAlgorithms:	/* compatibility ;) */
	case oHostbasedAlgorithms:
		charptr = (char**)&options->hostbased_algorithms;
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		/* cannot validate here - depend from X509KeyAlgorithm */
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		break;

	case oPubkeyAcceptedAlgorithms:		/* compatibility ;) */
	case oPubkeyAlgorithms:
		charptr = (char**)&options->pubkey_algorithms;
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		/* cannot validate here - depend from X509KeyAlgorithm */
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		break;

	case oX509KeyAlgorithm:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}

		if (*activep) {
			if (ssh_add_x509key_alg(arg) < 0) {
				error("%.200s line %d: Bad X.509 key algorithm '%.200s'.",
				    filename, linenum, arg);
				goto out;
			}
		}
		break;

	case oAllowedServerCertPurpose:
		intptr = &options->x509flags->allowedcertpurpose;
		arg = argv_next(&ac, &av);
		if (arg != NULL && *arg != '\0') {
			if (strcasecmp(arg, "skip") == 0) goto skip_purpose;

			/* convert string to OpenSSL index */
			value = ssh_get_x509purpose_s (0, arg);
			if (value < 0) {
				error("%.200s line %d: Bad certificate purpose '%.30s'.",
				    filename, linenum, arg);
				goto out;
			}

			if (*activep && *intptr == -1)
				*intptr = value;
		} else {
skip_purpose:
			if (*activep && *intptr == -1) {
				*intptr = -2;
				verbose("%.200s line %d: option is set to don`t check certificate purpose.",
				    filename, linenum);
			}
		}
		break;

	case oMandatoryCRL:
		intptr = &options->x509flags->mandatory_crl;
		goto parse_flag;

	case oCACertificateFile:
		/*X509StoreOptions preffered type is 'const char*' */
		charptr = (char**)&options->ca.certificate_file;
		goto parse_string;

	case oCACertificatePath:
		/*X509StoreOptions preffered type is 'const char*' */
		charptr = (char**)&options->ca.certificate_path;
		goto parse_string;

	case oCARevocationFile:
		/*X509StoreOptions preffered type is 'const char*' */
		charptr = (char**)&options->ca.revocation_file;
		goto parse_string;

	case oCARevocationPath:
		/*X509StoreOptions preffered type is 'const char*' */
		charptr = (char**)&options->ca.revocation_path;
		goto parse_string;

	case oUserCACertificateFile:
		/*X509StoreOptions preffered type is 'const char*' */
		charptr = (char**)&options->userca.certificate_file;
		goto parse_string;

	case oUserCACertificatePath:
		/*X509StoreOptions preffered type is 'const char*' */
		charptr = (char**)&options->userca.certificate_path;
		goto parse_string;

	case oUserCARevocationFile:
		/*X509StoreOptions preffered type is 'const char*' */
		charptr = (char**)&options->userca.revocation_file;
		goto parse_string;

	case oUserCARevocationPath:
		/*X509StoreOptions preffered type is 'const char*' */
		charptr = (char**)&options->userca.revocation_path;
		goto parse_string;

#ifdef USE_OPENSSL_STORE2
	case oCAStoreURI:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		opt_array_append(filename, linenum, "CAStoreURI",
		    (char***)&options->store_uri, &options->num_store_uri,
		    arg);
		break;
#endif /*def USE_OPENSSL_STORE2*/

#ifdef LDAP_ENABLED
	case oCAldapVersion:
		charptr = (char**)&options->ca_ldap_ver;
		goto parse_string;
	case oCAldapURL:
		charptr = (char**)&options->ca_ldap_url;
		goto parse_string;
#endif /*def LDAP_ENABLED*/

#ifdef SSH_OCSP_ENABLED
	case oVAType:
		intptr = &options->va.type;
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}

		value = ssh_get_vatype_s(arg);
		if (value < 0) {
			error("%.200s line %d: Bad OCSP responder type '%.30s'.",
			    filename, linenum, arg);
			goto out;
		}

		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oVACertificateFile:
		/* VAOptions preffered type is 'const char*' */
		charptr = (char**)&options->va.certificate_file;
		goto parse_string;

	case oVAOCSPResponderURL:
		/* VAOptions preffered type is 'const char*' */
		charptr = (char**)&options->va.responder_url;
		goto parse_string;
#endif /*def SSH_OCSP_ENABLED*/
	/* Other Standard Options */
	case oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			goto out;
		}
		if (strcmp(arg, "none") == 0)
			value = -1;
		else {
			value = parse_time(arg, filename, linenum);
			if (value == -1) goto out;
		}
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		value = parse_multistate_value(arg, multistate_flag,
		    filename, linenum, keyword);
		if (value != -1) {
			if (*activep && *intptr == -1)
				*intptr = value;
			break;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		if (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		goto parse_agent_path;

	case oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		value = parse_multistate_value(arg, multistate_ptr,
		    filename, linenum, keyword);
		if (value == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			goto out;
		}
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		goto parse_flag;

	case oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		goto parse_time;

	case oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		goto parse_flag;

	case oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		goto parse_flag;

	case oPasswordAuthentication:
		intptr = &options->password_authentication;
		goto parse_flag;

	case oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		goto parse_flag;

	case oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		goto parse_string;

	case oPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		goto parse_flag;

	case oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		goto parse_flag;

	case oGssAuthentication:
		intptr = &options->gss_authentication;
		goto parse_flag;

	case oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		goto parse_flag;

	case oBatchMode:
		intptr = &options->batch_mode;
		goto parse_flag;

	case oCheckHostIP:
		intptr = &options->check_host_ip;
		goto parse_flag;

	case oVerifyHostKeyDNS:
		intptr = &options->verify_host_key_dns;
		multistate_ptr = multistate_yesnoask;
		goto parse_multistate;

	case oStrictHostKeyChecking:
		intptr = &options->strict_host_key_checking;
		multistate_ptr = multistate_strict_hostkey;
		goto parse_multistate;

	case oCompression:
		intptr = &options->compression;
		goto parse_flag;

	case oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		goto parse_flag;

	case oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		goto parse_flag;

	case oNumberOfPasswordPrompts:
		intptr = &options->number_of_password_prompts;
		goto parse_int;

	case oRekeyLimit:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if (strcmp(arg, "default") == 0) {
			val64 = 0;
		} else {
			if (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				goto out;
			}
			if (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				goto out;
			}
		}
		if (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		if (ac > 0) { /* optional rekey interval present */
			if (strcmp(av[0], "none") == 0) {
				(void)argv_next(&ac, &av);	/* discard */
				break;
			}
			intptr = &options->rekey_interval;
			goto parse_time;
		}
		break;

	case oIdentityFile:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if (*activep) {
			intptr = &options->num_identity_files;
			if (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				goto out;
			}
			add_identity_file(options, NULL,
			    arg, flags & SSHCONF_USERCONF);
		}
		break;

	case oCertificateFile:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if (*activep) {
			intptr = &options->num_certificate_files;
			if (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				goto out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		break;

	case oXAuthLocation:
		charptr=&options->xauth_location;
		goto parse_string;

	case oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		break;

	case oGlobalKnownHostsFile:
		cpptr = (char **)&options->system_hostfiles;
		uintptr = &options->num_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		found = *uintptr > 0;
		i = 0;
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			if (strcasecmp(arg, "none") == 0) {
				if (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			i++;
			if (*activep && !found) {
				if ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries", filename, linenum,
					    keyword);
					goto out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		break;

	case oUserKnownHostsFile:
		cpptr = (char **)&options->user_hostfiles;
		uintptr = &options->num_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		goto parse_char_array;

	case oHostname:
		charptr = &options->hostname;
		goto parse_string;

	case oTag:
		charptr = &options->tag;
		goto parse_string;

	case oHostKeyAlias:
		charptr = &options->host_key_alias;
		goto parse_string;

	case oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		goto parse_string;

	case oBindAddress:
		charptr = &options->bind_address;
		goto parse_string;

	case oBindInterface:
		charptr = &options->bind_interface;
		goto parse_string;

	case oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		goto parse_string;

#ifdef ENABLE_SK
	case oSecurityKeyProvider:
		charptr = &options->sk_provider;
		goto parse_string;
#endif

	case oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		goto parse_command;

	case oProxyCommand:
		charptr = &options->proxy_command;
		/* Ignore ProxyCommand if ProxyJump already specified */
		if (options->jump_host != NULL)
			charptr = &options->jump_host; /* Skip below */
parse_command:
		len = strspn(str, WHITESPACE "=");
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		break;

	case oProxyJump:
		len = strspn(str, WHITESPACE "=");
		if (parse_jump(str + len, options, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			goto out;
		}
		argv_consume(&ac);
		break;

	case oPort:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		value = a2port(arg);
		if (value <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			goto out;
		}
		if (*activep && options->port == -1)
			options->port = value;
		break;

	case oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		if ((errstr = atoi_err(arg, &value)) != NULL) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			goto out;
		}
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oCiphers:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		if (*activep && options->ciphers == NULL)
			options->ciphers = xstrdup(arg);
		break;

	case oMacs:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		if (*activep && options->macs == NULL)
			options->macs = xstrdup(arg);
		break;

	case oKexAlgorithms:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		if (*activep && options->kex_algorithms == NULL)
			options->kex_algorithms = xstrdup(arg);
		break;

	case oHostKeyAlgorithms:
		charptr = &options->hostkeyalgorithms;
parse_key_algorithms:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		/* cannot validate here - depend from X509KeyAlgorithm */
	if (ca_only) {
		if (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
	}
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		break;

	case oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		goto parse_key_algorithms;

	case oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		value = log_level_number(arg);
		if (value == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		if (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) value;
		break;

	case oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		value = log_facility_number(arg);
		if (value == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			goto out;
		}
		if (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) value;
		break;

	case oLogVerbose:
		found = options->num_log_verbose > 0;
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			if (strcasecmp(arg, "none") == 0) {
				if (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		if (*activep && !found) {
			options->log_verbose = strs;
			options->num_log_verbose = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		break;

	case oLocalForward:
	case oRemoteForward:
	case oDynamicForward:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		if (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			if (arg2 == NULL || *arg2 == '\0') {
				if (remotefwd)
					dynamicfwd = 1;
				else {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					goto out;
				}
			} else {
				/* construct a string for parse_forward */
				snprintf(fwdarg, sizeof(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		if (dynamicfwd)
			strlcpy(fwdarg, arg, sizeof(fwdarg));

		if (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			goto out;
		}

		if (*activep) {
			if (remotefwd) {
				add_remote_forward(options, &fwd);
			} else {
				add_local_forward(options, &fwd);
			}
		} else {
			free(fwd.connect_host);
			fwd.connect_host = NULL;
			free(fwd.connect_path);
			fwd.connect_path = NULL;
			free(fwd.listen_host);
			fwd.listen_host = NULL;
			free(fwd.listen_path);
			fwd.listen_path = NULL;
		}
		break;

	case oPermitRemoteOpen: {
		uintptr = &options->num_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr > 0;
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			if (strcmp(arg, "any") == 0 || strcmp(arg, "none") == 0) {
				if (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					free(arg2);
					goto out;
				}
			} else {
			{	char *p = hpdelim(&arg);
				if (p == NULL) {
					error("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
					free(arg2);
					goto out;
				}
				p = cleanhostname(p);
			}
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				if (arg == NULL ||
				    (strcmp(arg, "*") != 0 && a2port(arg) <= 0)) {
					error("%s line %d: bad port number in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
					free(arg2);
					goto out;
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			free(arg2);
		}
		if (*activep && !found) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		} break;

	case oClearAllForwardings:
		intptr = &options->clear_forwardings;
		goto parse_flag;

	case oHost:
		if (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			goto out;
		}
		*activep = 0;
		arg2 = NULL;
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			if ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				break;
			}
			negated = *arg == '!';
			if (negated)
				arg++;
			if (match_pattern(host, arg)) {
				if (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					break;
				}
				if (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		if (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		break;

	case oMatch:
		if (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			goto out;
		}
		value = match_cfg_line(options, &str, pw, host, original_host,
		    flags & SSHCONF_FINAL, want_final_pass,
		    filename, linenum);
		if (value < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			goto out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : value;
		/*
		 * If match_cfg_line() didn't consume all its arguments then
		 * arrange for the extra arguments check below to fail.
		 */
		if (str == NULL || *str == '\0')
			argv_consume(&ac);
		break;

	case oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if (strcmp(arg, "none") == 0)
			value = SSH_ESCAPECHAR_NONE;
		else if (arg[1] == '\0')
			value = (u_char) arg[0];
		else if (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			value = (u_char) arg[1] & 31;
		else {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			goto out;
		}
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		goto parse_multistate;

	case oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		goto parse_flag;

	case oIdentitiesOnly:
		intptr = &options->identities_only;
		goto parse_flag;

	case oServerAliveInterval:
		intptr = &options->server_alive_interval;
		goto parse_time;

	case oServerAliveCountMax:
		intptr = &options->server_alive_count_max;
		goto parse_int;

	case oSendEnv:
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			if (strchr(arg, '=') != NULL) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				goto out;
			}
			if (!*activep)
				continue;
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->num_send_env, arg);
		}
		break;

	case oSetEnv:
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			if (strchr(arg, '=') == NULL) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				goto out;
			}
			if (!*activep)
				continue;
			if (lookup_setenv_in_list(arg, options->setenv,
			    options->num_setenv) != NULL) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				continue;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->setenv, &options->num_setenv, arg);
		}
		break;

	case oControlPath:
		charptr = &options->control_path;
		goto parse_string;

	case oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		goto parse_multistate;

	case oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		value = parse_multistate_value(arg, multistate_flag,
		    filename, linenum, keyword);
		value2 = 0;	/* timeout */
		if (value == -1) {
			value = 1;
			value2 = parse_time(arg, filename, linenum);
			if (value2 == -1) goto out;
		}
		if (*activep && *intptr == -1) {
			*intptr = value;
			options->control_persist_timeout = value2;
		}
		break;

	case oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		goto parse_flag;

	case oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		goto parse_multistate;

	case oTunnelDevice:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		value = a2tun(arg, &value2);
		if (value == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			goto out;
		}
		if (*activep && options->tun_local == -1) {
			options->tun_local = value;
			options->tun_remote = value2;
		}
		break;

	case oLocalCommand:
		charptr = &options->local_command;
		goto parse_command;

	case oPermitLocalCommand:
		intptr = &options->permit_local_command;
		goto parse_flag;

	case oRemoteCommand:
		charptr = &options->remote_command;
		goto parse_command;

	case oVisualHostKey:
		intptr = &options->visual_host_key;
		goto parse_flag;

	case oInclude:
		if (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			goto out;
		}
		value = 0;
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Expand %tokens and environment variables */
			arg2 = arg;
			if ((arg = expand_tokens(arg2,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == NULL) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				continue;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			if (*arg == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, arg2);
				goto out;
			}
			if (!path_absolute(arg) && *arg != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, arg);
			} else
				arg2 = xstrdup(arg);
			free(arg);

			memset(&gl, 0, sizeof(gl));
			r = glob(arg2, GLOB_TILDE, NULL, &gl);
			if (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				free(arg2);
				continue;
			} else if (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				goto out;
			}
			free(arg2);
			oactive = *activep;
			for (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, options,
				    flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				if (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					goto out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				if (r != 1)
					value = -1;
			}
			globfree(&gl);
		}
		if (value != 0)
			ret = value;
		break;

	case oIPQoS:
		arg = argv_next(&ac, &av);
		if ((value = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			goto out;
		}
		arg = argv_next(&ac, &av);
		if (arg == NULL)
			value2 = value;
		else if ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			goto out;
		}
		if (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = value;
			options->ip_qos_bulk = value2;
		}
		break;

	case oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		goto parse_multistate;

	case oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		goto parse_multistate;

	case oStdinNull:
		intptr = &options->stdin_null;
		goto parse_flag;

	case oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		goto parse_flag;

	case oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		goto parse_string;

	case oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		goto parse_flag;

	case oCanonicalDomains:
		found = options->num_canonical_domains > 0;
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			if (strcasecmp(arg, "none") == 0) {
				if (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			}
			if (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				goto out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		if (*activep && !found) {
			options->canonical_domains = strs;
			options->num_canonical_domains = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		break;

	case oCanonicalizePermittedCNAMEs:
		found = options->num_permitted_cnames > 0;
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			if (strcasecmp(arg, "none") == 0) {
				if (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
				arg2 = "";
			} else if (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} else {
				lowercase(arg);
				if ((arg2 = strchr(arg, ':')) == NULL ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					goto out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    sizeof(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		if (*activep && !found) {
			options->permitted_cnames = cnames;
			options->num_permitted_cnames = ncnames;
			cnames = NULL; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		break;

	case oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		goto parse_multistate;

	case oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		goto parse_int;

	case oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		goto parse_flag;

	case oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			goto out;
		}
		/* Parse mode in octal format */
		value = strtol(arg, &endofnumber, 8);
		if (arg == endofnumber || value < 0 || value > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			goto out;
		}
		options->fwd_opts.streamlocal_bind_mask = (mode_t)value;
		break;

	case oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		goto parse_flag;

	case oRevokedHostKeys:
		charptr = &options->revoked_host_keys;
		goto parse_string;

	case oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
		if ((value = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			goto out;
		}
		if (*activep && *intptr == -1)
			*intptr = value;
		break;

	case oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		goto parse_multistate;

	case oAddKeysToAgent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		value = parse_multistate_value(arg, multistate_yesnoaskconfirm,
		    filename, linenum, keyword);
		value2 = 0; /* unlimited lifespan by default */
		if (value == 3 && arg2 != NULL) {
			/* allow "AddKeysToAgent confirm 5m" */
			value2 = parse_time(arg2, filename, linenum);
			if (value2 == -1) goto out;
		} else if (value == -1 && arg2 == NULL) {
			value2 = parse_time(arg, filename, linenum);
			if (value2 == -1) goto out;
			value = 1; /* yes */
		} else if (value == -1 || arg2 != NULL) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			goto out;
		}
		if (*activep && options->add_keys_to_agent == -1) {
			options->add_keys_to_agent = value;
			options->add_keys_to_agent_lifespan = value2;
		}
		break;

	case oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		if (arg == NULL || *arg == '\0') {
			error("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
			goto out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		if ((arg2 = dollar_expand(&r, arg)) == NULL || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			goto out;
		}
		free(arg2);
		/* check for legacy environment format */
		if (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			goto out;
		}
		if (*activep && *charptr == NULL)
			*charptr = xstrdup(arg);
		break;

	case oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		goto parse_flag;

	case oRequiredRSASize:
		intptr = &options->required_rsa_size;
		goto parse_int;

	case oChannelTimeout:
		found = options->num_channel_timeouts > 0;
		while ((arg = argv_next(&ac, &av)) != NULL) {
			if (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				goto out;
			}
			/* Allow "none" only in first position */
			if (strcasecmp(arg, "none") == 0) {
				if (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					goto out;
				}
			} else if (parse_pattern_interval(arg,
			    NULL, NULL) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		if (*activep && !found) {
			options->channel_timeouts = strs;
			options->num_channel_timeouts = nstrs;
			strs = NULL; /* transferred */
			nstrs = 0;
		}
		break;

	case oVersionAddendum:
		len = strspn(str, WHITESPACE);
		if (strchr(str + len, '\r') != NULL) {
			error("%s line %d: keyword %s invalid argument",
			    filename, linenum, keyword);
			goto out;
		}
		if (*activep && options->version_addendum == NULL) {
			if (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			else
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		break;

	case oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		break;

#ifndef USE_OPENSSL_STORE2
	case oCAStoreURI:
#endif
#ifndef LDAP_ENABLED
	case oCAldapVersion:
	case oCAldapURL:
#endif /*ndef LDAP_ENABLED*/
#ifndef SSH_OCSP_ENABLED
	case oVAType:
	case oVACertificateFile:
	case oVAOCSPResponderURL:
#endif /*ndef SSH_OCSP_ENABLED*/
#ifndef ENABLE_SK
	case oSecurityKeyProvider:
#endif
	case oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		break;

	default:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		goto out;
	}

	/* Check that there is no garbage at end of line. */
	if (ac > 0) {
		error("%s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		goto out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, NULL, nstrs);
	argv_free(oav, oac);
	return ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
int
read_config_file(const char *filename, struct passwd *pw, const char *host,
    const char *original_host, Options *options, int flags,
    int *want_final_pass)
{
	int active = 1;

	return read_config_file_depth(filename, pw, host, original_host,
	    options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
static int
read_config_file_depth(const char *filename, struct passwd *pw,
    const char *host, const char *original_host, Options *options,
    int flags, int *activep, int *want_final_pass, int depth)
{
	FILE *f;
	char *line = NULL;
	size_t linesize = 0;
	int linenum;
	int bad_options = 0;

	if (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	if ((f = fopen(filename, "r")) == NULL)
		return 0;

	if (flags & SSHCONF_CHECKPERM) {
		char errmsg[1024];
		if (safe_usr_fileno(fileno(f), filename,
		    errmsg, sizeof(errmsg)) == -1)
			fatal("%s", errmsg);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	while (getline(&line, &linesize, f) != -1) {
		/* strip whitespace, preserve newlines, they are needed
		 * to reproduce line numbers later for error messages
		 */
		char *cp = line + strspn(line, " \t\r");
		/* Update line number counter. */
		linenum++;
		if (process_config_line_depth(options, pw, host, original_host,
		    cp, filename, linenum, activep, flags, want_final_pass,
		    depth) != 0)
			bad_options++;
	}
	free(line);
	fclose(f);
	if (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	return 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
int
option_clear_or_none(const char *o)
{
	return o == NULL || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
int
config_has_permitted_cnames(Options *options)
{
	if (options->num_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		return 0;
	return options->num_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

void
initialize_options(Options * options)
{
	memset(options, 'X', sizeof(*options));
	/* X.509 Standard Options */
	options->hostbased_algorithms = NULL;
	options->pubkey_algorithms = NULL;
	/* Supported X.509 key algorithms and signatures
	   are defined is external source. */
	options->x509flags = &ssh_x509flags;
	ssh_x509flags_initialize(options->x509flags, 0);
	X509StoreOptions_init(&options->ca);
	X509StoreOptions_init(&options->userca);
#ifdef LDAP_ENABLED
	options->ca_ldap_url = NULL;
	options->ca_ldap_ver = NULL;
#endif
#ifdef USE_OPENSSL_STORE2
	options->num_store_uri = 0;
	options->store_uri = NULL;
#endif
#ifdef SSH_OCSP_ENABLED
	options->va.type = -1;
	options->va.certificate_file = NULL;
	options->va.responder_url = NULL;
#endif /*def SSH_OCSP_ENABLED*/
	/* Standard Options */
	options->host_arg = NULL;
	options->forward_agent = -1;
	options->forward_agent_sock_path = NULL;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = NULL;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = NULL;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = NULL;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_key_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->number_of_password_prompts = -1;
	options->ciphers = NULL;
	options->macs = NULL;
	options->kex_algorithms = NULL;
	options->hostkeyalgorithms = NULL;
	options->ca_sign_algorithms = NULL;
	options->num_identity_files = 0;
	options->num_certificate_files = 0;
	options->hostname = NULL;
	options->host_key_alias = NULL;
	options->proxy_command = NULL;
	options->jump_user = NULL;
	options->jump_host = NULL;
	options->jump_port = -1;
	options->jump_extra = NULL;
	options->user = NULL;
	options->escape_char = -1;
	options->num_system_hostfiles = 0;
	options->num_user_hostfiles = 0;
	options->local_forwards = NULL;
	options->num_local_forwards = 0;
	options->remote_forwards = NULL;
	options->num_remote_forwards = 0;
	options->permitted_remote_opens = NULL;
	options->num_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->num_log_verbose = 0;
	options->log_verbose = NULL;
	options->preferred_authentications = NULL;
	options->bind_address = NULL;
	options->bind_interface = NULL;
	options->pkcs11_provider = NULL;
	options->sk_provider = NULL;
	options->enable_ssh_keysign = - 1;
	options->no_host_authentication_for_localhost = - 1;
	options->identities_only = - 1;
	options->rekey_limit = - 1;
	options->rekey_interval = -1;
	options->verify_host_key_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_count_max = -1;
	options->send_env = NULL;
	options->num_send_env = 0;
	options->setenv = NULL;
	options->num_setenv = 0;
	options->control_path = NULL;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = NULL;
	options->permit_local_command = -1;
	options->remote_command = NULL;
	options->add_keys_to_agent = -1;
	options->add_keys_to_agent_lifespan = -1;
	options->identity_agent = NULL;
	options->visual_host_key = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = NULL;
	options->num_canonical_domains = 0;
	options->num_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_keys = NULL;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->known_hosts_command = NULL;
	options->required_rsa_size = -1;
	options->enable_escape_commandline = -1;
	options->tag = NULL;
	options->channel_timeouts = NULL;
	options->num_channel_timeouts = 0;
	options->version_addendum = NULL;
}

void
cleanup_options(Options *options) {
	ssh_x509store_cleanup();
	X509StoreOptions_cleanup(&options->userca);
	X509StoreOptions_cleanup(&options->ca);
	ssh_xkalg_cleanup();

#define FREENULL(p)	{ free((p)); (p) = NULL; }
	/* default algorithms */
	FREENULL(options->hostkeyalgorithms);
	FREENULL(options->hostbased_algorithms);
	FREENULL(options->pubkey_algorithms);

	/* assembled names */
	FREENULL(options->ciphers);
	FREENULL(options->macs);
	FREENULL(options->kex_algorithms);
	FREENULL(options->ca_sign_algorithms);
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
void
fill_default_options_for_canonicalization(Options *options)
{
	if (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	if (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	if (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
int
fill_default_options(Options * options)
{
	int r;

	if (options->forward_agent == -1)
		options->forward_agent = 0;
	if (options->forward_x11 == -1)
		options->forward_x11 = 0;
	if (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	if (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	if (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != NULL ? 1 : 0;
	if (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != NULL ? 1 : 0;
	if (options->clear_forwardings == 1)
		clear_forwardings(options);

	if (options->xauth_location == NULL)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	if (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	if (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	if (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	if (options->pubkey_authentication == -1)
		options->pubkey_authentication = 1;
	if (options->gss_authentication == -1)
		options->gss_authentication = 0;
	if (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	if (options->password_authentication == -1)
		options->password_authentication = 1;
	if (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	if (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	if (options->batch_mode == -1)
		options->batch_mode = 0;
	if (options->check_host_ip == -1)
		options->check_host_ip = 0;
	if (options->strict_host_key_checking == -1)
		options->strict_host_key_checking = SSH_STRICT_HOSTKEY_ASK;
	if (options->compression == -1)
		options->compression = 0;
	if (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = 1;
	if (options->port == -1)
		options->port = 0;	/* filled in ssh client */
	if (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	if (options->connection_attempts == -1)
		options->connection_attempts = 1;
	if (options->number_of_password_prompts == -1)
		options->number_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	/* HostKeyAlgorithms depend from X509KeyAlgorithm options */
	if (options->add_keys_to_agent == -1) {
		options->add_keys_to_agent = 0;
		options->add_keys_to_agent_lifespan = 0;
	}
	if (options->num_identity_files == 0) {
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_RSA, 0);
#ifdef OPENSSL_HAS_ECC
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_ECDSA, 0);
#endif
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519, 0);
#ifdef WITH_DSA
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_DSA, 0);
#endif
#ifdef WITH_XMSS
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_XMSS, 0);
#endif
	}
	if (options->escape_char == -1)
		options->escape_char = '~';
	if (options->num_system_hostfiles == 0) {
		options->system_hostfiles[options->num_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->num_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	if (options->num_user_hostfiles == 0) {
		options->user_hostfiles[options->num_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->num_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	if (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	if (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	if (options->no_host_authentication_for_localhost == - 1)
		options->no_host_authentication_for_localhost = 0;
	if (options->identities_only == -1)
		options->identities_only = 0;
	if (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	if (options->rekey_limit == -1)
		options->rekey_limit = 0;
	if (options->rekey_interval == -1)
		options->rekey_interval = 0;
	if (options->verify_host_key_dns == -1)
		options->verify_host_key_dns = 0;
	if (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	if (options->server_alive_count_max == -1)
		options->server_alive_count_max = 3;
	if (options->control_master == -1)
		options->control_master = 0;
	if (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	if (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	if (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	if (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	if (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	if (options->permit_local_command == -1)
		options->permit_local_command = 0;
	if (options->visual_host_key == -1)
		options->visual_host_key = 0;
	if (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_AF21;
	if (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS1;
	if (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	if (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	if (options->stdin_null == -1)
		options->stdin_null = 0;
	if (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	if (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	if (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	if (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	if (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	if (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
	if (options->update_hostkeys == -1)
		options->update_hostkeys = 0;
	if (options->sk_provider == NULL)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
	if (options->required_rsa_size == -1)
		/* get default */
		options->required_rsa_size = required_rsa_size;
	else {
		/* transfer */
		if (options->required_rsa_size < required_rsa_size) {
			error("RSA key size %d is less then minimum %d.",
			    options->required_rsa_size, required_rsa_size);
			return -1;
		}
		required_rsa_size = options->required_rsa_size;
	}
	if (options->enable_escape_commandline == -1)
#ifndef HAVE_PLEDGE
		options->enable_escape_commandline = 1;
#else
		options->enable_escape_commandline = 0;
#endif

	/* expand KEX and etc. name lists */
{	char *all;
#define ASSEMBLE(what, defaults, all) \
	do { \
		char *def = match_filter_allowlist(defaults, all); \
		r = kex_assemble_names(&options->what, def, all); \
		free(def); \
		free(all); \
		if (r != 0) { \
			error_fr(r, "%s", #what); \
			return -1; \
		} \
	} while (0)

	all = cipher_alg_list(',', 0);
	ASSEMBLE(ciphers, KEX_CLIENT_ENCRYPT, all);

	all = mac_alg_list(',');
	ASSEMBLE(macs, KEX_CLIENT_MAC, all);

	all = kex_alg_list(',');
	ASSEMBLE(kex_algorithms, KEX_CLIENT_KEX, all);

	all = sshkey_alg_list(0, 1, 1, ',');
	ASSEMBLE(ca_sign_algorithms, SSH_ALLOWED_CA_SIGALGS, all);
#undef ASSEMBLE
}

#define CLEAR_ON_NONE(v) \
	do { \
		if (option_clear_or_none(v)) { \
			free(v); \
			v = NULL; \
		} \
	} while(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	do { \
		if (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			free(options->v[0]); \
			free(options->v); \
			options->v = NULL; \
			options->nv = 0; \
		} \
	} while (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->revoked_host_keys);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);

	CLEAR_ON_NONE_ARRAY(log_verbose, num_log_verbose, "none");
	CLEAR_ON_NONE_ARRAY(channel_timeouts, num_channel_timeouts, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	if (options->num_canonical_domains == 1 &&
	    strcmp(options->canonical_domains[0], "none") == 0) {
		free(options->canonical_domains[0]);
		options->num_canonical_domains = 0;
	}
	if (options->jump_host != NULL &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == NULL) {
		free(options->jump_host);
		options->jump_host = NULL;
	}
	if (options->num_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		free(options->permitted_cnames[0].source_list);
		free(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    sizeof(*options->permitted_cnames));
		options->num_permitted_cnames = 0;
	}
	if (options->version_addendum == NULL)
		options->version_addendum = xstrdup("");
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* options->hostbased_algorithms */
	/* options->pubkey_algorithms */
	fill_default_xkalg();
	ssh_x509flags_defaults(options->x509flags);
	X509StoreOptions_system_defaults(&options->ca);
	X509StoreOptions_user_defaults(&options->userca, getuid());

	(void)ssh_x509store_addlocations(&options->userca);
	(void)ssh_x509store_addlocations(&options->ca);
#ifdef LDAP_ENABLED
	(void)ssh_x509store_addldapurl(options->ca_ldap_url, options->ca_ldap_ver);
#endif
#ifdef USE_OPENSSL_STORE2
	(void)ssh_x509store_adduri(options->store_uri, options->num_store_uri);
#endif
#ifdef SSH_OCSP_ENABLED
	if (options->va.type == -1)
		options->va.type = ssh_get_default_vatype();
	ssh_set_validator(&options->va);
#endif /*def SSH_OCSP_ENABLED*/

	if (options->hostkeyalgorithms != NULL) {
		char *arg = options->hostkeyalgorithms;
		if (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, 0)) {
			error("Bad protocol 2 hostkey algorithms '%s'.",
			    options->hostkeyalgorithms);
			return -1;
		}
	}

	if (options->hostbased_algorithms != NULL) {
		if (!sshkey_names_valid2(options->hostbased_algorithms, 1, 0)) {
			error("Bad protocol 2 hostbased key algorithms '%s'.",
			    options->hostbased_algorithms);
			return -1;
		}
	} else
		options->hostbased_algorithms = xstrdup("*");

	if (options->pubkey_algorithms != NULL) {
		if (!sshkey_names_valid2(options->pubkey_algorithms, 1, 0)) {
			error("Bad protocol 2 public key algorithms '%s'.",
			    options->pubkey_algorithms);
			return -1;
		}
	} else
		options->pubkey_algorithms = xstrdup("*");

	return 0;
}

struct fwdarg {
	char *arg;
	int ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
static int
parse_fwd_field(char **p, struct fwdarg *fwd)
{
	char *ep, *cp = *p;
	int ispath = 0;

	if (*cp == '\0') {
		*p = NULL;
		return -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	if (*cp == '[') {
		/* find matching ']' */
		for (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			if (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		if (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			return -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		if (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		return 0;
	}

	for (cp = *p; *cp != '\0'; cp++) {
		switch (*cp) {
		case '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			if (*cp == '\0')
				return -1;
			break;
		case '/':
			ispath = 1;
			break;
		case ':':
			*cp++ = '\0';
			goto done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	return 0;
}

/*
 * parse_forward
 * parses a string containing a port forwarding specification of the form:
 *   dynamicfwd == 0
 *	[listenhost:]listenport|listenpath:connecthost:connectport|connectpath
 *	listenpath:connectpath
 *   dynamicfwd == 1
 *	[listenhost:]listenport
 * returns number of arguments parsed or zero on error
 */
int
parse_forward(struct Forward *fwd, const char *fwdspec, int dynamicfwd, int remotefwd)
{
	struct fwdarg fwdargs[4];
	char *p, *cp;
	int i, err;

	memset(fwd, 0, sizeof(*fwd));
	memset(fwdargs, 0, sizeof(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	if (p == NULL || err)
		return 0;

	/* skip leading spaces */
	while (isspace((u_char)*cp))
		cp++;

	for (i = 0; i < 4; ++i) {
		if (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			break;
	}

	/* Check for trailing garbage */
	if (cp != NULL && *cp != '\0') {
		i = 0;	/* failure */
	}

	switch (i) {
	case 1:
		if (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} else {
			fwd->listen_host = NULL;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		break;

	case 2:
		if (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} else if (fwdargs[1].ispath) {
			fwd->listen_host = NULL;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} else {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		break;

	case 3:
		if (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} else if (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} else {
			fwd->listen_host = NULL;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		break;

	case 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		break;
	default:
		i = 0; /* failure */
	}

	free(p);

	if (dynamicfwd) {
		if (!(i == 1 || i == 2))
			goto fail_free;
	} else {
		if (!(i == 3 || i == 4)) {
			if (fwd->connect_path == NULL &&
			    fwd->listen_path == NULL)
				goto fail_free;
		}
		if (fwd->connect_port <= 0 && fwd->connect_path == NULL)
			goto fail_free;
	}

	if ((fwd->listen_port < 0 && fwd->listen_path == NULL) ||
	    (!remotefwd && fwd->listen_port == 0))
		goto fail_free;
	if (fwd->connect_host != NULL &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		goto fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	if (fwd->connect_path != NULL &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		goto fail_free;
	if (fwd->listen_host != NULL &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		goto fail_free;
	if (fwd->listen_path != NULL &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		goto fail_free;

	return (i);

 fail_free:
	free(fwd->connect_host);
	fwd->connect_host = NULL;
	free(fwd->connect_path);
	fwd->connect_path = NULL;
	free(fwd->listen_host);
	fwd->listen_host = NULL;
	free(fwd->listen_path);
	fwd->listen_path = NULL;
	return (0);
}

int
parse_jump(const char *s, Options *o, int active)
{
	char *orig, *sdup, *cp;
	char *host = NULL, *user = NULL;
	int r, ret = -1, port = -1, first;

	active &= o->proxy_command == NULL && o->jump_host == NULL;

	if (strcasecmp(s, "none") == 0) {
		if (active) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		return 0;
	}

	orig = sdup = xstrdup(s);
	first = active;
	do {
		if ((cp = strrchr(sdup, ',')) == NULL)
			cp = sdup; /* last */
		else
			*cp++ = '\0';

		if (first) {
			/* First argument and configuration is active */
			r = parse_ssh_uri(cp, &user, &host, &port);
			if (r == -1 || (r == 1 &&
			    parse_user_host_port(cp, &user, &host, &port) != 0))
				goto out;
		} else {
			/* Subsequent argument or inactive configuration */
			r = parse_ssh_uri(cp, NULL, NULL, NULL);
			if (r == -1 || (r == 1 &&
			    parse_user_host_port(cp, NULL, NULL, NULL) != 0))
				goto out;
		}
		first = 0; /* only check syntax for subsequent hosts */
	} while (cp != sdup);
	/* success */
	if (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = NULL;
		if ((cp = strrchr(s, ',')) != NULL && cp != s) {
			o->jump_extra = xstrdup(s);
			o->jump_extra[cp - s] = '\0';
		}
	}
	ret = 0;
 out:
	free(orig);
	free(user);
	free(host);
	return ret;
}

int
parse_ssh_uri(const char *uri, char **userp, char **hostp, int *portp)
{
	char *user = NULL, *host = NULL, *path = NULL;
	int r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	if (r == 0 && path != NULL)
		r = -1;		/* path not allowed */
	if (r == 0) {
		if (userp != NULL) {
			*userp = user;
			user = NULL;
		}
		if (hostp != NULL) {
			*hostp = host;
			host = NULL;
		}
		if (portp != NULL)
			*portp = port;
	}
	free(user);
	free(host);
	free(path);
	return r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
static const char *
fmt_multistate_int(int val, const struct multistate *m)
{
	u_int i;

	for (i = 0; m[i].key != NULL; i++) {
		if (m[i].value == val)
			return m[i].key;
	}
	return "UNKNOWN";
}

static const char *
fmt_intarg(OpCodes code, int val)
{
	if (val == -1)
		return "unset";
	switch (code) {
#ifdef SSH_OCSP_ENABLED
	case oVAType:
		return ssh_get_vatype_i(val);
#endif
	case oAddressFamily:
		return fmt_multistate_int(val, multistate_addressfamily);
	case oVerifyHostKeyDNS:
	case oUpdateHostkeys:
		return fmt_multistate_int(val, multistate_yesnoask);
	case oStrictHostKeyChecking:
		return fmt_multistate_int(val, multistate_strict_hostkey);
	case oControlMaster:
		return fmt_multistate_int(val, multistate_controlmaster);
	case oTunnel:
		return fmt_multistate_int(val, multistate_tunnel);
	case oRequestTTY:
		return fmt_multistate_int(val, multistate_requesttty);
	case oSessionType:
		return fmt_multistate_int(val, multistate_sessiontype);
	case oCanonicalizeHostname:
		return fmt_multistate_int(val, multistate_canonicalizehostname);
	case oAddKeysToAgent:
		return fmt_multistate_int(val, multistate_yesnoaskconfirm);
	case oFingerprintHash:
		return ssh_digest_alg_name(val);
	default:
		switch (val) {
		case 0:
			return "no";
		case 1:
			return "yes";
		default:
			return "UNKNOWN";
		}
	}
}

static const char *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	for (i = 0; keywords[i].name != NULL; i++)
		if (keywords[i].opcode == code)
			return(keywords[i].name);
	return "UNKNOWN";
}

static void
dump_cfg_int(OpCodes code, int val)
{
	printf("%s %d\n", lookup_opcode_name(code), val);
}

static void
dump_cfg_fmtint(OpCodes code, int val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

static void
dump_cfg_string(OpCodes code, const char *val)
{
	if (val == NULL)
		return;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

static void
dump_cfg_strarray(OpCodes code, u_int count, char **vals)
{
	u_int i;

	for (i = 0; i < count; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

static void
dump_cfg_strarray_oneline(OpCodes code, u_int count, char **vals)
{
	u_int i;
	const char *def = "";

	if ((int)count < 0) return;

	if (count == 0)
		def = " none";

	printf("%s%s", lookup_opcode_name(code), def);
	for (i = 0; i < count; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

static void
dump_cfg_forwards(OpCodes code, u_int count, const struct Forward *fwds)
{
	const struct Forward *fwd;
	u_int i;

	/* oDynamicForward */
	for (i = 0; i < count; i++) {
		fwd = &fwds[i];
		if (code == oDynamicForward && fwd->connect_host != NULL &&
		    strcmp(fwd->connect_host, "socks") != 0)
			continue;
		if (code == oLocalForward && fwd->connect_host != NULL &&
		    strcmp(fwd->connect_host, "socks") == 0)
			continue;
		printf("%s", lookup_opcode_name(code));
		if (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		else if (fwd->listen_host == NULL)
			printf(" %d", fwd->listen_port);
		else {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		if (code != oDynamicForward) {
			if (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			else if (fwd->connect_host == NULL)
				printf(" %d", fwd->connect_port);
			else {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

void
dump_client_config(Options *o, const char *host)
{
	int i;
	char buf[8];

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(oPort, o->port);

	/* X.509 options */
	dump_cfg_string(oHostbasedAlgorithms, o->hostbased_algorithms);
	dump_cfg_string(oPubkeyAlgorithms, o->pubkey_algorithms);
	/* TODO to implement dump of sX509KeyAlgorithm */
	/* sshd PKI(X509) flags */
	/* sshd PKI(X509) system store */
	dump_cfg_string(oCACertificateFile, o->ca.certificate_file);
	dump_cfg_string(oCACertificatePath, o->ca.certificate_path);
	dump_cfg_string(oCARevocationFile , o->ca.revocation_file );
	dump_cfg_string(oCARevocationPath , o->ca.revocation_path );
	/* sshd PKI(X509) user store */
	dump_cfg_string(oUserCACertificateFile, o->userca.certificate_file);
	dump_cfg_string(oUserCACertificatePath, o->userca.certificate_path);
	dump_cfg_string(oUserCARevocationFile , o->userca.revocation_file );
	dump_cfg_string(oUserCARevocationPath , o->userca.revocation_path );
#ifdef SSH_OCSP_ENABLED
	/* ssh X.509 extra validation */
	dump_cfg_fmtint(oVAType		   , o->va.type		   );
	dump_cfg_string(oVACertificateFile , o->va.certificate_file);
	dump_cfg_string(oVAOCSPResponderURL, o->va.responder_url   );
#endif /*def SSH_OCSP_ENABLED*/

	/* Flag options */
	dump_cfg_fmtint(oAddressFamily, o->address_family);
	dump_cfg_fmtint(oBatchMode, o->batch_mode);
	dump_cfg_fmtint(oCanonicalizeFallbackLocal, o->canonicalize_fallback_local);
	dump_cfg_fmtint(oCanonicalizeHostname, o->canonicalize_hostname);
	dump_cfg_fmtint(oCheckHostIP, o->check_host_ip);
	dump_cfg_fmtint(oCompression, o->compression);
	dump_cfg_fmtint(oControlMaster, o->control_master);
	dump_cfg_fmtint(oEnableSSHKeysign, o->enable_ssh_keysign);
	dump_cfg_fmtint(oClearAllForwardings, o->clear_forwardings);
	dump_cfg_fmtint(oExitOnForwardFailure, o->exit_on_forward_failure);
	dump_cfg_fmtint(oFingerprintHash, o->fingerprint_hash);
	dump_cfg_fmtint(oForwardX11, o->forward_x11);
	dump_cfg_fmtint(oForwardX11Trusted, o->forward_x11_trusted);
	dump_cfg_fmtint(oGatewayPorts, o->fwd_opts.gateway_ports);
#ifdef GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#endif /* GSSAPI */
	dump_cfg_fmtint(oHashKnownHosts, o->hash_known_hosts);
	dump_cfg_fmtint(oHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(oIdentitiesOnly, o->identities_only);
	dump_cfg_fmtint(oKbdInteractiveAuthentication, o->kbd_interactive_authentication);
	dump_cfg_fmtint(oNoHostAuthenticationForLocalhost, o->no_host_authentication_for_localhost);
	dump_cfg_fmtint(oPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(oPermitLocalCommand, o->permit_local_command);
	dump_cfg_fmtint(oProxyUseFdpass, o->proxy_use_fdpass);
	dump_cfg_fmtint(oPubkeyAuthentication, o->pubkey_authentication);
	dump_cfg_fmtint(oRequestTTY, o->request_tty);
	dump_cfg_fmtint(oSessionType, o->session_type);
	dump_cfg_fmtint(oStdinNull, o->stdin_null);
	dump_cfg_fmtint(oForkAfterAuthentication, o->fork_after_authentication);
	dump_cfg_fmtint(oStreamLocalBindUnlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(oStrictHostKeyChecking, o->strict_host_key_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(oVerifyHostKeyDNS, o->verify_host_key_dns);
	dump_cfg_fmtint(oVisualHostKey, o->visual_host_key);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(oNumberOfPasswordPrompts, o->number_of_password_prompts);
	dump_cfg_int(oServerAliveCountMax, o->server_alive_count_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(oHostKeyAlgorithms, o->hostkeyalgorithms);
	dump_cfg_string(oHostKeyAlias, o->host_key_alias);
	dump_cfg_string(oIdentityAgent, o->identity_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#ifdef ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#endif
#ifdef ENABLE_SK
	dump_cfg_string(oSecurityKeyProvider, o->sk_provider);
#endif
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oRevokedHostKeys, o->revoked_host_keys);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->num_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->num_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->num_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->num_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->num_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->num_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->num_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->num_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray(oSendEnv, o->num_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->num_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->num_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->num_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	if (o->num_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	else
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->num_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	if (o->add_keys_to_agent_lifespan <= 0)
		dump_cfg_fmtint(oAddKeysToAgent, o->add_keys_to_agent);
	else {
		printf("addkeystoagent%s %d\n",
		    o->add_keys_to_agent == 3 ? " confirm" : "",
		    o->add_keys_to_agent_lifespan);
	}

	/* oForwardAgent */
	if (o->forward_agent_sock_path == NULL)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	else
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	if (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	else
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	if (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	else
		printf(" %d", o->tun_local);
	if (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	else
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizePermittedcnames");
	if (o->num_permitted_cnames == 0)
		printf(" none");
	for (i = 0; i < o->num_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	if (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	else
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	if (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	else {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		printf("escapechar %s\n", buf);
	}

	/* oIPQoS */
	printf("ipqos %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	printf("rekeylimit %llu %d\n",
	    (unsigned long long)o->rekey_limit, o->rekey_interval);

	/* oStreamLocalBindMask */
	printf("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_mask);

	/* oLogFacility */
	printf("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	if (o->jump_host == NULL)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	else {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != NULL ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, sizeof(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == NULL ? "" : o->jump_extra,
		    o->jump_extra == NULL ? "" : ",",
		    /* optional user */
		    o->jump_user == NULL ? "" : o->jump_user,
		    o->jump_user == NULL ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_port <= 0 ? "" : ":",
		    o->jump_port <= 0 ? "" : buf);
	}
}
