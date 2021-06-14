/*
 * We will put into store X509 object from passed data in buffer only
 * when object name match passed. To compare both names we use our
 * method "ssh_X509_NAME_cmp"(it is more general).
 */
static int/*bool*/
ldaplookup_data2store(
	int         type,
	X509_NAME*  name,
	void*       buf,
	int         len,
	X509_STORE* store
) {
	int ok = 0;
	BIO *mbio;

	if (name == NULL) return 0;
	if (buf == NULL) return 0;
	if (len <= 0) return 0;
	if (store == NULL) return 0;

	mbio = BIO_new_mem_buf(buf, len);
	if (mbio == NULL) return 0;

	switch (type) {
	case X509_LU_X509: {
		X509 *x509 = d2i_X509_bio(mbio, NULL);
		if(x509 == NULL) goto exit;

		/*This is correct since lookup method is by subject*/
		if (ssh_X509_NAME_cmp(name, X509_get_subject_name(x509)) != 0) goto exit;

		ok = X509_STORE_add_cert(store, x509);
		/* X509_STORE_add...() increase "object" reference,
		 * so here object must be released unconditionally.
		 */
		X509_free(x509);
		} break;
	case X509_LU_CRL: {
		X509_CRL *crl = d2i_X509_CRL_bio(mbio, NULL);
		if(crl == NULL) goto exit;

		if (ssh_X509_NAME_cmp(name, X509_CRL_get_issuer(crl)) != 0) goto exit;

		ok = X509_STORE_add_crl(store, crl);
		X509_CRL_free(crl);
		} break;
	}

exit:
	BIO_free_all(mbio);
TRACE_BY_LDAP(__func__, "ok: %d", ok);
	return ok;
}


/*
 * Clasic(direct) search "by subject"
 */
static int
ldaplookup_by_subject(
	X509_LOOKUP *ctx,
	int          type,
	X509_NAME   *name,
	X509_OBJECT *ret
) {
	int count = 0;
	lookup_item *p;
	const char *attrs[2];
	static const char *ATTR_CACERT = "cACertificate";
	static const char *ATTR_CACRL = "certificateRevocationList";
	char *filter = NULL;

TRACE_BY_LDAP(__func__, "ctx=%p, type: %d", ctx, type);
	if (ctx == NULL) return 0;
	if (name == NULL) return 0;

	p = (lookup_item*)(void*) ctx->method_data;
	if (p == NULL) return 0;

	switch(type) {
	case X509_LU_X509: {
		attrs[0] = ATTR_CACERT;
		} break;
	case X509_LU_CRL: {
		attrs[0] = ATTR_CACRL;
		} break;
	default: {
		X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_WRONG_LOOKUP_TYPE);
		goto done;
		}
	}
	attrs[1] = NULL;

	filter = X509_NAME_ldapfilter(name, attrs[0]);
	if (filter == NULL) {
		X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_UNABLE_TO_GET_FILTER);
		goto done;
	}
TRACE_BY_LDAP(__func__, "filter: '%s'", filter);

	for (; p != NULL; p = p->next) {
		ldaphost *lh = p->lh;
		LDAPMessage *res = NULL;
		int result;

#ifdef TRACE_BY_LDAP_ENABLED
{
int version = -1;

ldap_get_option(lh->ld, LDAP_OPT_PROTOCOL_VERSION, &version);
TRACE_BY_LDAP(__func__, "bind to '%s://%s:%d' using protocol v%d"
, lh->ldapurl->lud_scheme, lh->ldapurl->lud_host, lh->ldapurl->lud_port
, version
);
}
#endif /*def TRACE_BY_LDAP_ENABLED*/

		result = ssh_ldap_bind_s(lh->ld);
		if (result != LDAP_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_UNABLE_TO_BIND);
			{
				char	buf[1024];
				snprintf(buf, sizeof(buf),
					" url=\"%s://%s:%d\""
					" ldaperror=0x%x(%.256s)"
					, lh->ldapurl->lud_scheme, lh->ldapurl->lud_host, lh->ldapurl->lud_port
					, result, ldap_err2string(result)
				);
				ERR_add_error_data(1, buf);
			}
			continue;
		}

		result = ssh_ldap_search_s(lh->ld, lh->ldapurl->lud_dn,
				LDAP_SCOPE_SUBTREE, filter, (char**)attrs, 0, &res);
		if (result != LDAP_SUCCESS) {
			X509byLDAPerr(X509byLDAP_F_GET_BY_SUBJECT, X509byLDAP_R_SEARCH_FAIL);
			ldap_msgfree(res);
			continue;
		}
	{	X509_STORE *store = ctx->store_ctx;
		ldapsearch_result *it = ldapsearch_iterator(lh->ld, res);

		while (ldapsearch_advance(it)) {
		{	const char *q;

			switch (type) {
			case X509_LU_X509: q = ATTR_CACERT; break;
			case X509_LU_CRL : q = ATTR_CACRL ; break;
			default: /* warnings */
				continue;
			}
			if (strncmp(it->attr, q, strlen(q)) != 0)
				continue;
		}

		{	struct berval *q = *it->p;
			count += ldaplookup_data2store(type, name,
			    q->bv_val, q->bv_len, store)
			    ? 1 : 0;
		}
		}

		OPENSSL_free(it);
	}

		ldap_msgfree(res);

		/* NOTE: do not call ldap_unbind... here!
		 * Function ldaphost_free() unbind LDAP structure.
		 */
	}

TRACE_BY_LDAP(__func__, "count: %d", count);
	if (count > 0) {
		X509_STORE *store = ctx->store_ctx;
		X509_OBJECT *tmp;

		X509_STORE_lock(store);
		{	STACK_OF(X509_OBJECT) *objs;
			objs = X509_STORE_get0_objects(store);
			tmp = X509_OBJECT_retrieve_by_subject(objs, type, name);
		}
		X509_STORE_unlock(store);
TRACE_BY_LDAP(__func__, "tmp=%p", (void*)tmp);

		if (tmp == NULL) {
			count = 0;
			goto done;
		}

		ret->type = tmp->type;
		memcpy(&ret->data, &tmp->data, sizeof(ret->data));
	}

done:
	OPENSSL_free(filter);
	return count > 0;
}
