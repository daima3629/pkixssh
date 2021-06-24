static int
ldaplookup_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **retp) {
	int ret = 0;

	UNUSED(argl);
	UNUSED(retp);
TRACE_BY_LDAP(__func__, "ctx=%p, cmd: %d, argc: '%s'", ctx, cmd, argc);
	switch (cmd) {
	case X509_L_LDAP_HOST:
		ret = ldaplookup_add_search(ctx, argc);
		break;
	default:
		X509byLDAPerr(X509byLDAP_F_LOOKUPCRTL, X509byLDAP_R_INVALID_CRTLCMD);
		break;
	}
	return ret;
}


/*
 * We will put into store X509 object from passed data in buffer only
 * when object name match passed. To compare both names we use our
 * method "ssh_X509_NAME_cmp"(it is more general).
 */
static int/*bool*/
ldaplookup_data2store(
	int type, X509_NAME *name,
	OSSL_STORE_INFO *info,
	X509_STORE *store
) {
	int ok = 0;

	if (name == NULL) return 0;
	if (info == NULL) return 0;
	if (store == NULL) return 0;

	switch (type) {
	case X509_LU_X509: {
		X509 *x509 = OSSL_STORE_INFO_get0_CERT(info);
		if(x509 == NULL) goto exit;

		/*This is correct since lookup method is by subject*/
		if (ssh_X509_NAME_cmp(name, X509_get_subject_name(x509)) != 0) goto exit;

		ok = X509_STORE_add_cert(store, x509);
		} break;
	case X509_LU_CRL: {
		X509_CRL *crl = OSSL_STORE_INFO_get0_CRL(info);
		if(crl == NULL) goto exit;

		if (ssh_X509_NAME_cmp(name, X509_CRL_get_issuer(crl)) != 0) goto exit;

		ok = X509_STORE_add_crl(store, crl);
		} break;
	default:
		return 0;
	}
exit:
	return ok;
}


/*
 * Search "by subject" based on "Store2 API"
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

TRACE_BY_LDAP(__func__, "ctx=%p, type: %d", ctx, type);
	if (ctx == NULL) return 0;
	if (name == NULL) return 0;

	p = (lookup_item*)(void*) ctx->method_data;
	if (p == NULL) return 0;

	for (; p != NULL; p = p->next) {
		ldapstore *ls = p->ls;
		X509_STORE *store = ctx->store_ctx;
		OSSL_STORE_SEARCH *search;

TRACE_BY_LDAP(__func__, "ls->ctx=%p", (void*)ls->ctx);
		if (ls->ctx == NULL)
			ls->ctx = OSSL_STORE_open(ls->url, NULL, NULL, NULL, NULL);
		if (ls->ctx == NULL) continue;

	{	int expected;
		switch(type) {
		case X509_LU_X509: expected = OSSL_STORE_INFO_CERT; break;
		case X509_LU_CRL: expected = OSSL_STORE_INFO_CRL; break;
		default: expected = -1; /*suppress warning*/
		}
		(void)OSSL_STORE_expect(ls->ctx, expected);
	}

		search = OSSL_STORE_SEARCH_by_name(name);
		OSSL_STORE_find(ls->ctx, search);

		while (!OSSL_STORE_eof(ls->ctx)) {
			OSSL_STORE_INFO *store_info;

			store_info = OSSL_STORE_load(ls->ctx);
			if (store_info == NULL) break;
#ifdef TRACE_BY_LDAP_ENABLED
{
const char *uri = OSSL_STORE_INFO_get0_NAME(store_info);
TRACE_BY_LDAP(__func__, "store  uri='%s'", uri);
}
#endif

			count += ldaplookup_data2store(type, name,
			    store_info, store)
			    ? 1 : 0;

			OSSL_STORE_INFO_free(store_info);
		}

		OSSL_STORE_SEARCH_free(search);
		OSSL_STORE_close(ls->ctx);
		ls->ctx = NULL;
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
	return count > 0;
}
