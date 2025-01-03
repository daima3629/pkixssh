/*
 * Copyright (c) 2011-2025 Roumen Petrov.  All rights reserved.
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

#include <openssl/ui.h>

#include "misc.h"
#include "log.h"


/* structure reserved for future use */
typedef struct ssh_pw_cb_data {
	const void *password;
} SSH_PW_CB_DATA;


static int
ui_open(UI *ui) {
	return UI_method_get_opener(UI_OpenSSL())(ui);
}


static int
ui_read(UI *ui, UI_STRING *uis) {
	enum UI_string_types  uis_type;
	int ui_flags;

	ui_flags = UI_get_input_flags(uis);
	uis_type = UI_get_string_type(uis);

	if (ui_flags & UI_INPUT_FLAG_DEFAULT_PWD) {
		SSH_PW_CB_DATA* cb_data = (SSH_PW_CB_DATA*)UI_get0_user_data(ui);
		if (cb_data != NULL) {
			switch(uis_type) {
			case UIT_PROMPT:
			case UIT_VERIFY: {
				const char *password = cb_data->password;
				if (password && password[0] != '\0') {
					UI_set_result(ui, uis, password);
					return 1;
				}
				} break;
			default:
				break;
			}
		}
	}

{ /* use own method to prompt properly */
	int flags = RP_USE_ASKPASS | RP_ALLOW_STDIN;
	if (ui_flags & UI_INPUT_FLAG_ECHO)
		flags |= RP_ECHO;

	switch(uis_type) {
	case UIT_PROMPT:
	case UIT_VERIFY: {
		const char *prompt;
		char *password;

		prompt = UI_get0_output_string(uis);
		debug3_f("read_passphrase prompt=%s",  prompt);
		password = read_passphrase(prompt, flags);
		UI_set_result(ui, uis, password);
		memset(password, 'x', strlen(password));
		free(password);
		return 1;
		} break;
	case UIT_INFO: {
		const char *s = UI_get0_output_string(uis);
		debug_f("UIT_INFO '%s'", s);
		return 1;
		} break;
	case UIT_ERROR: {
		const char *s = UI_get0_output_string(uis);
		error_f("UIT_ERROR '%s'", s);
		return 1;
		} break;
	default:
		break;
	}
}

	return UI_method_get_reader(UI_OpenSSL())(ui, uis);
}


static int
ui_write(UI *ui, UI_STRING *uis) {
	enum UI_string_types  uis_type;
	int ui_flags;

	ui_flags = UI_get_input_flags(uis);
	uis_type = UI_get_string_type(uis);

	if (ui_flags & UI_INPUT_FLAG_DEFAULT_PWD) {
		SSH_PW_CB_DATA* cb_data = (SSH_PW_CB_DATA*)UI_get0_user_data(ui);
		if (cb_data != NULL) {
			switch(uis_type) {
			case UIT_PROMPT:
			case UIT_VERIFY: {
				const char *password = cb_data->password;
				if (password && password[0] != '\0') {
					return 1;
				}
				} break;
			default:
				break;
			}
		}
	}
	switch(uis_type) {
	case UIT_INFO: {
		const char *s = UI_get0_output_string(uis);
		debug_f("UIT_INFO '%s'", s);
		return 1;
		} break;
	case UIT_ERROR: {
		const char *s = UI_get0_output_string(uis);
		error_f("UIT_ERROR '%s'", s);
		return 1;
		} break;
	default:
		break;
	}
	return UI_method_get_writer(UI_OpenSSL())(ui, uis);
}


static int
ui_close(UI *ui) {
	return UI_method_get_closer(UI_OpenSSL())(ui);
}


extern int/*bool*/setup_ssh_ui_method(void);
extern void destroy_ssh_ui_method(void);

UI_METHOD *ssh_ui_method = NULL;

void
destroy_ssh_ui_method(void) {
	if (ssh_ui_method == NULL) return;

	UI_destroy_method(ssh_ui_method);
	ssh_ui_method = NULL;
}

int/*bool*/
setup_ssh_ui_method(void) {
	ssh_ui_method = UI_create_method("PKIX-SSH application user interface");

	if (ssh_ui_method == NULL) return 0;

	if ((UI_method_set_opener(ssh_ui_method, ui_open ) < 0)
	||  (UI_method_set_reader(ssh_ui_method, ui_read ) < 0)
	||  (UI_method_set_writer(ssh_ui_method, ui_write) < 0)
	||  (UI_method_set_closer(ssh_ui_method, ui_close) < 0)) {
		destroy_ssh_ui_method();
		return 0;
	}
	return 1;
}
