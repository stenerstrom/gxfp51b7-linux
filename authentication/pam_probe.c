/* SPDX-License-Identifier: MIT
 * Exercise a real PAM stack. Fingerprint informational prompts are displayed;
 * password input is deliberately declined, never accepted or logged here.
 */
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int password_prompts;
static int conversation(int n, const struct pam_message **messages,
                        struct pam_response **responses, void *unused)
{
    (void)unused;
    if (n < 1 || n > 32) return PAM_CONV_ERR;
    for (int i = 0; i < n; ++i) {
        if (messages[i]->msg_style == PAM_PROMPT_ECHO_OFF ||
            messages[i]->msg_style == PAM_PROMPT_ECHO_ON) {
            password_prompts++;
            return PAM_CONV_ERR;
        }
        if (messages[i]->msg_style != PAM_TEXT_INFO && messages[i]->msg_style != PAM_ERROR_MSG)
            return PAM_CONV_ERR;
        if (messages[i]->msg) puts(messages[i]->msg);
    }
    *responses = calloc((size_t)n, sizeof(**responses));
    return *responses ? PAM_SUCCESS : PAM_BUF_ERR;
}

int main(int argc, char **argv)
{
    if (argc != 4) return 2;
    struct pam_conv conv = {.conv = conversation};
    pam_handle_t *handle = NULL;
    int started = pam_start_confdir(argv[2], argv[3], &conv, argv[1], &handle);
    if (started != PAM_SUCCESS) { printf("pam_start_result=%d\n", started); return 2; }
    int auth = pam_authenticate(handle, 0);
    int account = auth == PAM_SUCCESS ? pam_acct_mgmt(handle, 0) : -1;
    printf("pam_authenticate_result=%d pam_account_result=%d password_prompts=%d\n",
           auth, account, password_prompts);
    int ended = pam_end(handle, auth);
    return auth == PAM_SUCCESS && account == PAM_SUCCESS && ended == PAM_SUCCESS ? 0 : 1;
}
