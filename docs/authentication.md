# Omarchy authentication setup

First establish a working standard fprintd enrollment and a match in a fresh
session. Selecting `right-index-finger` is compatible with PAM's `VerifyStart`
request for `any` enrolled finger. A second enrollment without `-f` is not
needed for sudo or Polkit.

The optional planner targets `sudo`, `polkit-1`, `sddm`, and
`omarchy-lock-fingerprint`. It reads the actual existing service stacks and
their account-lock settings. It requires the inspected Omarchy lid helper,
`/usr/bin/omarchy-hw-laptop-closed`, and UID1000 local Polkit authentication.
It does not modify shared `system-auth`, SSH, the password lock-screen service,
autologin, or keyring/session configuration.

The tested block checks the existing faillock policy, skips fingerprints when
the lid is closed, runs pam_fprintd with one completed attempt and a15-second
timeout, and resets faillock on fingerprint success. Password fallback remains
in the original service stack. Acquisition retries are nonfinal fprintd events
and do not consume a completed attempt.

## Prepare, review and apply

The planner refuses an already configured fingerprint stack. Inspect that
configuration rather than layering another copy over it.

```sh
python3 authentication/integrate_pam.py --plan authentication/plan.json
cat authentication/plan.json
```

Review the generated service files and original-file hashes. Then apply that
exact plan using its printed SHA256:

```sh
plan_sha=$(sha256sum authentication/plan.json | cut -d ' ' -f1)
pkexec /usr/bin/python3 -B "$PWD/authentication/integrate_pam.py" \
  --apply "$PWD/authentication/plan.json" --sha256 "$plan_sha"
```

Original local files and a restoration manifest are saved under a protected
`/var/lib/gxfp51b7/pam-backups/` directory. Concurrent source changes reject
the plan. Partial apply failure attempts to restore the original files.
The existing successful enrollment is not read, replaced or deleted by this
PAM script.

## Check authentication

In your own terminal, invalidate the sudo timestamp and authenticate:

```sh
sudo -k
sudo -v
```

Keep the reader empty until prompted. Use the enrolled finger. A harmless
desktop Polkit test is:

```sh
pkexec --disable-internal-agent /usr/bin/id -u
```

A successful command alone does not prove which authentication method was
used; use the actual finger prompt and fresh numerical backend match record.
Both sudo and Polkit were verified that way on the development laptop.

Other distributions and desktop lock screens need their own reviewed PAM
setup. This repository does not run a distribution fingerprint wizard or
replace the distribution's fprintd package. A full login/lock trial remains
separate from the verified sudo/Polkit tests.
