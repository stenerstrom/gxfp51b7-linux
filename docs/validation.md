# Validation and remaining limits

## Functional evidence

The original-engine pilot was tested on one Huawei MACHC-WAX9 with the
GXFP51B7 reader, Omarchy kernel7.2.5-3 and fprintd1.94.5. The initial working
release enrolled through ordinary fprintd, matched the enrolled finger in two
fresh verification sessions, and returned a completed nonmatch for a middle
finger. Each completed worker restored the sensor transport.

The subsequent retry-lifecycle release passed ordinary empty-reader
Claim/Release, then sudo and desktop Polkit fingerprint authentication. The
sudo transaction returned original Engine17 application0 (match). Polkit
returned application1 (match with adaptive update), with the update erased
rather than stored. Both workers exited successfully and restored transport.

A later transaction returned application-2 (insufficient evidence), retained
its worker across a reported acquisition retry, and later returned application1
in that same worker before clean restoration. It validates the retained retry
path; it was not a separately attributed controlled sudo/Polkit trial.

The publication copy removes workspace-specific build assumptions, resolves the
pilot account by UID instead of a literal username, excludes retired SIFT code
and replaces the assembly fixture with synthetic noise. These packaging changes
do not install a new driver or change the existing working enrollment.

## Known limits

- Empty-reader startup is required for each fresh worker. Placing a finger
  before initialization can give it an invalid baseline.
- Startup still initializes hardware SGX and TLS. Completed actions use new
  workers; nonfinal healthy acquisition retries can reuse one.
- Finger detection uses bounded image polling. Complete hardware finger-event
  scheduling is not implemented.
- Adaptive template updates are not persistent.
- A pre-image TLS failure (`-28800`, state8) occurred during earlier development.
  Retry retention does not establish its cause. It was not observed in the
  recorded successful sudo/Polkit transactions.
- Model, UID/GID and IOMMU-layout constraints remain. Secure Boot/module-signing
  and other hardware configurations have not been validated.
- Login/lock PAM files were configured, but no separate full logout/login or
  lock-screen trial is claimed here.
- No population false-accept/false-reject rates, spoof resistance, formal
  security audit, or vendor certification have been established.

## Automated checks

The source-only tests cover host protocol/state, action boundaries, retained
worker reuse, cancellation, cleanup, manifest tampering, installation rollback,
pilot account resolution and PAM fallback/account-lock semantics. They use no
actual enrollment or reader.

The complete build additionally validates signed external asset layout, uses
UBSan for C contracts, builds the kernel modules against the running kernel,
and runs libfprint's five unit suites, including16 original-engine driver cases.
The assembly fixture is generated from a fixed pseudorandom seed. Passing these
checks does not itself validate physical recognition on another machine.
