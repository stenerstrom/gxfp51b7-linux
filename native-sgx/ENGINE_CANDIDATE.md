# Original Engine candidate

This candidate integrates the unchanged signed Goodix Engine with Linux
libfprint and the existing fprintd daemon. Its marker and driver identity are
separate from the historical SIFT route. No Windows operating system is used.

Build and check with `python3 scripts/build.py` after importing the
external vendor assets and installing build dependencies (see the root README).
The build performs no hardware access. Temporary Unix socket tests need permission to create local sockets.
`python3 native-sgx/engine_backend.py --check` validates the pinned build
without opening the reader.

The candidate service keeps original TLS, paired SGX, calibration and action
state across frames. It exports only typed status and opaque sealed enrollment
templates to libfprint. Matching thresholds and enrollment completion come from
the original engine. The ordinary clients are `fprintd-enroll -f
right-index-finger` and `fprintd-verify -f right-index-finger`.

The first controlled rollout requires an empty reader before starting either
client. Place a finger only after the client starts enrollment or verification.
During enrollment, lift completely between accepted placements. Keep using the
same finger. A fresh saved template must also be tested in a separately opened
verify session; a completed registration alone is not recognition evidence.

Known limitations:

- Startup needs a confirmed empty baseline. Bounded image polling implements
  the recovered original classifier; complete hardware finger-event scheduling
  is not yet mapped.
- Each completed action ends its worker. Enrollment placement retries and
  wait events retain state. A healthy nonfinal verification acquisition retry
  retains its worker across libfprint actions and requires an actual finger lift.
- Original adaptive updates are exported and erased, without persistent
  storage. A match-with-update remains a match.
- Sealed templates have a4MiB engineering cap and a0x255 nonempty-body minimum.
  Their original enclave authentication is preserved; old SIFT templates are
  incompatible and cannot be converted by changing a schema marker.
- Offline tests and an empty Claim/Release preflight do not establish real
  recognition accuracy or complete enrollment behavior.

Installation uses a protected hash-addressed release and an explicit ordinary
fprintd Claim/Release readiness gate. Failure restores the previous release and
service configuration. Old-template deletion is never an installation side effect. Use ordinary
`fprintd-delete` only when intentionally replacing an enrollment. The installer does not
change PAM or create a custom GUI.

The dependency manifest records the exact vendor images, loader, worker,
transport, protocol, library and test inputs. Numeric stage diagnostics do not
include images, feature descriptors, templates or keys. Runtime images and
calibration remain in RAM; fprintd alone stores the new opaque template.
