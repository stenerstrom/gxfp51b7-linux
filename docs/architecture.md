# Runtime architecture

```text
fprintd-enroll / fprintd-verify / pam_fprintd
                     |
             ordinary fprintd
                     |
     libfprint goodix_chicago_engine driver
                     |
        protected Unix socket, protocol v2
                     |
       root-owned Linux backend service
          |                        |
   bounded kernel transport    unprivileged finite worker
          |                        |
   EC-mediated sensor TLS      hardware SGX: LE + WBDI + Engine
```

The unchanged production-signed Goodix Engine is
`Engine_Enclave_3.02.00.signed.dll`, version `Milan_v_3.02.00.15`, profile12.
The separate WBDI enclave supplies the original acquisition preparation and
protected handoff. The loader reconstructs and verifies the signed enclave
layout, then uses hardware SGX through a tiny OS-free KVM instruction guest.
It does not boot Windows or use a Windows driver stack.

The root parent owns the bounded sensor transport and encrypted BIOS input.
The worker permanently drops privileges and owns its LE/WBDI/Engine session.
Original signature, launch authorization, peer, template and TLS checks remain.

## State and lifetimes

Fresh worker startup requires an empty reader to establish the original
baseline. Images and calibration remain transient RAM. Original enrollment
classification, preprocessing, merging and completion counters decide which
placements contribute; libfprint carries progress and retry reports.

The exported enrollment is an opaque, originally sealed template in FpPrint.
fprintd stores it normally. A legacy SIFT template is a different representation
and cannot be converted by changing a schema marker.

A healthy nonfinal verification acquisition retry can end the current
libfprint action while retaining the worker, its calibration and actual-lift
gate. Protocol flag `RETRY_SESSION_RETAINED` (bit4) is valid only on an empty
`END_ACTION`/`CLOSED` acknowledgement. Host template buffers are erased at that
boundary. A subsequent `BEGIN_VERIFY` must provide a template again before
another step. Only actual vendor empty classification clears the removal gate.

Completed decisions, enrollment completion, cancellation, error and timeout
close the worker and restore the sensor. General reuse after a completed match
or nonmatch is not implemented. Original adaptive updates are exported and
erased, without persisting the replacement template. Match-with-update still
counts as a match.

The session has a512-frame and1200-second outer bound. Template bodies have a
4MiB engineering cap and0x255 minimum. These are integration bounds, not vendor
accuracy thresholds. Original matching thresholds are unchanged.

## Source layout

- `native-probe/`: GPL kernel transport, factory/identity wrappers, sealed-input
  transfer and transport cleanup checks.
- `native-sgx/`: loader, worker, action contracts, backend, protocol, installer
  and synthetic tests.
- `sgx-vm/`: shared Linux TLS/sealed transfer helpers and image packet checks.
  The directory name is historical; no Windows VM is shipped or required.
- `analysis/`: two public build helpers for kernel BTF and signature validation.
- `libfprint/`: LGPL upstream library source plus the original-Engine driver.
- `intel-sgx-sdk/`: the public Intel headers and root public key needed for
  signature/ABI checks, with their original license.
- `authentication/`: scoped Omarchy PAM planner and synthetic control tests.
- `scripts/`: asset import, clean build and offline tests.

Diagnostics retain bounded numerical status, not images, features, templates
or key material. Use `journalctl --all` when inspecting JSON diagnostics because
systemd can omit long `MESSAGE` fields otherwise.
