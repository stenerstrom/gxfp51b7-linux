# gxfp51b7-linux

Linux support for the **Goodix GXFP51B7 / ChicagoHS fingerprint reader** in the
tested Huawei MACHC-WAX9 laptop. It integrates with ordinary **libfprint,
fprintd and pam_fprintd**.

The original signed Goodix Engine performs enrollment and matching inside
hardware Intel SGX. Linux handles the sensor transport, lifecycle and fprintd
integration. No Windows installation, Wine, or replacement SIFT matcher is
used. A small OS-free KVM guest runs the SGX entry instructions.

This is an experimental, hardware-specific pilot. It is not an upstream
libfprint driver or a general driver for every Goodix reader.

## Verified behavior

On the development laptop:

- Standard `fprintd-enroll` produced a new original-engine sealed template.
- Standard `fprintd-verify` matched the enrolled finger in fresh sessions and
  rejected a different finger.
- Fingerprint authentication succeeded through both **sudo** and a real
  desktop **Polkit** prompt.
- An acquisition retry retained its SGX/TLS worker, then reached a match in the
  same worker. The sensor transport restored successfully afterwards.

These are functional checks on one laptop, not measured biometric error rates.
See [validation and limitations](docs/validation.md).

## Supported pilot environment

- Huawei DMI vendor `HUAWEI`, product `MACHC-WAX9`.
- ACPI device `GXFP51B7:00`, original ChicagoHS profile12, 80×64 samples.
- x86-64 Linux; tested with Omarchy/Arch kernel `7.2.5-3-omarchy`.
- Python3.11 or newer for the build and host scripts.
- Working Intel SGX, `/dev/sgx_vepc`, KVM, and the required EPC capacity.
- Running-kernel headers and BTF matching the kernel's IOVA layout. The
  low-level EC/IOMMU transport checks its assumptions before use.
- The pilot desktop account must have **UID1000 and GID1000**. Its username is
  resolved locally; no particular username is required.
- fprintd `1.94.5`, libfprint base `1.94.100`, libgusb `0.4.9`
  (`libgusb.so.2.0.10`) in the tested environment.

Other models, sensor revisions, distributions and kernels need their own
validation. The existing model, ownership and layout guards are intentional.

## Build

The build runs as an ordinary user. It compiles modules but does not load them,
open the reader, read enrollments, or edit system authentication.

On Arch, install the build/runtime dependencies and headers for your running
kernel. For the tested Omarchy kernel, the header package is
`linux-omarchy-headers`; other kernels use their corresponding header package.

```sh
sudo pacman -S --needed base-devel python meson ninja glib2-devel libgusb \
  libgudev cairo openssl zlib fprintd python-gobject polkit
git clone https://github.com/stenerstrom/gxfp51b7-linux.git
cd gxfp51b7-linux
```

Obtain the original **Goodix 1.1.151.18** and **Intel SGX DCAP for Windows
1.27.101.1** packages from their official distribution locations. Download
links and exact identities are in [vendor-assets.json](vendor-assets.json).
Extract the packages locally, then import the five required files:

```sh
python3 scripts/import_vendor.py \
  --goodix-dir /path/to/extracted/goodix \
  --intel-dir /path/to/extracted/intel
python3 scripts/build.py
```

The importer accepts only the listed filenames, sizes and SHA256 hashes. It
does not execute a vendor installer. Imported assets, generated enclave load
plans and compiled files stay in ignored directories. Their original licenses
continue to apply; this repository does not redistribute them.

For the Goodix package, select the driver source directory containing the
top-level `Engine_Enclave_3.02.00.signed.dll` and `WBDI_Enclave.signed.dll`.
Some packages also contain a second WBDI copy under `SGXDriver`; the import
script uses the explicitly selected directory's direct file first.

The build writes `native-sgx/engine-service-build/build.json`, binding the
runtime dependencies and successful checks to their hashes.

## Install the driver

The installer stages a protected release under `/opt/gxfp51b7`, adds a backend
service and gives the existing fprintd daemon a private library path. It keeps
the distribution's fprintd and PAM modules. The private libfprint build enables
only this reader driver.

Finish other fprintd operations first. Keep the reader **empty** throughout
installation and the automatic Claim/Release readiness check. If the Polkit
prompt asks for authentication, use the local password so the reader remains
empty. The installer can wait for fprintd's normal idle exit after that prompt.

```sh
manifest_sha=$(sha256sum native-sgx/engine-service-build/build.json | cut -d ' ' -f1)
pkexec /usr/bin/python3 -B "$PWD/native-sgx/install_engine_candidate.py" \
  --manifest-sha256 "$manifest_sha" --reader-is-empty
```

Readiness failure restores the previous release and service configuration.
Installation preserves existing enrollments and does not change PAM. Keep the
previous protected release for rollback. After a kernel update, rebuild for
that kernel before installing a new release.

## Enroll and verify

Use the standard clients in your own terminal:

```sh
fprintd-enroll -f right-index-finger
fprintd-verify -f right-index-finger
```

Keep the reader empty until the operation starts. During enrollment, use the
same finger throughout and lift completely between placements. The original
engine determines when it has enough enrollment evidence.

`verify-remove-and-retry` requests a complete lift and another placement.
`verify-no-match` is a completed comparison. A successful enrollment should be
followed by verification in a fresh session.

The right-index label is compatible with PAM: pam_fprintd asks fprintd to verify
`any` enrolled finger. Enrollment without `-f` defaults to right-index too.
An existing working template should be kept. If you intentionally replace an
incompatible old SIFT enrollment, ordinary `fprintd-delete` deletes the user's
enrollments; that is never an automatic install step.

## Sudo, Polkit and desktop authentication

Driver installation and PAM configuration are separate. Sudo and Polkit have
been verified with the enrolled right-index finger. The supplied Omarchy PAM
integration retains password fallback and the existing lockout policy.

Read [authentication setup](docs/authentication.md) before applying it. It is
specific to the inspected Omarchy service stacks and lid helper. Other
distributions need their own PAM integration. Login and lock configuration is
provided; a complete logout/login trial is not part of the recorded validation.

## Development

Synthetic tests need no reader or proprietary runtime assets:

```sh
python3 scripts/test.py
```

They exercise protocol validation, action state, worker reuse and cancellation,
cleanup, manifest binding, installer rollback and real Linux-PAM control flow.
The full build also runs UBSan C checks and libfprint's unit suites. Its image
assembly fixture is deterministic generated noise, not a fingerprint image.

See [architecture](docs/architecture.md), [validation](docs/validation.md), and
[component licenses](THIRD_PARTY.md). No finger images, private templates,
feature arrays, BIOS inputs, keys, or personal diagnostic journals are included.
