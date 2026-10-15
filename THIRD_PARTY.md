# Component licenses and provenance

| Component | License | Source / notice |
| --- | --- | --- |
| Original host loader, worker and Python integration | MIT | Root `LICENSE`; existing SPDX notices |
| `native-probe/` kernel transport and sealing modules | GPL-2.0-only | `licenses/GPL-2.0-only.txt`; per-file SPDX notices |
| `libfprint/` | LGPL-2.1-or-later | Upstream v1.94.100; `libfprint/COPYING`, `AUTHORS`, and per-file notices |
| `intel-sgx-sdk/common/inc/` | BSD-3-Clause | Intel SGX SDK 2.25 headers; `intel-sgx-sdk/License.txt` |

The libfprint copy adds the original-Engine driver and its synthetic tests.
The previous experimental SIFT driver and recorded device/fingerprint fixtures
are excluded. The assembly test uses a generated synthetic texture instead.
Upstream archive identities are recorded in [docs/upstream.json](docs/upstream.json).

Goodix and Intel signed runtime assets are supplied separately by the user.
Their filenames, expected hashes and official package locations are recorded
in [vendor-assets.json](vendor-assets.json). Importing them does not grant
redistribution rights or change their original terms. The runtime preserves
the vendor enclave signatures and launch authorization.

System dependencies, including libgusb, GLib, OpenSSL and zlib, remain under
their respective licenses. The local installer stages a copy of the system
libgusb library for this pilot; no compiled libraries are published here.
