# kmp-boot-check

`kmp-boot-check` checks whether installed SUSE/openSUSE kernels have the kernel
modules needed for the next successful boot. It is intended for systems using
multiversion kernels and Kernel Module Packages (KMPs), where an older kernel can
hide that a newer installed kernel is missing a required module.

The implementation is Rust-only: the main checker and the libzypp system plugin
are both Rust binaries. The first release is warning-only and does not abort
package transactions.

## Usage

```sh
kmp-boot-check
kmp-boot-check --kernel 7.0.2-1-default
kmp-boot-check --json
kmp-boot-check --strict
```

Exit codes:

- `0`: no issue found
- `1`: warning found
- `2`: boot-risk found
- `3`: the check could not determine the result

## Built-in checks

- `bcachefs`: checked when `/` is bcachefs; module and initrd presence are
  required and reported as boot-risk.
- `nvidia`: checked when NVIDIA packages are installed; module presence is
  required and reported as warning.
- `zfs`: checked when `/` is zfs; module and initrd presence are required and
  reported as boot-risk.
- Generic KMPs: installed `*-kmp-*` packages are scanned for `kmod(...ko)`
  provides and checked as warning-level module policies for the running/latest
  kernels. A specific `--kernel` request also checks generic KMPs for that
  kernel.

The checker uses rpmdb as the source of installed bootable kernels and uses
`modinfo -k <kernel> <module>` as the source of module availability. This avoids
false results from stale `/usr/lib/modules` directories or weak-modules generated
files that are not owned by an RPM.

Generic KMP detection is intentionally warning-only. Boot-critical modules should
use a builtin or configured policy so initrd requirements and severity are
explicit.

## Configuration

Additional modules can be configured in `/etc/kmp-boot-check/modules.d/*.conf`:

```ini
[module "v4l2loopback"]
detect = package:v4l2loopback-kmp-*
module = v4l2loopback
initrd = optional
severity = warning
```

Supported `detect` values are:

- `always`
- `never`
- `rootfs:<fstype>`
- `package:<rpm-glob>[,<rpm-glob>...]`

Supported `initrd` values are `optional`, `required`, and `auto`.
Supported severities are `warning` and `boot-risk`.

## libzypp system plugin

The `zypp-plugin-kmp-boot-check` binary is intended to be installed as:

```text
/usr/lib/zypp/plugins/system/kmp-boot-check
```

It calls:

```sh
/usr/bin/kmp-boot-check --strict
```

and prints warnings after the package set changes. It intentionally does not
block package transactions. It speaks the stateful libzypp system plugin
protocol and only writes checker output to stderr so stdout remains reserved for
plugin acknowledgements.

## Build

```sh
cargo build --release
cargo test
```

## License

GPL-3.0-or-later.
