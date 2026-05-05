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

## Automatic checks

Installed `*-kmp-*` packages are scanned for `kmod(...ko)` provides. Each
provided module becomes an automatic policy:

- runtime KMP modules are warning-level checks for the running and latest
  kernels. A specific `--kernel` request also checks runtime KMPs for that
  kernel.
- filesystem KMP modules used by boot-required mounts are promoted to boot-risk.
  `/` requires the module to be present in the initrd. Other `/etc/fstab` mounts
  without `nofail` are treated as boot-risk but do not require initrd presence by
  default.

The checker uses rpmdb as the source of installed bootable kernels and uses
`modinfo -k <kernel> <module>` as the source of module availability. This avoids
false results from stale `/usr/lib/modules` directories or weak-modules generated
files that are not owned by an RPM.

KMP detection is intentionally conservative. Storage, network-root, accelerator,
or site-specific boot dependencies that cannot be inferred from mounts should use
a configured policy so initrd requirements and severity are explicit.

## Configuration

Additional modules can be configured in `/etc/kmp-boot-check/modules.d/*.conf`:

```ini
[module "v4l2loopback"]
detect = package:v4l2loopback-kmp-*
module = v4l2loopback
initrd = optional
severity = warning
scope = important
```

Supported `detect` values are:

- `always`
- `never`
- `rootfs:<fstype>`
- `package:<rpm-glob>[,<rpm-glob>...]`

Supported `initrd` values are `optional`, `required`, and `auto`.
Supported severities are `warning` and `boot-risk`.
Supported scopes are `important` and `all`.
Use `enabled = false` to disable an automatically detected module policy.

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
