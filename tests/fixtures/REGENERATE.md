# Regenerating `sample-firmware.bin`

`sample-firmware.bin` is a small (< 5 MB) crafted **squashfs v4** image shipped
in the repository as a binary blob. It is the bundled firmware fixture used by
embalmer's smoke and integration tests. It contains deliberately planted
artifacts (fake credentials, a fake private key, placeholder ELF binaries) so
the `creds` and `binaries` checks have something to find.

The blob is checked in directly so that the test suite does not depend on
`squashfs-tools` being installed. You only need the steps below if you want to
**rebuild** it.

## System dependency

Building the fixture requires `mksquashfs` from `squashfs-tools`:

- **Arch:** `sudo pacman -S squashfs-tools`
- **Debian/Ubuntu:** `sudo apt install squashfs-tools`

## Planted artifacts

| Path                       | Purpose                                              |
|----------------------------|------------------------------------------------------|
| `etc/shadow`               | hashed root + admin password hashes (credential)     |
| `etc/sample.conf`          | plaintext `admin_password`, `api_key`, `db_pass`     |
| `etc/network.conf`         | benign config (negative control — no credentials)    |
| `home/admin/.ssh/id_rsa`   | fake RSA private key (credential)                     |
| `bin/busybox`              | placeholder ELF binary (target for the blight handoff)|
| `bin/init`                 | small shell script                                   |
| `usr/lib/libcrypto.so`     | placeholder ELF shared object                        |

All key material and passwords above are **fake** and exist only to exercise
the scanners. They are not real secrets.

## Regeneration script

Run from the repository root:

```sh
cd tests/fixtures
rm -rf rootfs sample-firmware.bin
mkdir -p rootfs/etc rootfs/bin rootfs/usr/lib rootfs/home/admin/.ssh

printf 'root:$6$saltsalt$3xampleHashedPasswordValueForFixtureTestingABCDEF0123456789:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nadmin:$1$abc$0123456789abcdefSHORTmd5hash:19000:0:99999:7:::\n' > rootfs/etc/shadow

printf '# sample device config\nadmin_password=SuperSecret123\napi_key=AKIAIOSFODNN7EXAMPLE\ndb_user=root\ndb_pass=toor\nhost=192.168.0.1\n' > rootfs/etc/sample.conf

printf '# network\nhostname=router\ndns=8.8.8.8\n' > rootfs/etc/network.conf

printf '\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00' > rootfs/bin/busybox
head -c 1024 /dev/zero >> rootfs/bin/busybox

printf '\x7fELF\x02\x01\x01\x00' > rootfs/usr/lib/libcrypto.so
head -c 512 /dev/zero >> rootfs/usr/lib/libcrypto.so

printf -- '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAfixtureFakeKeyMaterialForTestingNotRealABCDEFG=\n-----END RSA PRIVATE KEY-----\n' > rootfs/home/admin/.ssh/id_rsa

printf '#!/bin/sh\necho boot\n' > rootfs/bin/init
chmod +x rootfs/bin/init rootfs/bin/busybox

# -all-root + -mkfs-time 0 + -fstime 0 make the build reproducible
mksquashfs rootfs sample-firmware.bin -comp gzip -noappend -all-root -mkfs-time 0 -fstime 0

rm -rf rootfs
```

The `rootfs/` source tree is intentionally **not** committed — only the built
`sample-firmware.bin` blob and this document are. Re-run the script to recreate
`rootfs/` and rebuild the blob.
