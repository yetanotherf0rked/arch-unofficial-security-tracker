# Source comparison

Tracker data from 2026-10-15 04:14Z: 2506 package/CVE pairs, 2425 unique CVEs (NVD checked for 2425).

## Precision: does the official record agree Arch's version is affected?

| Source | Tracker says | Agrees (affected) | Disagrees (not affected) | No version data / missing | Agreement where decidable |
|---|---|---|---|---|---|
| NVD | fixable | 285 | 15 | 34 | 95% |
| NVD | uncertain | 4 | 14 | 13 | 22% |
| NVD | unfixed | 187 | 489 | 1465 | 28% |
| MITRE | fixable | 269 | 11 | 54 | 96% |
| MITRE | uncertain | 3 | 2 | 26 | 60% |
| MITRE | unfixed | 312 | 301 | 1528 | 51% |

"No version data" means the record has no usable ranges for this product (NVD awaiting analysis, CNA gave only git commits, etc.).

## Recall: Repology (per-package `vulnerable` flag on Arch entries)

- Flagged by Repology: **138** Arch packages
- Flagged by both: **53**
- Repology only: **85**
- Tracker only: **367** (11 with a fixable CVE)

<details><summary>Repology only</summary>

- `aarch64-linux-gnu-binutils` 2.47 (binutils)
- `aarch64-linux-gnu-gcc` 16.1.0 (gcc)
- `adguardhome` 0.107.79 (adguardhome)
- `antiword` 0.37 (antiword)
- `arm-none-eabi-binutils` 2.47 (binutils)
- `arm-none-eabi-gcc` 16.2.0 (gcc)
- `avr-binutils` 2.47 (binutils)
- `avr-gcc` 16.1.0 (gcc)
- `crypto++` 8.9.0 (crypto++)
- `db` 6.2.32 (db)
- `db5.3` 5.3.28 (db)
- `dhcp` 4.4.3.P1 (dhcp)
- `django` 5.2.13 (python:django)
- `dovecot23` 2.3.21.1 (dovecot)
- `electron` 44 (electron)
- `electron39` 39.8.10 (electron)
- `electron40` 40.10.6 (electron)
- `electron41` 41.10.7 (electron)
- `electron42` 42.11.14 (electron)
- `electron43` 43.7.11 (electron)
- `electron44` 44.7.2 (electron)
- `ffmpeg4.4` 4.4.8 (ffmpeg)
- `freecol` 1.2.0 (freecol)
- `fuseiso` 20070708 (fuseiso)
- `gcc` 16.2.1 (gcc)
- `gcc15` 15.3.0 (gcc)
- `ghidra` 12.1.2 (ghidra)
- `gitlab` 19.4.1 (gitlab)
- `gpsd` 3.27.5 (gpsd)
- `id3lib` 3.8.3 (id3lib)
- `indent` 2.2.13 (indent)
- `lib32-libcups` 2.4.20 (cups)
- `lib32-libssh2` 1.11.1 (libssh2)
- `lib32-libxml2` 2.15.4 (libxml2)
- `libcaca` 0.99.beta20 (libcaca)
- `libdwarf` 2.3.3 (libdwarf)
- `libgda6` 6.0.0 (libgda)
- `libolm` 3.2.16 (olm)
- `libp11` 0.4.21 (libp11)
- `libprocps` 3.3.17 (procps)
- `libssh2` 1.11.1 (libssh2)
- `libtar` 1.2.20 (libtar)
- `libtomcrypt` 1.18.2 (libtomcrypt)
- `libvips` 8.18.7 (vips)
- `libxml2` 2.15.4 (libxml2)
- `libxml2-legacy` 2.13.9 (libxml2)
- `linux-api-headers` 7.2 (linux)
- `linux-lts` 6.18.56 (linux)
- `linux-tools` 7.2.10 (linux)
- `loongarch64-linux-gnu-gcc` 16.2.0 (gcc)
- `lua` 5.5.1 (lua)
- `lua51` 5.1.5 (lua)
- `lua52` 5.2.4 (lua)
- `lua53` 5.3.6 (lua)
- `lua54` 5.4.9 (lua)
- `mbedtls3` 3.6.7 (mbedtls)
- `ming` 0.4.8.r68.g04aee523 (ming)
- `mkinitcpio-busybox` 1.36.1 (busybox)
- `mujs` 1.3.10 (mujs)
- `mumble` 1.5.915 (mumble)
- `openscad` 2021.01 (openscad)
- `opusfile` 0.12 (opusfile)
- `ospray` 3.2.0 (ospray)
- `percona-server` 9.7.2_2 (percona-server)
- `postorius` 1.3.13 (postorius)
- `ppc64le-elf-binutils` 2.45.1 (binutils)
- `procps-ng` 4.0.7 (procps)
- `python-docx` 1.2.0 (python:docx-misnamed)
- `raylib` 6.0 (raylib)
- `riscv32-elf-binutils` 2.45.1 (binutils)
- `riscv64-elf-binutils` 2.47 (binutils)
- `riscv64-elf-gcc` 16.2.0 (gcc)
- `riscv64-linux-gnu-binutils` 2.47 (binutils)
- `riscv64-linux-gnu-gcc` 16.2.1 (gcc)
- `sassc` 3.6.2 (sassc)
- `sdl_image` 1.2.12 (sdl-image)
- `sdl_ttf` 2.0.11 (sdl-ttf)
- `sharutils` 4.15.2 (sharutils)
- `solr` 10.0.0 (solr)
- `tidy` 5.8.0 (tidy)
- `tinc` 1.0.37 (tinc)
- `tinyxml` 2.6.2 (tinyxml)
- `tt-rss` r12985.5236ecb04 (tt-rss)
- `yarn` 1.22.22 (yarn)
- `zip` 3.0 (zip)

</details>

<details><summary>Tracker only</summary>

- `389-ds-base`
- `7zip`
- `9base`
- `abiword`
- `aegisub`
- `alsa-lib`
- `amarok`
- `amavisd-new`
- `anki`
- `ansible`
- `ansible-core`
- `ansible-runner`
- `antlr4`
- `apcupsd`
- `apt`
- `aria2`
- `aspell`
- `assimp`
- `awstats`
- `barcode`
- `bash-completion`
- `binaryen`
- `bird`
- `blender`
- `bluez`
- `botan`
- `btrbk`
- `bzip2`
- `bzip3`
- `cacti`
- `cadaver`
- `caddy`
- `cairo`
- `capstone`
- `catdoc`
- `chromium`
- `cifs-utils`
- `cimg`
- `cjson`
- `ckermit`
- `claws-mail`
- `clevis`
- `cmake`
- `consul`
- `containerd`
- `coreutils`
- `cpanminus`
- `cpio`
- `cpp-httplib`
- `cppcheck`
- `crun`
- `cups-filters`
- `curl`
- `cvs`
- `dash`
- `dbus-broker`
- `diffutils`
- `discount`
- `dnsmasq`
- `docker-buildx`
- `dokuwiki`
- `dolphin`
- `dpdk`
- `dracut`
- `duktape`
- `efivar`
- `elfutils`
- `emacs`
- `entr`
- `eog`
- `erlang`
- `etcd`
- `ettercap`
- `evolution`
- `exiv2`
- `expat`
- `fail2ban`
- `faust`
- `fio`
- `freeglut`
- `fuse-overlayfs`
- `gawk`
- `gdal`
- `gdb`
- `gdu`
- `geary`
- `gedit`
- `gegl`
- `giac`
- `giflib`
- `gifsicle`
- `git`
- `gitsign`
- `glibc`
- `gnome-control-center`
- `gnome-keyring`
- `gnome-remote-desktop`
- `gnome-settings-daemon`
- `gnome-tweaks`
- `gnumeric`
- `gnuplot`
- `gnutls`
- `gradle`
- `graphicsmagick`
- `graphviz`
- `grpc`
- `grub`
- `gsoap`
- `gssproxy`
- `hamster-time-tracker`
- `hashcat`
- `haskell-crypton-x509`
- `haskell-crypton-x509-validation`
- `haskell-tls`
- `hdf5`
- `hiredis`
- `hplip`
- `httpie`
- `icedtea-web`
- `igmpproxy`
- `imagemagick`
- `in-toto`
- `influxdb`
- `iptables`
- `jbigkit`
- `jpegoptim`
- `jq`
- `jupyter-notebook`
- `jupyter-server`
- `jupyterlab`
- `jython`
- `keepassxc`
- `kitty`
- `knot-resolver`
- `leocad`
- `lib32-alsa-lib`
- `lib32-bzip2`
- `lib32-cairo`
- `lib32-curl`
- `lib32-expat`
- `lib32-freeglut`
- `lib32-gnutls`
- `lib32-libglvnd`
- `lib32-libx11`
- `lib32-libxi`
- `lib32-libxrender`
- `lib32-libxtst`
- `lib32-mesa`
- `lib32-ncurses`
- `lib32-nss`
- `lib32-nvidia-cg-toolkit`
- `lib32-pixman`
- `lib32-systemd`
- `lib32-util-linux`
- `lib32-zlib`
- `libao`
- `libarchive`
- `libass`
- `libcupsfilters`
- `libelfin`
- `libesmtp`
- `libfyaml`
- `libglvnd`
- `libhangul`
- `libmatio`
- `libmicrohttpd`
- `libmodplug`
- `libnfs`
- `libraw`
- `libre`
- `librecad`
- `librest`
- `libsass`
- `libsixel`
- `libsolv`
- `libsoup3`
- `libspf2`
- `libtheora`
- `libtpms`
- `libvncserver`
- `libvterm`
- `libwebsockets`
- `libwmf`
- `libx11`
- `libxi`
- `libxpm`
- `libxrender`
- `libxslt`
- `libxtst`
- `linuxptp`
- `lmdb`
- `log4cxx`
- `lrzip`
- `lrzsz`
- `luajit`
- `luksmeta`
- `lvm2`
- `lxc`
- `lxd`
- `m17n-lib`
- `m4`
- `mako`
- `man2html`
- `mapnik`
- `mc`
- `mesa`
- `miniflux`
- `miniupnpd`
- `mitmproxy`
- `mkdocs-material`
- `modemmanager`
- `mold`
- `mongo-c-driver`
- `monitoring-plugins`
- `multipath-tools`
- `mupdf`
- `mutt`
- `mutter`
- `mxml`
- `nanomsg`
- `nasm`
- `ncurses`
- `neomutt`
- `net-tools`
- `netcdf`
- `netdata`
- `netsurf`
- `network-manager-applet`
- `network-manager-sstp`
- `nginx`
- `nix`
- `nmap`
- `nnn`
- `npm`
- `nsd`
- `nss`
- `nuget`
- `nut`
- `nvidia-cg-toolkit`
- `oath-toolkit`
- `okular`
- `onnx`
- `openbabel`
- `opencascade`
- `opencolorio`
- `openconnect`
- `openexr`
- `openjpeg2`
- `openldap`
- `openvpn`
- `os-prober`
- `packagekit`
- `pam`
- `patchelf`
- `pcmanfm-qt`
- `pcp`
- `pgbouncer`
- `php-mongodb`
- `phpldapadmin`
- `phpmyadmin`
- `pixman`
- `plantuml`
- `poco`
- `podman`
- `poppler`
- `popt`
- `postgis`
- `ppp`
- `prometheus-blackbox-exporter`
- `prometheus-postgres-exporter`
- `protobuf`
- `puppet`
- `pwgen`
- `pyenv`
- `pypy3`
- `python-asyncssh`
- `python-authlib`
- `python-autobahn`
- `python-dotenv`
- `python-ecdsa`
- `python-h2`
- `python-hpack`
- `python-jose`
- `python-jwcrypto`
- `python-lupa`
- `python-oauthlib`
- `python-pip`
- `python-pysaml2`
- `python-rsa`
- `python-tornado`
- `python-virtualenv`
- `qbittorrent`
- `qemu`
- `qt6-base`
- `qt6-declarative`
- `quickjs-ng`
- `radvd`
- `rapidjson`
- `razor`
- `rbenv`

</details>

## Disagreements on fixable CVEs

| Package | Arch | CVE | Tracker fix | NVD | MITRE |
|---|---|---|---|---|---|
| chromium | 154.0.8037.97 | CVE-2026-103631 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103630 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103629 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103628 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103627 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103626 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103625 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103624 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103623 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103622 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| chromium | 154.0.8037.97 | CVE-2026-103621 | 155.0.8059.39 | not_affected (google:chrome) | not_affected (Google:Chrome) |
| openimageio | 3.1.12.1 | CVE-2026-50291 | 3.1.18.0 | not_affected (openimageio:openimageio) | no_data (AcademySoftwareFoundation:OpenImageIO) |
| cvs | 1.11.23 | CVE-2004-0778 | 1.12.9 | not_affected (gnu:cvs) | no_data (n/a:n/a) |
| cvs | 1.11.23 | CVE-2004-0405 | 1.12.5 | not_affected (cvs:cvs) | no_data (n/a:n/a) |
| cvs | 1.11.23 | CVE-2004-0180 | 1.12.5 | not_affected (cvs:cvs) | no_data (n/a:n/a) |
