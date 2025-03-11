# feed-ipq

This repository has the OpenWrt feed to build the OS for the Qualcomm WiFi SoC platforms.
This feed can be used with OpenWrt, prplOS, and openWiFi

## OpenWrt

OpenWrt Project is a Linux operating system targeting embedded devices. Instead
of trying to create a single, static firmware, OpenWrt provides a fully
writable filesystem with package management. This frees you from the
application selection and configuration provided by the vendor and allows you
to customize the device through the use of packages to suit any application.
For developers, OpenWrt is the framework to build an application without having
to build a complete firmware around it; for users this means the ability for
full customization, to use the device in ways never envisioned.

* https://openwrt.org/

## OpenWrt Feeds

In OpenWrt, a “feed” is a collection of packages which share a common location.
Feeds may reside on a remote server, in a version control system, on the local
filesystem, or in any other location addressable by a single name (path/URL)
over a protocol with a supported feed method. Feeds are additional predefined
package build recipes for OpenWrt Buildroot. They may be configured to support
custom feeds or non-default feed packages via a feed configuration file.

The list of usable feeds is configured from either the feeds.conf file, if it
exists, or otherwise the feeds.conf.default file. This file contains a list of
feeds with each feed listed on a separate line. Each feed line consists of 3
whitespace-separated components: The feed method, the feed name, and the feed
source. Blank lines, excessive white-space/newlines, and comments are ignored
during parsing. Comments begin with `#` and extend to the end of a line.

Below is the reference `feeds.conf.default` available in **OpenWrt 24.10.0** release

```
src-git packages https://git.openwrt.org/feed/packages.git^201fd099b80a2931b7326ce20b0cbb824296c99f
src-git luci https://git.openwrt.org/project/luci.git^7b0663a5557118499dc3b3d44550efc1b6fa3feb
src-git routing https://git.openwrt.org/feed/routing.git^e87b55c6a642947ad7e24cd5054a637df63d5dbe
src-git telephony https://git.openwrt.org/feed/telephony.git^fd605af7143165a2490681ec1752f259873b9147
```

* https://openwrt.org/docs/guide-developer/feeds

## Directory structure

```
user@linux:[feed-ipq]$ tree --charset=ascii -L 2
.
|-- feeds
|   |-- clo-upstream
|   |-- nss-host
|   |-- platform_utils
|   |-- ssdk
|   `-- wlan_utils
|-- README.md
`-- targets
    `-- ipq95xx

8 directories, 1 file
```

Directory structure of the feed-ipq is segregated based on the following

* targets - contains ipq targets like ipq95xx and target related configs, files and patches

* feeds   - contains ipq target specific drivers, packages and scripts

* feeds/clo-upstream - contains OpenWrt upstream components which are customized for ipq targets

## Development

To build your own firmware you need a GNU/Linux, BSD or macOS system (case
sensitive filesystem required). Cygwin is unsupported because of the lack of a
case sensitive file system.

### Requirements

You need the following tools to compile OpenWrt, the package names vary between
distributions. A complete list with distribution specific packages is found in
the [Build System Setup](https://openwrt.org/docs/guide-developer/build-system/install-buildsystem)
documentation.

```
binutils bzip2 diff find flex gawk gcc-6+ getopt grep install libc-dev libz-dev
make4.1+ perl python3.7+ rsync subversion unzip which
```

## Build OpenWrt using feed-ipq for ipq targets

### 1. OpenWrt repo initialization

* Clone the OpenWrt repository using the command

```
git clone https://github.com/openwrt/openwrt.git
cd openwrt
```

* Checkout to OpenWrt Latest Stable Release - **v24.10.0**

```
git checkout v24.10.0
```

### 2. Configure feed-ipq repo in feeds.conf.default

* Append the below line into OpenWrt's `feeds.conf.default` to add and configure
  feed-ipq repo into the build

```
src-git feed_ipq https://github.com/zilogic-systems/feed-ipq.git^23e8cddafd7d21810288024ef5de137447646fc6
```

* Update the **latest commit_hash** in `feeds.conf.default` to fetch updated commits in
  **feed-ipq** repo.

### 3. Bump Kernel version for ipq targets

* Based on clo release, Kernel version needs to be updated for ipq targets

* Update the below Kernel version related details in `include/kernel-6.6`

```
LINUX_VERSION-6.6 = .47
LINUX_KERNEL_HASH-6.6.47 = d43376c9e9eaa92bb1b926054bd160d329c58a62d64bd65fe1222c11c6564f50
```

### 4. Update & Install feeds

1. Run `./scripts/feeds update -a` to obtain all the latest package definitions
   defined in feeds.conf / feeds.conf.default

2. Run `./scripts/feeds install -a` to install symlinks for all obtained
   packages into package/feeds/


### 5. Install IPQ targets from feed-ipq

* Install IPQ targets from `feed_ipq` directory using the command

```bash
./scripts/feeds install ipq95xx
```

* Above command will create a symlink of target between `feeds/feed_ipq/targets/ipq95xx` and `target/linux/feeds/ipq95xx` directory

### 6. Configure Build Target profile

* Select and save ipq95xx target profile using the **make menuconfig** command in the below sequence

```bash
1. Target System  -> Qualcomm Technologies, Inc. IPQ95XX
2. Subtarget      -> (QTI IPQ95xx(64bit) based boards)
3. Target Profile -> Qualcomm IPQ9574-RDP433
4. Save -> .config
5. Exit -> Yes
```

### 7. Trigger OpenWrt build

* Execute the below command to trigger the OpenWrt build

```bash
make V=e -j$(nproc)
```

## License

OpenWrt is licensed under GPL-2.0
