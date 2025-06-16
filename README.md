# feed-ipq

`feed-ipq` is an OpenWrt feed repository which helps to build latest OpenWrt
firmware for Qualcomm Wi-Fi SoC platforms (IPQ Devices), which is on-par with
the latest release from Qualcomm. This feed can be easily integrated into
OpenWrt and OpenWrt based build systems like prplOS, IOWRT and openWiFi.

`feed-ipq` is intended to be layered on-top of an OpenWrt providing only the
required packages and files relevant for bring-up of the networking and Wi-Fi
features in the IPQ devices. This repository contains OpenWrt Target directory
files for IPQ devices, Network, Wi-Fi drivers, packages and scripts.
These can be used along with other feeds of OpenWrt.

### Directory structure

```bash
.
|-- feeds
|   |-- clo-upstream
|   ...
|   ...
|-- ipq-ext
|   |-- board-cfg-ipq95xx
|   |-- meta-tools-ipq
|   `-- qca-oem-firmware
|-- LICENSE
|-- openwrt
|   `-- 24.10
|-- README.md
`-- targets
    `-- ipq95xx
```

Directory structure of the feed-ipq is segregated based on the following

* `targets` - contains IPQ targets like ipq95xx and target related configs, files and patches

* `feeds`   - contains IPQ target specific drivers, packages and scripts

* `feeds/clo-upstream` - contains OpenWrt upstream components which are customized for IPQ targets

* `ipq-ext` - contains package extensions over ipq feeds developed by Zilogic to enhance OpenWrt features

* `openwrt` - contains release based custom enhancement patches for OpenWrt build specific for IPQ targets

## License

feed-ipq is licensed under Apache 2.0 and maintained by [Zilogic Systems](http://zilogic.com).
