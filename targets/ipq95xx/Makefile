include $(TOPDIR)/rules.mk

ARCH:=aarch64
BOARD:=ipq95xx
BOARDNAME:=Qualcomm Technologies, Inc. IPQ95XX
FEATURES:=squashfs fpu ramdisk nand pcie
CPU_TYPE:=cortex-a73
CPU_SUBTYPE:=neon-vfpv4
SUBTARGETS:=generic

KERNELNAME:=Image dtbs

KERNEL_PATCHVER:=6.6
KERNEL_DETAILS_FILE_CUSTOM=$(PLATFORM_DIR)/kernel-$(KERNEL_PATCHVER)

include $(INCLUDE_DIR)/target.mk
include $(PLATFORM_DIR)/profiles/ipq-ath.mk
include $(PLATFORM_DIR)/profiles/iowrt.mk

DEFAULT_PACKAGES += \
	e2fsprogs uboot-envtools kmod-leds-gpio kmod-gpio-button-hotplug kmod-button-hotplug \
	kmod-ata-core kmod-ata-ahci kmod-ata-ahci-platform kmod-usb3 \
	kmod-usb-phy-ipq807x kmod-usb-dwc3-qcom-internal kmod-usb-dwc3-internal \
	kmod-fs-ext4 mkf2fs f2fsck kmod-fs-f2fs \
	kmod-leds-gpio taskset \
	rpcd libuci-lua

IPQ_EXT_PROFILE_PACKAGES := \
	meta-tools-ipq qca-oem-firmware

DEFAULT_PACKAGES += \
	$(IPQ_ATH_PROFILE_PACKAGES) \
	$(IPQ_EXT_PROFILE_PACKAGES)

# Uncomment to enable TR-x69 packages
# DEFAULT_PACKAGES += \
# 	$(IOWRT_PROFILE_PACKAGES) -odhcpd-ipv6only

GENERIC_LINUX_CONFIG = $(PLATFORM_DIR)/generic/config-$(KERNEL_PATCHVER)-platform

override GENERIC_BACKPORT_DIR :=
override GENERIC_PATCH_DIR :=
override GENERIC_HACK_DIR :=
override GENERIC_FILES_DIR :=

define Kernel/Prepare
	$(LINUX_CAT) $(DL_DIR)/$(LINUX_SOURCE) | $(TAR) -C $(KERNEL_BUILD_DIR) $(TAR_OPTIONS)

	$(if $(QUILT),rm -rf $(LINUX_DIR)/patches; mkdir -p $(LINUX_DIR)/patches)
	$(if $(FILES_DIR),$(CP) $(FILES_DIR)/* $(LINUX_DIR)/)
	find $(LINUX_DIR)/ -name \*.rej -or -name \*.orig | $(XARGS) rm -f
	$(call PatchDir,$(LINUX_DIR),$(PATCH_DIR),platform/)

	$(if $(QUILT),touch $(LINUX_DIR)/.quilt_used)
endef

define Kernel/Configure
	$(call Kernel/Configure/Default)
	echo '# CONFIG_INITRAMFS_PRESERVE_MTIME is not set' >> $(LINUX_DIR)/.config
endef

$(eval $(call BuildTarget))
