include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

define Device/Default
	PROFILES := Default
	KERNEL_LOADADDR := 0x41000000
	DEVICE_DTS = $$(SOC)-$(lastword $(subst _, ,$(1)))
	DEVICE_DTS_CONFIG := config@1
	DTS_DIR := $(DTS_DIR)/qcom
	IMAGES := sysupgrade.bin
	IMAGE/sysupgrade.bin = sysupgrade-tar | append-metadata
	IMAGE/sysupgrade.bin/squashfs :=
	ifeq ($(CONFIG_TARGET_ENABLE_SINGLE_IMAGE),y)
		IMAGES += single.img
		IMAGE/single.img := gen-single-image
	endif
endef

include $(SUBTARGET).mk

$(eval $(call BuildImage))
