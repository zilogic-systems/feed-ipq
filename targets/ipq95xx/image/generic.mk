# DEVICE_FLASH_TYPE supported values - nor, nand, norplusnand, emmc, norplusemmc
# DEVICE_BOARD_CONFIG points to directory name containing the DDR and Flash related config details

DEVICE_VARS += DEVICE_FLASH_TYPE \
		DEVICE_BOARD_CONFIG

include ipq95xx-gen-single-image.mk

CHIPCODE_BUILD_DIR=$(BUILD_DIR)/qca-oem-firmware
CHIPCODE_PROFILE_DIR=$(CHIPCODE_BUILD_DIR)-build-profiles

define pack_single_image
	@echo Single Image : Pack IPQ Image Components into Single Image

	$(eval CHIPCODE_DEVICE_BUILD_DIR=$(CHIPCODE_DEVICE_DIR)/common/build)

	python $(CHIPCODE_DEVICE_BUILD_DIR)/ipq_x64/scripts/pack.py \
			--arch     ipq9574_64 \
			--fltype   $(DEVICE_FLASH_TYPE) \
			--srcPath  $(CHIPCODE_DEVICE_BUILD_DIR)/ipq_x64 \
			--inImage  $(CHIPCODE_DEVICE_BUILD_DIR)/ipq_x64 \
			--outImage $(CHIPCODE_DEVICE_BUILD_DIR)/bin \
			--multi_wifi_fw && \
	$(CP) -fpv $(CHIPCODE_DEVICE_BUILD_DIR)/bin/$(DEVICE_FLASH_TYPE)-ipq9574_64-single.img $@
endef

define update_board_config
	rm -rf $(CHIPCODE_DEVICE_DIR)/apss_proc/out/meta-tools/ipq9574
	cp -rf $(STAGING_DIR_IMAGE)/$(DEVICE_BOARD_CONFIG) $(CHIPCODE_DEVICE_DIR)/apss_proc/out/meta-tools/ipq9574
endef

define prepare_single_image
	@echo Single Image : Generate IPQ Image Components for Single Image

	$(eval TARGET_DEVICE_NAME=$(notdir $@))
	$(eval CHIPCODE_DEVICE_DIR=$(CHIPCODE_PROFILE_DIR)/$(TARGET_DEVICE_NAME))

	$(call image_generation_prerequisites)
	$(call update_board_config)

	cd $(CHIPCODE_DEVICE_DIR)/common/build && \
			export BLD_ENV_BUILD_ID=O && \
			python update_common_info.py --fltype $(DEVICE_FLASH_TYPE)
endef

define Build/gen-single-image
	$(call prepare_single_image)
	$(call pack_single_image)
endef

define Device/FitImage
	KERNEL_SUFFIX := -uImage.itb
	KERNEL = kernel-bin | libdeflate-gzip | fit gzip $$(KDIR)/image-$$(DEVICE_DTS).dtb
	KERNEL_NAME := Image
endef

define Device/EmmcImage
	IMAGES += factory.bin sysupgrade.bin
	IMAGE/factory.bin := append-rootfs | pad-rootfs | pad-to 64k
	IMAGE/sysupgrade.bin/squashfs := append-rootfs | pad-to 64k | sysupgrade-tar rootfs=$$$$@ | append-metadata
endef

define Device/qcom_rdp433
	$(call Device/FitImage)
	$(call Device/EmmcImage)
	DEVICE_VENDOR := Qualcomm
	DEVICE_MODEL := IPQ9574-RDP433
	DEVICE_DTS_CONFIG := config-rdp433
	DEVICE_FLASH_TYPE := norplusnand
	DEVICE_BOARD_CONFIG := board-cfg-ipq9574
	SOC := ipq9574
	DEVICE_PACKAGES += uboot-ipq9574-norplusnand board-cfg-ipq95xx
endef
TARGET_DEVICES += qcom_rdp433

define Device/qcom_rdp433-mht-phy
	$(call Device/FitImage)
	$(call Device/EmmcImage)
	DEVICE_VENDOR := Qualcomm
	DEVICE_MODEL := IPQ9574-RDP433-MHT-PHY
	DEVICE_DTS_CONFIG := config-rdp433-mht-phy
	DEVICE_FLASH_TYPE := emmc
	DEVICE_BOARD_CONFIG := board-cfg-ipq9574
	SOC := ipq9574
	DEVICE_PACKAGES += uboot-ipq9574-mmc board-cfg-ipq95xx
endef
TARGET_DEVICES += qcom_rdp433-mht-phy
