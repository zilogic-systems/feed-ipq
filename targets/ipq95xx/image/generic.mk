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
	SOC := ipq9574
endef
TARGET_DEVICES += qcom_rdp433

define Device/qcom_rdp433-mht-phy
	$(call Device/FitImage)
	$(call Device/EmmcImage)
	DEVICE_VENDOR := Qualcomm
	DEVICE_MODEL := IPQ9574-RDP433-MHT-PHY
	DEVICE_DTS_CONFIG := config-rdp433-mht-phy
	SOC := ipq9574
endef
TARGET_DEVICES += qcom_rdp433-mht-phy
