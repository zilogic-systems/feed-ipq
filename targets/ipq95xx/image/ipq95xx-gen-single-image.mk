#
# Copyright (C) 2025, Zilogic Systems <code@zilogic.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Single Image Creation

define clean_chipcode_device_dir
	@rm -rf $(CHIPCODE_DEVICE_DIR)
endef

define chipcode_device_dir_setup
	$(call clean_chipcode_device_dir)

	@mkdir -vp $(CHIPCODE_DEVICE_DIR)

	@cp -rfpv $(CHIPCODE_BUILD_DIR)/* $(CHIPCODE_DEVICE_DIR)/

	cd $(CHIPCODE_DEVICE_DIR)/ && rm -rf \
					TZ.WIN_WC.1.0    \
					BOOT.MXF.2.3.1   \
					TMEL.WNS.2.2     \
					TMEL.WNS.2.1     \
					IPQ5424.ATH.13.0 \
					IPQ5322.ATH.13.0 \
					about.html       \
					.gitattributes

	cp -rf $(CHIPCODE_DEVICE_DIR)/*/* $(CHIPCODE_DEVICE_DIR)/

	mkdir -p $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64
	mkdir -p $(CHIPCODE_DEVICE_DIR)/apss_proc/out/meta-scripts
endef

define copy_wifi_files
	cp -rf $(CHIPCODE_DEVICE_DIR)/WLAN.HK*/wlan_proc/build/ms/bin/9574.wlanfw.eval/FW_IMAGES/*      $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/
	cp -rf $(CHIPCODE_DEVICE_DIR)/WLAN.WBE.*/wlan_proc/build/ms/bin/9224.wlanfw.eval_v2/upstream/*  $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/
	cp -rf $(CHIPCODE_DEVICE_DIR)/WLAN.WBE.*/wlan_proc/build/ms/bin/9224.wlanfw.single_dualmac_v2/* $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/
	cp -rf $(CHIPCODE_DEVICE_DIR)/TMEL.WNS*/firmware/signed/tmel-ipq95xx-firmware.elf $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/
endef

define copy_staging_dir_files
	cp ${STAGING_DIR_HOST}/bin/mkimage     $(CHIPCODE_DEVICE_DIR)/apss_proc/out/meta-tools/
	cp ${STAGING_DIR_HOST}/bin/ubinize     $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/
	cp ${STAGING_DIR_HOST}/bin/unsquashfs4 $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/
	cp ${STAGING_DIR_HOST}/bin/mksquashfs4 $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/
endef

define copy_built_images
	cp $(IMAGE_KERNEL) $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/openwrt-ipq95xx-generic-qcom_alxx-fit-uImage.itb
	cp $(IMAGE_ROOTFS) $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/openwrt-ipq95xx-generic-squashfs-root.img
	cp $(STAGING_DIR_IMAGE)/u-boot/* $(CHIPCODE_DEVICE_DIR)/common/build/ipq_x64/
endef

define copy_meta_tools
	cp $(STAGING_DIR_IMAGE)/meta-tools/pack.py $(CHIPCODE_DEVICE_DIR)/apss_proc/out/meta-scripts/pack.py
	cp -rf $(STAGING_DIR_IMAGE)/meta-tools $(CHIPCODE_DEVICE_DIR)/apss_proc/out/meta-tools
endef

define image_generation_prerequisites
	$(call chipcode_device_dir_setup)
	$(call copy_meta_tools)
	$(call copy_built_images)
	$(call copy_staging_dir_files)
	$(call copy_wifi_files)
endef
