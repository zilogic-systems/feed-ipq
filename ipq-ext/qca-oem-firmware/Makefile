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

include $(TOPDIR)/rules.mk

PKG_NAME:=qca-oem-firmware
PKG_RELEASE:=1

# Update PKG_SOURCE_URL with the internal chipcode release's  mirror repo
PKG_SOURCE_URL:=qca-networking-2025-ath-spf-13-0_qca_oem.git
PKG_SOURCE_PROTO:=git
PKG_MIRROR_HASH:=skip
PKG_VERSION:=f4138ad0de120ea8912968bdabc37885d5fd6523

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_VERSION:=$(PKG_VERSION)

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=Firmware
  CATEGORY:=ipq-ext
  TITLE:=qca-oem-firmware
  DEPENDS:=@TARGET_ENABLE_SINGLE_IMAGE @TARGET_ipq95xx||TARGET_ipq53xx||TARGET_ipq54xx
endef

define Package/$(PKG_NAME)/description
  This package contains the proprietary binaries, tools and scripts for ipq targets
endef

define Build/Compile
	true
endef

define Package/$(PKG_NAME)/install
	true
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
