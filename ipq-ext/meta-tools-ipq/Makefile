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

PKG_NAME:=meta-tools-ipq
PKG_RELEASE:=1

PKG_SOURCE_URL:=https://git.codelinaro.org/clo/qsdk/oss/system/tools/meta.git
PKG_SOURCE_PROTO:=git
PKG_MIRROR_HASH:=skip
PKG_VERSION:=3fb1222d9b725222d16e33a751aaed4a0eca1d2b

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_VERSION:=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=meta-tools
  CATEGORY:=ipq-ext
  TITLE:=meta-tools-ipq
  DEPENDS:=@TARGET_ipq95xx||TARGET_ipq53xx||TARGET_ipq54xx
endef

define Package/$(PKG_NAME)/description
  This package contains required scripts to generate single image for ipq targets
endef

Build/Compile=true

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)/meta-tools
	$(CP) -rf $(PKG_BUILD_DIR)/* $(STAGING_DIR_IMAGE)/meta-tools
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
