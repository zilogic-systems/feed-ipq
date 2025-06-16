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

PKG_NAME:=board-cfg-ipq95xx
PKG_RELEASE:=1
PKG_VERSION:=1.0

include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
  SECTION:=board-cfg-ipq95xx
  CATEGORY:=ipq-ext
  TITLE:=board-cfg-ipq95xx
  DEPENDS:=@TARGET_ipq95xx
endef

define Package/$(PKG_NAME)/description
  This package contains board configuration details like Boot, DDR and Flash layout for IPQ based target boards
endef

Build/Compile=true

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR_IMAGE)/
	$(CP) -rf ./files/* $(STAGING_DIR_IMAGE)/
endef

$(eval $(call BuildPackage,$(PKG_NAME)))
