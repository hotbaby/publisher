#
# Copyright (C) 2006-2012 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=publisher
PKG_VERSION:=1.0.0
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

PKG_LICENSE:=GPLv2 GPLv2+
PKG_LICENSE_FILES:=

include $(INCLUDE_DIR)/package.mk

define Package/publisher
  CATEGORY:=HomeHub
  DEPENDS:=+libubox +libubus +libblobmsg-json +libjson-c +libcurl
  TITLE:= publisher
endef

define Package/publisher/description
 publisher
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

#target=$(firstword $(subst -, ,$(BOARD)))

TARGET_CFLAGS := $(TARGET_CFLAGS) -Werror

#define Build/Compile
#	$(MAKE) -C $(PKG_BUILD_DIR) 
#endef

define Package/publisher/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/publisher $(1)/sbin/
endef

$(eval $(call BuildPackage,publisher))
