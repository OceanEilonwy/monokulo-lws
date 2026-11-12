# OpenWrt package for monokulo-lws, the Monero light wallet server, with the
# LuCI page that manages it (Services > Light Wallet Server).
#
# The binary is cross-compiled with cargo (scripts/build-openwrt.sh) and
# dropped into files/ before the SDK runs: building Rust inside the SDK
# would mean bootstrapping a whole Rust toolchain. The SDK packages it with
# its init script, the LuCI page and the page's backend (an rpcd ucode
# plugin), and signs the package.
#
# LWS_VERSION, LWS_RELEASE and LWS_COMMIT come from the build script (the
# crate version, the commit count so every build upgrades the last, and the
# commit it was built from).

include $(TOPDIR)/rules.mk

PKG_NAME:=monokulo-lws
PKG_VERSION:=$(or $(LWS_VERSION),0.1.0)
PKG_RELEASE:=$(or $(LWS_RELEASE),1)
PKG_COMMIT:=$(LWS_COMMIT)

include $(INCLUDE_DIR)/package.mk

define Package/monokulo-lws
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=monokulo-lws: a Monero light wallet server
  # A static binary (TLS roots are compiled in). The LuCI page's backend is
  # an rpcd ucode plugin that reaches the server's admin API through the
  # uclient module; taskset (the init script's CPU check) is BusyBox's.
  DEPENDS:=@(aarch64||x86_64) +rpcd +rpcd-mod-ucode +ucode +ucode-mod-fs +ucode-mod-ubus +ucode-mod-uci \
	+ucode-mod-uloop +ucode-mod-uclient
  # The server runs as this user; created on install by the package scripts.
  USERID:=monokulo-lws:monokulo-lws
endef

define Package/monokulo-lws/description
  A Monero light wallet server, for Fob's Light Wallet mode and any client
  that speaks the MyMonero/monero-lws REST API. It scans the chain through
  your own monerod for every wallet's view key registered with it, so a
  wallet catches up in one request; a client keeps its spend key and signs
  on its own. Includes its LuCI page under Services > Light Wallet Server:
  the settings, the wallets it scans, and whether it is keeping up.
endef

define Package/monokulo-lws/conffiles
/etc/config/monokulo-lws
endef

define Build/Compile
endef

define Package/monokulo-lws/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config $(1)/etc/uci-defaults $(1)/lib/upgrade/keep.d
	$(INSTALL_BIN) $(CURDIR)/files/monokulo-lws $(1)/usr/bin/monokulo-lws
	$(INSTALL_BIN) $(CURDIR)/files/monokulo-lws.init $(1)/etc/init.d/monokulo-lws
	$(INSTALL_CONF) $(CURDIR)/files/monokulo-lws.config $(1)/etc/config/monokulo-lws
	$(INSTALL_BIN) $(CURDIR)/files/monokulo-lws.defaults $(1)/etc/uci-defaults/90-monokulo-lws
	$(INSTALL_DATA) $(CURDIR)/files/monokulo-lws.keep $(1)/lib/upgrade/keep.d/monokulo-lws
	$(INSTALL_DIR) $(1)/usr/share/monokulo-lws
	# The page's backend's HTTP helper (see its header).
	$(INSTALL_DATA) $(CURDIR)/files/http.uc $(1)/usr/share/monokulo-lws/http.uc
	# Which build this is: the init script hands it to procd with the
	# instance it starts, so LuCI shows the version that is running.
	printf 'version=%s\ncommit=%s\n' '$(PKG_VERSION)-r$(PKG_RELEASE)' '$(PKG_COMMIT)' \
		>$(1)/usr/share/monokulo-lws/version
	chmod 0644 $(1)/usr/share/monokulo-lws/version
	# The LuCI page's backend: ubus object monokulo-lws.
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode
	$(INSTALL_DATA) $(CURDIR)/files/rpcd.uc $(1)/usr/share/rpcd/ucode/monokulo-lws
	$(INSTALL_DIR) $(1)/www/luci-static/resources/view
	$(INSTALL_DATA) $(CURDIR)/files/luci/monokulo-lws.js $(1)/www/luci-static/resources/view/monokulo-lws.js
	$(INSTALL_DIR) $(1)/usr/share/luci/menu.d $(1)/usr/share/rpcd/acl.d
	$(INSTALL_DATA) $(CURDIR)/files/luci/menu.json $(1)/usr/share/luci/menu.d/luci-app-monokulo-lws.json
	$(INSTALL_DATA) $(CURDIR)/files/luci/acl.json $(1)/usr/share/rpcd/acl.d/luci-app-monokulo-lws.json
endef

# LuCI reads its menu and ACLs at login, and rpcd its plugins at start:
# drop LuCI's caches and reload rpcd so Services > Light Wallet Server
# shows up (or goes) without a reboot.
#
# On an upgrade, restart the server so the new binary runs: the SDK's own
# script (default_postinst, which runs before this) only calls start, and
# procd leaves a running instance alone when its command line is unchanged.
define Package/monokulo-lws/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* /tmp/luci-modulecache/* 2>/dev/null
/etc/init.d/rpcd reload 2>/dev/null
if [ "$${PKG_UPGRADE}" = 1 ] && /etc/init.d/monokulo-lws running; then
	/etc/init.d/monokulo-lws restart
fi
exit 0
endef

# Removal leaves the data folder (the database holds every wallet's view
# key: the operator's to delete), the admin key and the settings, and
# takes the firewall rule the package made.
define Package/monokulo-lws/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
if [ "$${PKG_UPGRADE}" != 1 ] && uci -q get firewall.monokulo_lws >/dev/null; then
	uci -q delete firewall.monokulo_lws && uci -q commit firewall
fi
rm -f /tmp/luci-indexcache* /tmp/luci-modulecache/* /var/run/monokulo-lws/check /var/run/monokulo-lws/check.* 2>/dev/null
/etc/init.d/rpcd reload 2>/dev/null
exit 0
endef

$(eval $(call BuildPackage,monokulo-lws))
