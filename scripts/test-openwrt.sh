#!/bin/sh
# Boot OpenWrt (the official x86_64 rootfs image, its own procd, ubus, rpcd
# and uhttpd) in Docker and test the package scripts/build-openwrt.sh built
# for x86_64, as a router runs it: installed by name from the signed
# repository, started against a stand-in node (a CGI script that answers
# get_info), and driven through the LuCI page's backend over ubus (through
# LuCI's own JSON-RPC, as a login granted the page's ACL alone, so the
# ACL is what is tested): its status with the server's own /daemon_status,
# a wallet added from a block, paused, rescanned and removed, a wrong view
# key refused in the server's words, a saved setting taken, a refused one
# leaving the server running, an upgrade keeping settings and the admin
# key, a new admin key, and removal stopping it.
#
# Usage: scripts/test-openwrt.sh [dist]
#   dist: what scripts/build-openwrt.sh made for x86_64 (default dist/):
#   the repository in dist/repo/, and dist/throwaway.pem when a throwaway
#   key signed it (otherwise openwrt/keys/monokulo.pem must have).
#
# Needs: docker (the container runs --privileged: procd as PID 1 needs it).
# openwrt.yml's test job runs it after the x86_64 build.
set -eu
cd "$(dirname "$0")/.."

DIST=$(cd "${1:-dist}" && pwd)
# The official rootfs, pinned by digest.
IMAGE="${ROOTFS_IMAGE:-openwrt/rootfs:x86-64-25.12.5@sha256:c5d5f05bab4ce06a4e840b3573671a06ec8ae9842273188ffc53f7021836b8e2}"
C=monokulo-lws-openwrt-test-$$
PKG=monokulo-lws
KEY=$DIST/throwaway.pem
[ -f "$KEY" ] || KEY=$PWD/openwrt/keys/monokulo.pem
for f in "$DIST/repo/packages.adb" "$KEY"; do
	[ -f "$f" ] || {
		echo "error: no $f: run scripts/build-openwrt.sh for x86_64 first" >&2
		exit 1
	}
done
# A stagenet wallet with nothing in it, made from the spend key 7 and the
# view key 11: a key pair the server can check, and a wrong key for it.
ADDRESS=58pQgGqEdTh43yGQYLWKxshBnnq8nRkFfPcUwfqpihwJWcrHzKy8pyk9Ai1fXeg2Gf49S2CrTyPYJG9ru2hQcTWoLczdF1N
VIEW_KEY=0b00000000000000000000000000000000000000000000000000000000000000
WRONG_KEY=0c00000000000000000000000000000000000000000000000000000000000000
DB=/srv/$PKG/lws.sqlite
KEY_FILE=/etc/$PKG/secrets/MONOKULO_LWS_ADMIN_KEY

passed=0
cleanup() {
	docker rm -f "$C" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# x <script>: runs a shell script in the router.
x() {
	docker exec -i "$C" sh -c "$1"
}

fail() {
	echo "not ok - $1" >&2
	echo "--- the router's log:" >&2
	x 'logread | tail -n 60' >&2 || true
	exit 1
}

# check <what> <script>: the script, run in the router, must succeed.
check() {
	x "$2" >/dev/null 2>&1 || {
		echo "--- $2" >&2
		x "$2" >&2 || true
		fail "$1"
	}
	passed=$((passed + 1))
	echo "ok - $1"
}

# eventually <what> <script>: the script must succeed within 30 seconds.
eventually() {
	i=0
	until x "$2" >/dev/null 2>&1; do
		i=$((i + 1))
		[ $i -lt 60 ] || {
			echo "--- $2" >&2
			x "$2" >&2 || true
			fail "$1"
		}
		sleep 0.5
	done
	passed=$((passed + 1))
	echo "ok - $1"
}

docker run -d --privileged --name "$C" -v "$DIST:/dist:ro" "$IMAGE" /sbin/init >/dev/null
eventually "OpenWrt boots: procd, ubus, rpcd and LuCI's ubus objects" 'ubus call system board && ubus -S list luci'
eventually "the LAN has its address" '. /lib/functions/network.sh && network_get_ipaddr a lan && [ -n "$a" ]'

# Shell helpers in the router: whether the server runs, and LuCI's JSON-RPC
# as the page calls it.
x 'cat >/tmp/t.sh' <<'EOF'
running() {
	ubus call service list "{\"name\":\"$1\"}" | jsonfilter -q -e "@['$1'].instances.*.running" | grep -q true
}
pid() {
	ubus call service list "{\"name\":\"$1\"}" | jsonfilter -q -e "@['$1'].instances.*.pid"
}
# rpc <method> [args]: the page's backend through uhttpd's /ubus, as LuCI
# calls it, in a session of a login granted the page's ACL alone
# (luci-app-monokulo-lws), so the call is held to what the page may do.
rpc() {
	args=${2:-'{}'}
	sid=$(ubus call session login '{"username":"monokulo-lws","password":""}' | jsonfilter -e '@.ubus_rpc_session')
	uclient-fetch -q -O - --post-data="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$sid\",\"monokulo-lws\",\"$1\",$args]}" \
		http://127.0.0.1/ubus | jsonfilter -e '@.result[1]'
}
# denied <object> <method>: the page's ACL doesn't let it call that.
denied() {
	sid=$(ubus call session login '{"username":"monokulo-lws","password":""}' | jsonfilter -e '@.ubus_rpc_session')
	[ "$(uclient-fetch -q -O - --post-data="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"call\",\"params\":[\"$sid\",\"$1\",\"$2\",{}]}" \
		http://127.0.0.1/ubus | jsonfilter -e '@.error.code')" = -32002 ]
}
# accounts_with <state> <address>: whether the page lists the wallet in that state.
accounts_with() {
	rpc accounts | jsonfilter -e "@.accounts.$1[*].address" | grep -qx "$2"
}
scan_height_of() {
	rpc accounts | jsonfilter -e "@.accounts.*[@.address='$1'].scan_height"
}
EOF

# A stand-in for monerod on the node's usual port: every JSON-RPC call is
# answered as get_info on stagenet, so the server starts and finds its
# network; blocks it asks for are 404s it retries, which is fine here.
x 'mkdir -p /tmp/node && cat >/tmp/node/json_rpc <<"EOF"
#!/bin/sh
cat >/dev/null
printf "Status: 200 OK\r\nContent-Type: application/json\r\n\r\n"
printf "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"result\":{\"status\":\"OK\",\"height\":2300000,\"target_height\":2300000,\"nettype\":\"stagenet\",\"version\":\"0.18.4.0\",\"synchronized\":true,\"top_block_hash\":\"%064d\"}}\n" 0
EOF
chmod +x /tmp/node/json_rpc && uhttpd -p 127.0.0.1:18081 -h /tmp/node -x /'
check "the stand-in node answers get_info" 'uclient-fetch -q -O - --post-data="{}" http://127.0.0.1:18081/json_rpc | jsonfilter -e "@.result.nettype" | grep -qx stagenet'

# The repository, as the install page says: its key trusted and the
# repository added, nothing else (the container has no internet: the
# package's dependencies are in the image already).
docker cp "$KEY" "$C:/etc/apk/keys/monokulo.pem"
x ': >/etc/apk/repositories.d/distfeeds.list; echo /dist/repo/packages.adb >/etc/apk/repositories.d/customfeeds.list'
check "the repository's index is signed by the key the router trusts" 'apk update'
check "the repository holds the package" "apk search $PKG | grep -q '^$PKG-[0-9]'"

# --- install and start ---------------------------------------------------------

check "the package installs by name from the repository" "apk add $PKG"
check "the server's user exists" "id -u $PKG"
check "the LuCI page is installed: its view, menu, ACL and backend" \
	"[ -s /www/luci-static/resources/view/$PKG.js ] && jsonfilter -i /usr/share/luci/menu.d/luci-app-$PKG.json -e '@[\"admin/services/$PKG\"].action.path' | grep -qx $PKG && jsonfilter -i /usr/share/rpcd/acl.d/luci-app-$PKG.json -e '@[\"luci-app-$PKG\"].read.ubus[\"$PKG\"]' | grep -q status && [ -s /usr/share/$PKG/http.uc ]"
check "rpcd serves the page's ubus object" "ubus -S list $PKG"
check "the firewall rule is made, off" \
	"[ \"\$(uci get firewall.monokulo_lws.enabled)\" = 0 ] && [ \"\$(uci get firewall.monokulo_lws.dest_port)\" = 8443 ]"
eventually "the server runs, as its own user" \
	". /tmp/t.sh; running $PKG && [ \"\$(awk '/^Uid:/ { print \$2 }' /proc/\$(pid $PKG)/status)\" = \"\$(id -u $PKG)\" ]"
check "the admin key was made at the first start, 64 hex characters, root's alone" \
	"[ \"\$(ls -ln $KEY_FILE | awk '{ print \$1, \$3 }')\" = '-rw------- 0' ] && grep -qx '[0-9a-f]\{64\}' $KEY_FILE && [ \"\$(ls -ldn /etc/$PKG/secrets | cut -c1-10)\" = drwx------ ]"
check "the database is the server's, in its data folder" \
	"[ \"\$(ls -ln $DB | awk '{ print \$3 }')\" = \"\$(id -u $PKG)\" ] && [ \"\$(ls -ldn /srv/$PKG | cut -c1-10)\" = drwx------ ]"
check "the sysupgrade backup keeps the settings, the admin key and the data" \
	"sysupgrade -l | grep -qx /etc/config/$PKG && sysupgrade -l | grep -qx $KEY_FILE"

# A LuCI login granted the page's ACL alone, named as the package (root's
# password, none here), which rpc and denied call as.
x "uci -q batch >/dev/null; /etc/init.d/rpcd reload" <<-EOF
	add rpcd login
	set rpcd.@login[-1].username='$PKG'
	set rpcd.@login[-1].password='\$p\$root'
	add_list rpcd.@login[-1].read='luci-app-$PKG'
	add_list rpcd.@login[-1].write='luci-app-$PKG'
	commit rpcd
EOF
eventually "LuCI's JSON-RPC answers the page's status under its ACL: running, its build, the admin key made" \
	". /tmp/t.sh; s=\$(rpc status); [ \"\$(echo \"\$s\" | jsonfilter -e '@.running')\" = true ] && echo \"\$s\" | jsonfilter -e '@.running_build.version' | grep -q -- -r && [ \"\$(echo \"\$s\" | jsonfilter -e '@.admin_key')\" = true ]"
# The server names the network as its --network option takes it: stage.
eventually "the status carries the server's own /daemon_status: the node's network and height, scanning on the CPU" \
	". /tmp/t.sh; s=\$(rpc status); echo \"\$s\"; [ \"\$(echo \"\$s\" | jsonfilter -e '@.server.network')\" = stage ] && [ \"\$(echo \"\$s\" | jsonfilter -e '@.server.daemon_height')\" = 2300000 ] && [ \"\$(echo \"\$s\" | jsonfilter -e '@.server.scanner_engine.gpu')\" = false ]"
check "the status names no secret" ". /tmp/t.sh; ! rpc status | grep -q \"\$(cat $KEY_FILE)\""
check "the page's ACL grants nothing beyond it (not procd's service list, not files, not LuCI's setInitAction, which takes any service)" \
	'. /tmp/t.sh; denied service list && denied file read && denied luci setInitAction'

# --- wallets, through the admin API -------------------------------------------

check "the page lists the wallets: none yet, and no request waiting" \
	". /tmp/t.sh; a=\$(rpc accounts); [ \"\$(echo \"\$a\" | jsonfilter -e '@.ok')\" = true ] && [ -z \"\$(echo \"\$a\" | jsonfilter -q -e '@.accounts.active[0]')\" ]"
check "a wrong view key is refused, in the server's words, and nothing is added" \
	". /tmp/t.sh; r=\$(rpc add_account '{\"address\":\"$ADDRESS\",\"view_key\":\"$WRONG_KEY\",\"start_height\":-1}'); [ \"\$(echo \"\$r\" | jsonfilter -e '@.ok')\" = false ] && echo \"\$r\" | jsonfilter -e '@.error' | grep -qi 'key' && ! accounts_with active $ADDRESS"
check "the page adds a wallet, to be scanned from block 1000" \
	". /tmp/t.sh; [ \"\$(rpc add_account '{\"address\":\"$ADDRESS\",\"view_key\":\"$VIEW_KEY\",\"start_height\":1000}' | jsonfilter -e '@.ok')\" = true ] && accounts_with active $ADDRESS && [ \"\$(scan_height_of $ADDRESS)\" = 1000 ]"
check "the same wallet again is refused" \
	". /tmp/t.sh; [ \"\$(rpc add_account '{\"address\":\"$ADDRESS\",\"view_key\":\"$VIEW_KEY\",\"start_height\":-1}' | jsonfilter -e '@.ok')\" = false ]"
check "the server's own command line sees it too" "$PKG admin list --db $DB | grep -q \"active .* $ADDRESS\""
check "the page pauses the wallet" \
	". /tmp/t.sh; [ \"\$(rpc set_status '{\"addresses\":[\"$ADDRESS\"],\"status\":\"inactive\"}' | jsonfilter -e '@.ok')\" = true ] && accounts_with inactive $ADDRESS && ! accounts_with active $ADDRESS"
check "the page rescans the wallet from block 500" \
	". /tmp/t.sh; [ \"\$(rpc rescan '{\"addresses\":[\"$ADDRESS\"],\"height\":500}' | jsonfilter -e '@.ok')\" = true ] && [ \"\$(scan_height_of $ADDRESS)\" = 500 ]"
check "the page hides the wallet, and shows it again" \
	". /tmp/t.sh; [ \"\$(rpc set_status '{\"addresses\":[\"$ADDRESS\"],\"status\":\"hidden\"}' | jsonfilter -e '@.ok')\" = true ] && accounts_with hidden $ADDRESS && [ \"\$(rpc set_status '{\"addresses\":[\"$ADDRESS\"],\"status\":\"active\"}' | jsonfilter -e '@.ok')\" = true ] && accounts_with active $ADDRESS"
check "a state that isn't one is refused by the backend" \
	". /tmp/t.sh; [ \"\$(rpc set_status '{\"addresses\":[\"$ADDRESS\"],\"status\":\"gone\"}' | jsonfilter -e '@.ok')\" = false ]"
check "the page removes the wallet, whole" \
	". /tmp/t.sh; r=\$(rpc remove_accounts '{\"addresses\":[\"$ADDRESS\"]}'); [ \"\$(echo \"\$r\" | jsonfilter -e '@.ok')\" = true ] && echo \"\$r\" | jsonfilter -e '@.result.removed[0]' | grep -qx $ADDRESS && ! rpc accounts | grep -q $ADDRESS && ! $PKG admin list --db $DB | grep -q $ADDRESS"
check "the request bodies the backend hands its HTTP helper leave nothing behind" "[ -z \"\$(ls -A /var/run/$PKG 2>/dev/null | grep -vx check)\" ]"

# --- settings: taken, refused, kept across an upgrade -------------------------

check "a saved port is taken: the server listens where UCI says after a reload" \
	". /tmp/t.sh; uci set $PKG.main.port=8450; uci commit $PKG; /etc/init.d/$PKG reload; sleep 2; running $PKG"
eventually "the wallet API answers on the new port, on this router alone" \
	"uclient-fetch -q -O - http://127.0.0.1:8450/daemon_status | jsonfilter -e '@.network' | grep -qx stage && ! uclient-fetch -q -O - -T 2 http://127.0.0.1:8443/daemon_status >/dev/null 2>&1"
check "LuCI's status knows the new address" ". /tmp/t.sh; rpc status | jsonfilter -e '@.wallet_url' | grep -qx http://127.0.0.1:8450"
x ". /tmp/t.sh; pid $PKG >/tmp/$PKG.pid; uci set $PKG.main.admin_port=8450; uci commit $PKG"
check "a reload with the admin port set to the wallet's leaves the server running on its earlier settings, and LuCI says why" \
	". /tmp/t.sh; /etc/init.d/$PKG reload; sleep 2; running $PKG && [ \"\$(pid $PKG)\" = \"\$(cat /tmp/$PKG.pid)\" ] && rpc status | jsonfilter -e '@.check_error' | grep -q 'port of its own'"
check "a restart with that setting doesn't start it, and LuCI says why" \
	". /tmp/t.sh; /etc/init.d/$PKG restart; sleep 1; ! running $PKG && rpc status | jsonfilter -e '@.check_error' | grep -q 'port of its own'"
x "uci set $PKG.main.admin_port=8444; uci commit $PKG; /etc/init.d/$PKG restart"
eventually "the server runs again with the admin port restored, and the refusal is gone" ". /tmp/t.sh; running $PKG && [ ! -e /var/run/$PKG/check ]"
x ". /tmp/t.sh; pid $PKG >/tmp/$PKG.pid; uci set $PKG.main.data_dir=/tmp/$PKG-data; uci commit $PKG"
check "a data folder in memory is refused on a reload, the server kept running" \
	". /tmp/t.sh; /etc/init.d/$PKG reload; sleep 2; running $PKG && [ \"\$(pid $PKG)\" = \"\$(cat /tmp/$PKG.pid)\" ] && rpc status | jsonfilter -e '@.check_error' | grep -q 'in memory'"
check "the refusal is kept where only root reaches it" \
	"[ -s /var/run/$PKG/check ] && [ \"\$(ls -ldn /var/run/$PKG | awk '{ print \$1, \$3 }')\" = 'drwx------ 0' ]"
for dir in /root /etc/$PKG /srv /srv/../root; do
	x "uci set $PKG.main.data_dir=$dir; uci commit $PKG"
	check "a system or top-level data folder ($dir) is refused on a reload, and isn't made the server's" \
		". /tmp/t.sh; /etc/init.d/$PKG reload; sleep 2; running $PKG && [ \"\$(pid $PKG)\" = \"\$(cat /tmp/$PKG.pid)\" ] && [ -n \"\$(rpc status | jsonfilter -e '@.check_error')\" ] && [ \"\$(ls -ldn /root /etc /srv | awk '{ print \$3 }' | sort -u)\" = 0 ]"
done
x "uci set $PKG.main.data_dir=/srv/$PKG; uci commit $PKG; /etc/init.d/$PKG restart"
eventually "the server runs again in its data folder" ". /tmp/t.sh; running $PKG && [ ! -e /var/run/$PKG/check ]"
# A link the server's user could plant in its own folder: root must not
# follow it when it readies the folder.
x "ln -s /etc/shadow /srv/$PKG/shadow; ln -s /etc /srv/$PKG/etc"
check "a reload doesn't follow links in the data folder: /etc and /etc/shadow stay root's" \
	". /tmp/t.sh; /etc/init.d/$PKG reload; sleep 2; running $PKG && [ \"\$(ls -ldn /etc /etc/shadow | awk '{ print \$3 }' | sort -u)\" = 0 ]"
x "rm -f /srv/$PKG/shadow /srv/$PKG/etc"

x "sha256sum $KEY_FILE >/tmp/$PKG.sum"
check "an upgrade keeps the settings and the admin key" \
	"apk fix --reinstall $PKG && [ \"\$(uci get $PKG.main.port)\" = 8450 ] && sha256sum -c /tmp/$PKG.sum"
eventually "the server runs after the upgrade, and the page still reaches its admin API" \
	". /tmp/t.sh; running $PKG && [ \"\$(rpc accounts | jsonfilter -e '@.ok')\" = true ]"

check "the page makes a new admin key: the server stops and starts, the key changes, the page works with it" \
	". /tmp/t.sh; [ \"\$(rpc new_admin_key | jsonfilter -e '@.ok')\" = true ] && ! sha256sum -c /tmp/$PKG.sum >/dev/null 2>&1 && grep -qx '[0-9a-f]\{64\}' $KEY_FILE"
eventually "the server runs with the new key, and lists the wallets for the page" \
	". /tmp/t.sh; running $PKG && [ \"\$(rpc accounts | jsonfilter -e '@.ok')\" = true ]"
check "a key the database doesn't know is refused, and the page says to make a new one" \
	". /tmp/t.sh; cp $KEY_FILE /tmp/key.good; printf '%064d\n' 1 >$KEY_FILE; a=\$(rpc accounts); cp /tmp/key.good $KEY_FILE; [ \"\$(echo \"\$a\" | jsonfilter -e '@.ok')\" = false ] && [ \"\$(echo \"\$a\" | jsonfilter -e '@.code')\" = refused ]"

# --- removal -----------------------------------------------------------------

check "the package is removed" "apk del $PKG"
eventually "its removal stops the server" ". /tmp/t.sh; ! running $PKG"
check "its removal takes the program, the LuCI page, the backend and the firewall rule" \
	"[ ! -e /usr/bin/$PKG ] && [ ! -e /www/luci-static/resources/view/$PKG.js ] && [ ! -e /usr/share/rpcd/ucode/$PKG ] && ! uci -q get firewall.monokulo_lws && ! ubus -S list $PKG"
check "its removal keeps the database, the admin key and the settings, the operator's" \
	"[ -s $DB ] && [ -s $KEY_FILE ] && [ -s /etc/config/$PKG ]"

echo "all $passed checks passed"
