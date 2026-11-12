#!/bin/sh
# Boot OpenWrt (the official x86_64 rootfs image, its own procd, ubus, rpcd
# and uhttpd) in Docker and test the package scripts/build-openwrt.sh built
# for x86_64, as a router runs it: installed by name from the signed
# repository, started against stand-in nodes (CGI scripts that answer
# get_info, one on mainnet and one on stagenet), and driven through the
# LuCI page's backend over ubus (through LuCI's own JSON-RPC, as a login
# granted the page's ACL alone, so the ACL is what is tested): mainnet's
# server alone at first, then stagenet's turned on beside it; the status of
# each with the server's own /daemon_status, a stagenet wallet added from a
# block, paused, rescanned and removed, a wrong view key refused in the
# server's words, a saved setting taken, a refused one leaving the servers
# running, networks that would share a port refused, an upgrade keeping
# settings and the admin keys, a new admin key for one network leaving the
# other's server alone, settings from before networks had sections
# migrated, and removal stopping them.
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
# The wallet tests run on stagenet's server; mainnet's runs beside it.
DB=/srv/$PKG-stagenet/lws.sqlite
KEY_FILE=/etc/$PKG/secrets/stagenet/MONOKULO_LWS_ADMIN_KEY
MAIN_DB=/srv/$PKG/lws.sqlite
MAIN_KEY_FILE=/etc/$PKG/secrets/mainnet/MONOKULO_LWS_ADMIN_KEY

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
# running <service> [network]: whether that network's server runs (any, without one).
running() {
	which=.*
	[ -n "${2:-}" ] && which="['$2']"
	ubus call service list "{\"name\":\"$1\"}" | jsonfilter -q -e "@['$1'].instances$which.running" | grep -q true
}
pid() {
	ubus call service list "{\"name\":\"$1\"}" | jsonfilter -q -e "@['$1'].instances['$2'].pid"
}
# rpc <method> [args]: the page's backend through uhttpd's /ubus, as LuCI
# calls it, in a session of a login granted the page's ACL alone
# (luci-app-monokulo-lws), so the call is held to what the page may do.
# The network is stagenet's unless $NET names another.
rpc() {
	args=${2:-'{}'}
	if [ "$1" = status ] || [ "$1" = restart ] || [ "$1" = reload ]; then
		:
	elif [ "$args" = '{}' ]; then
		args="{\"network\":\"${NET:-stagenet}\"}"
	else
		args="{\"network\":\"${NET:-stagenet}\",${args#\{}"
	fi
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

# Stand-ins for monerod on each network's usual port, 18081 mainnet and
# 38081 stagenet: every JSON-RPC call is answered as get_info on that
# network, so each server starts and finds its network; blocks it asks for
# are 404s it retries, which is fine here.
for node in mainnet:18081:3300000 stagenet:38081:2300000; do
	net=${node%%:*}
	rest=${node#*:}
	port=${rest%%:*}
	height=${rest#*:}
	x "mkdir -p /tmp/node-$net && cat >/tmp/node-$net/json_rpc && chmod +x /tmp/node-$net/json_rpc && uhttpd -p 127.0.0.1:$port -h /tmp/node-$net -x /" <<-EOF
		#!/bin/sh
		cat >/dev/null
		printf "Status: 200 OK\r\nContent-Type: application/json\r\n\r\n"
		printf '{"jsonrpc":"2.0","id":"0","result":{"status":"OK","height":$height,"target_height":$height,"nettype":"$net","version":"0.18.4.0","synchronized":true,"top_block_hash":"%064d"}}\n' 0
	EOF
	check "the stand-in $net node answers get_info on $port" "uclient-fetch -q -O - --post-data='{}' http://127.0.0.1:$port/json_rpc | jsonfilter -e '@.result.nettype' | grep -qx $net"
done

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
eventually "mainnet's server runs, as its own user, and it alone" \
	". /tmp/t.sh; running $PKG mainnet && ! running $PKG stagenet && ! running $PKG testnet && [ \"\$(awk '/^Uid:/ { print \$2 }' /proc/\$(pid $PKG mainnet)/status)\" = \"\$(id -u $PKG)\" ]"
check "its admin key was made at the first start, 64 hex characters, root's alone" \
	"[ \"\$(ls -ln $MAIN_KEY_FILE | awk '{ print \$1, \$3 }')\" = '-rw------- 0' ] && grep -qx '[0-9a-f]\{64\}' $MAIN_KEY_FILE && [ \"\$(ls -ldn /etc/$PKG/secrets /etc/$PKG/secrets/mainnet | cut -c1-10 | sort -u)\" = drwx------ ]"
check "its database is the server's, in its data folder" \
	"[ \"\$(ls -ln $MAIN_DB | awk '{ print \$3 }')\" = \"\$(id -u $PKG)\" ] && [ \"\$(ls -ldn /srv/$PKG | cut -c1-10)\" = drwx------ ]"

check "stagenet's server is turned on beside it" \
	"uci set $PKG.stagenet.enabled=1 && uci commit $PKG && /etc/init.d/$PKG reload"
eventually "both servers run, each on its own node, ports, database and admin key" \
	". /tmp/t.sh; running $PKG mainnet && running $PKG stagenet && [ -s $DB ] && grep -qx '[0-9a-f]\{64\}' $KEY_FILE && ! cmp -s $KEY_FILE $MAIN_KEY_FILE"
check "the sysupgrade backup keeps the settings, the admin keys and the data" \
	"sysupgrade -l | grep -qx /etc/config/$PKG && sysupgrade -l | grep -qx $KEY_FILE && sysupgrade -l | grep -qx $MAIN_KEY_FILE"

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
eventually "LuCI's JSON-RPC answers the page's status under its ACL: each network on or off, running, its build, its admin key made" \
	". /tmp/t.sh; s=\$(rpc status); for n in mainnet stagenet; do [ \"\$(echo \"\$s\" | jsonfilter -e \"@.networks.\$n.running\")\" = true ] && echo \"\$s\" | jsonfilter -e \"@.networks.\$n.running_build.version\" | grep -q -- -r && [ \"\$(echo \"\$s\" | jsonfilter -e \"@.networks.\$n.admin_key\")\" = true ] || exit 1; done; [ \"\$(echo \"\$s\" | jsonfilter -e '@.networks.testnet.enabled')\" = false ] && [ \"\$(echo \"\$s\" | jsonfilter -e '@.networks.testnet.running')\" = false ]"
# A server names the network as its --network option takes it: main, stage.
eventually "the status carries each server's own /daemon_status: its node's network and height, scanning on the CPU" \
	". /tmp/t.sh; s=\$(rpc status); echo \"\$s\"; [ \"\$(echo \"\$s\" | jsonfilter -e '@.networks.stagenet.server.network')\" = stage ] && [ \"\$(echo \"\$s\" | jsonfilter -e '@.networks.stagenet.server.daemon_height')\" = 2300000 ] && [ \"\$(echo \"\$s\" | jsonfilter -e '@.networks.stagenet.server.scanner_engine.gpu')\" = false ] && [ \"\$(echo \"\$s\" | jsonfilter -e '@.networks.mainnet.server.network')\" = main ] && [ \"\$(echo \"\$s\" | jsonfilter -e '@.networks.mainnet.server.daemon_height')\" = 3300000 ]"
check "the status names no secret" ". /tmp/t.sh; s=\$(rpc status); ! echo \"\$s\" | grep -q \"\$(cat $KEY_FILE)\" && ! echo \"\$s\" | grep -q \"\$(cat $MAIN_KEY_FILE)\""
check "the page's ACL grants nothing beyond it (not procd's service list, not files, not LuCI's setInitAction, which takes any service)" \
	'. /tmp/t.sh; denied service list && denied file read && denied luci setInitAction'

# --- wallets, through the admin API -------------------------------------------

check "a network that isn't one is refused by the backend" \
	". /tmp/t.sh; [ \"\$(NET=moon rpc accounts | jsonfilter -e '@.ok')\" = false ]"
check "testnet's server, off, is said to be off" \
	". /tmp/t.sh; [ \"\$(NET=testnet rpc accounts | jsonfilter -e '@.code')\" = off ]"
check "the page lists the wallets: none yet, and no request waiting" \
	". /tmp/t.sh; a=\$(rpc accounts); [ \"\$(echo \"\$a\" | jsonfilter -e '@.ok')\" = true ] && [ -z \"\$(echo \"\$a\" | jsonfilter -q -e '@.accounts.active[0]')\" ]"
check "a wrong view key is refused, in the server's words, and nothing is added" \
	". /tmp/t.sh; r=\$(rpc add_account '{\"address\":\"$ADDRESS\",\"view_key\":\"$WRONG_KEY\",\"start_height\":-1}'); [ \"\$(echo \"\$r\" | jsonfilter -e '@.ok')\" = false ] && echo \"\$r\" | jsonfilter -e '@.error' | grep -qi 'key' && ! accounts_with active $ADDRESS"
check "the page adds a wallet, to be scanned from block 1000" \
	". /tmp/t.sh; [ \"\$(rpc add_account '{\"address\":\"$ADDRESS\",\"view_key\":\"$VIEW_KEY\",\"start_height\":1000}' | jsonfilter -e '@.ok')\" = true ] && accounts_with active $ADDRESS && [ \"\$(scan_height_of $ADDRESS)\" = 1000 ]"
check "the same wallet again is refused" \
	". /tmp/t.sh; [ \"\$(rpc add_account '{\"address\":\"$ADDRESS\",\"view_key\":\"$VIEW_KEY\",\"start_height\":-1}' | jsonfilter -e '@.ok')\" = false ]"
check "the server's own command line sees it too" "$PKG admin list --db $DB | grep -q \"active .* $ADDRESS\""
check "mainnet's server has wallets of its own: not this one" \
	". /tmp/t.sh; [ \"\$(NET=mainnet rpc accounts | jsonfilter -e '@.ok')\" = true ] && ! NET=mainnet rpc accounts | grep -q $ADDRESS && ! $PKG admin list --db $MAIN_DB | grep -q $ADDRESS"
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
check "the request bodies the backend hands its HTTP helper leave nothing behind" "[ -z \"\$(ls -A /var/run/$PKG 2>/dev/null | grep -v '^check')\" ]"

# --- settings: taken, refused, kept across an upgrade -------------------------

# Both servers keep running through every refusal below: their pids, to see
# that neither was restarted.
pids='echo "$(pid monokulo-lws mainnet) $(pid monokulo-lws stagenet)"'
same_pids=". /tmp/t.sh; running $PKG mainnet && running $PKG stagenet && [ \"\$($pids)\" = \"\$(cat /tmp/$PKG.pids)\" ]"
no_refusal="[ -z \"\$(ls /var/run/$PKG 2>/dev/null | grep '^check')\" ]"

check "a saved port is taken: stagenet's server listens where UCI says after a reload" \
	". /tmp/t.sh; uci set $PKG.stagenet.port=8450; uci commit $PKG; /etc/init.d/$PKG reload; sleep 2; running $PKG stagenet"
eventually "its wallet API answers on the new port, on this router alone, and mainnet's still on its own" \
	"uclient-fetch -q -O - http://127.0.0.1:8450/daemon_status | jsonfilter -e '@.network' | grep -qx stage && ! uclient-fetch -q -O - -T 2 http://127.0.0.1:38443/daemon_status >/dev/null 2>&1 && uclient-fetch -q -O - http://127.0.0.1:8443/daemon_status | jsonfilter -e '@.network' | grep -qx main"
check "LuCI's status knows the new address" ". /tmp/t.sh; rpc status | jsonfilter -e '@.networks.stagenet.wallet_url' | grep -qx http://127.0.0.1:8450"
x ". /tmp/t.sh; $pids >/tmp/$PKG.pids; uci set $PKG.stagenet.admin_port=8450; uci commit $PKG"
check "a reload with stagenet's admin port set to its wallet port leaves both servers running on their earlier settings, and LuCI says why" \
	"/etc/init.d/$PKG reload; sleep 2; $same_pids && rpc status | jsonfilter -e '@.check_error' | grep -q 'port of its own'"
check "a restart with that setting doesn't start them, and LuCI says why" \
	". /tmp/t.sh; /etc/init.d/$PKG restart; sleep 1; ! running $PKG && rpc status | jsonfilter -e '@.check_error' | grep -q 'port of its own'"
x "uci set $PKG.stagenet.admin_port=38444; uci commit $PKG; /etc/init.d/$PKG restart"
eventually "both servers run again with the admin port restored, and the refusal is gone" ". /tmp/t.sh; running $PKG mainnet && running $PKG stagenet && $no_refusal"
x ". /tmp/t.sh; $pids >/tmp/$PKG.pids; uci set $PKG.stagenet.port=8443; uci commit $PKG"
check "stagenet's port set to mainnet's is refused on a reload, both servers kept running, and LuCI says why" \
	"/etc/init.d/$PKG reload; sleep 2; $same_pids && rpc status | jsonfilter -e '@.check_error' | grep -q 'both use the port 8443'"
x "uci set $PKG.stagenet.port=8450; uci set $PKG.stagenet.data_dir=/srv/$PKG/stagenet; uci commit $PKG"
check "a stagenet data folder inside mainnet's is refused on a reload, both servers kept running" \
	"/etc/init.d/$PKG reload; sleep 2; $same_pids && rpc status | jsonfilter -e '@.check_error' | grep -q 'inside the other' && [ ! -e /srv/$PKG/stagenet ]"
x "uci set $PKG.stagenet.data_dir=/tmp/$PKG-data; uci commit $PKG"
check "a data folder in memory is refused on a reload, both servers kept running" \
	"/etc/init.d/$PKG reload; sleep 2; $same_pids && rpc status | jsonfilter -e '@.networks.stagenet.check_error' | grep -q 'in memory'"
check "the refusal is kept where only root reaches it" \
	"[ -s /var/run/$PKG/check.stagenet ] && [ \"\$(ls -ldn /var/run/$PKG | awk '{ print \$1, \$3 }')\" = 'drwx------ 0' ]"
check "a restart with that setting starts mainnet's server alone, and LuCI says why stagenet's didn't" \
	". /tmp/t.sh; /etc/init.d/$PKG restart; sleep 2; running $PKG mainnet && ! running $PKG stagenet && rpc status | jsonfilter -e '@.networks.stagenet.check_error' | grep -q 'in memory' && [ -z \"\$(rpc status | jsonfilter -e '@.networks.mainnet.check_error')\" ]"
x "uci set $PKG.stagenet.data_dir=/srv/$PKG-stagenet; uci commit $PKG; /etc/init.d/$PKG restart"
eventually "both servers run again" ". /tmp/t.sh; running $PKG mainnet && running $PKG stagenet && $no_refusal"
x ". /tmp/t.sh; $pids >/tmp/$PKG.pids"
for dir in /root /etc/$PKG /srv /srv/../root; do
	x "uci set $PKG.stagenet.data_dir=$dir; uci commit $PKG"
	check "a system or top-level data folder ($dir) is refused on a reload, and isn't made the server's" \
		"/etc/init.d/$PKG reload; sleep 2; $same_pids && [ -n \"\$(rpc status | jsonfilter -e '@.check_error')\$(rpc status | jsonfilter -e '@.networks.stagenet.check_error')\" ] && [ \"\$(ls -ldn /root /etc /srv | awk '{ print \$3 }' | sort -u)\" = 0 ]"
done
x "uci set $PKG.stagenet.data_dir=/srv/$PKG-stagenet; uci commit $PKG; /etc/init.d/$PKG restart"
eventually "stagenet's server runs again in its data folder" ". /tmp/t.sh; running $PKG stagenet && $no_refusal"
# A link the server's user could plant in its own folder: root must not
# follow it when it readies the folder.
x "ln -s /etc/shadow /srv/$PKG-stagenet/shadow; ln -s /etc /srv/$PKG-stagenet/etc"
check "a reload doesn't follow links in the data folder: /etc and /etc/shadow stay root's" \
	". /tmp/t.sh; /etc/init.d/$PKG reload; sleep 2; running $PKG stagenet && [ \"\$(ls -ldn /etc /etc/shadow | awk '{ print \$3 }' | sort -u)\" = 0 ]"
x "rm -f /srv/$PKG-stagenet/shadow /srv/$PKG-stagenet/etc"

x "sha256sum $KEY_FILE $MAIN_KEY_FILE >/tmp/$PKG.sum"
check "an upgrade keeps the settings and the admin keys" \
	"apk fix --reinstall $PKG && [ \"\$(uci get $PKG.stagenet.port)\" = 8450 ] && [ \"\$(uci get $PKG.stagenet.enabled)\" = 1 ] && sha256sum -c /tmp/$PKG.sum"
eventually "both servers run after the upgrade, and the page still reaches their admin APIs" \
	". /tmp/t.sh; running $PKG mainnet && running $PKG stagenet && [ \"\$(rpc accounts | jsonfilter -e '@.ok')\" = true ] && [ \"\$(NET=mainnet rpc accounts | jsonfilter -e '@.ok')\" = true ]"

x "sha256sum $KEY_FILE >/tmp/$PKG.sum; sha256sum $MAIN_KEY_FILE >/tmp/$PKG.main.sum; . /tmp/t.sh; pid $PKG mainnet >/tmp/$PKG.main.pid"
check "the page makes a new admin key for stagenet: its server stops and starts, its key changes, the page works with it" \
	". /tmp/t.sh; [ \"\$(rpc new_admin_key | jsonfilter -e '@.ok')\" = true ] && ! sha256sum -c /tmp/$PKG.sum >/dev/null 2>&1 && grep -qx '[0-9a-f]\{64\}' $KEY_FILE"
eventually "stagenet's server runs with the new key, and lists the wallets for the page" \
	". /tmp/t.sh; running $PKG stagenet && [ \"\$(rpc accounts | jsonfilter -e '@.ok')\" = true ]"
check "mainnet's server and key are left alone" \
	". /tmp/t.sh; [ \"\$(pid $PKG mainnet)\" = \"\$(cat /tmp/$PKG.main.pid)\" ] && sha256sum -c /tmp/$PKG.main.sum"
check "a key the database doesn't know is refused, and the page says to make a new one" \
	". /tmp/t.sh; cp $KEY_FILE /tmp/key.good; printf '%064d\n' 1 >$KEY_FILE; a=\$(rpc accounts); cp /tmp/key.good $KEY_FILE; [ \"\$(echo \"\$a\" | jsonfilter -e '@.ok')\" = false ] && [ \"\$(echo \"\$a\" | jsonfilter -e '@.code')\" = refused ]"

# --- settings from before networks had sections ------------------------------

# The one server of an older version, on the stagenet node, with no network
# guard: its settings in the main section, its key where it was then.
x "/etc/init.d/$PKG stop; mv $KEY_FILE /etc/$PKG/secrets/MONOKULO_LWS_ADMIN_KEY; rmdir /etc/$PKG/secrets/stagenet"
x "cat >/etc/config/$PKG" <<-EOF
	config $PKG 'main'
		option enabled '1'
		option daemon 'http://127.0.0.1:38081'
		option port '8460'
		option admin_port '8461'
		option listen 'loopback'
		option data_dir '/srv/$PKG-stagenet'
		option log_level 'info'
EOF
check "a start turns older settings into network sections: the old server's in stagenet's, as its node says, the others off" \
	"/etc/init.d/$PKG start; [ \"\$(uci get $PKG.stagenet.enabled)\" = 1 ] && [ \"\$(uci get $PKG.stagenet.port)\" = 8460 ] && [ \"\$(uci get $PKG.stagenet.admin_port)\" = 8461 ] && [ \"\$(uci get $PKG.stagenet.data_dir)\" = /srv/$PKG-stagenet ] && [ \"\$(uci get $PKG.mainnet.enabled)\" = 0 ] && [ \"\$(uci get $PKG.testnet.enabled)\" = 0 ] && ! uci -q get $PKG.main.daemon && ! uci -q get $PKG.main.port"
check "the old admin key is moved to stagenet's folder, root's alone" \
	"[ ! -e /etc/$PKG/secrets/MONOKULO_LWS_ADMIN_KEY ] && [ \"\$(ls -ln $KEY_FILE | awk '{ print \$1, \$3 }')\" = '-rw------- 0' ]"
eventually "stagenet's server runs on the old settings, alone, with its wallets, through the old key" \
	". /tmp/t.sh; running $PKG stagenet && ! running $PKG mainnet && uclient-fetch -q -O - http://127.0.0.1:8460/daemon_status | jsonfilter -e '@.network' | grep -qx stage && [ \"\$(rpc accounts | jsonfilter -e '@.ok')\" = true ]"

# --- removal -----------------------------------------------------------------

check "the package is removed" "apk del $PKG"
eventually "its removal stops the server" ". /tmp/t.sh; ! running $PKG"
check "its removal takes the program, the LuCI page, the backend and the firewall rule" \
	"[ ! -e /usr/bin/$PKG ] && [ ! -e /www/luci-static/resources/view/$PKG.js ] && [ ! -e /usr/share/rpcd/ucode/$PKG ] && ! uci -q get firewall.monokulo_lws && ! ubus -S list $PKG"
check "its removal keeps the databases, the admin keys and the settings, the operator's" \
	"[ -s $DB ] && [ -s $MAIN_DB ] && [ -s $KEY_FILE ] && [ -s $MAIN_KEY_FILE ] && [ -s /etc/config/$PKG ]"

echo "all $passed checks passed"
