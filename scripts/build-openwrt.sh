#!/bin/sh
# Build the OpenWrt package (.apk) for one OpenWrt release and CPU
# architecture (by default 25.12 on the GL.iNet Flint 2: mediatek/filogic,
# aarch64_cortex-a53) and a signed apk repository holding it: monokulo-lws
# with its LuCI page (openwrt/monokulo-lws). The same layout and key as
# monokulo's own packages (its scripts/build-openwrt.sh), so a router that
# trusts monokulo.pem takes this one too.
#
# The binary is cross-compiled here with cargo. Its C parts (SQLite, ring)
# are compiled with the gcc from the official OpenWrt SDK image, so they
# are built exactly as OpenWrt builds C. The same SDK (in Docker) then
# packages the binary with its init script, LuCI page and backend. Last,
# the package and the repository index are signed here on the host, by
# openssl and apk-tools built from its upstream source at a pinned commit
# (the release the SDK's own apk is): no container ever sees the key.
#
# Usage: scripts/build-openwrt.sh [build|apk-tools|sign|all]   (default all)
#   build  the binary and the unsigned package, in dist/unsigned/. Never
#          reads the signing key: cargo runs every dependency's build
#          script and proc macro, and the SDK runs its own build, so no
#          signing key may be anywhere they could reach it.
#   apk-tools  builds apk (apk-tools $APK_TOOLS_VERSION, from the commit
#          pinned below, checked after the fetch) into its cache directory
#          (~/.cache/monokulo-lws/apk-tools/<commit>/), unless it is there
#          already. Never reads the key. CI runs it in a step of its own,
#          before the step that has the key.
#   sign   signs dist/unsigned/ into dist/ and dist/repo/, running nothing
#          with the key but openssl and that apk (building it first, as
#          apk-tools does, if it is missing). CI runs it in a job of its
#          own, on a fresh runner that never built anything.
#   all    apk-tools, build, then sign: for local use. A key in
#          $APK_SIGNING_KEY is taken out of the environment before anything
#          is built, but that keeps it only from careless code, not from a
#          malicious dependency: a build script runs as you, and can read
#          the key file under ~/.config or the environment of the shell
#          that ran this (/proc/<pid>/environ). Sign with the real key only
#          in CI, or as a user the build never runs as.
#
# Needs: docker, rustup (stable), openssl (build); git, a C compiler, meson,
# ninja, pkg-config and the openssl, zlib and zstd headers (apk-tools);
# openssl, and docker to turn the signed index into index.json with the
# SDK's script, the key long gone (sign).
#
# Output:
#   dist/unsigned/ the unsigned package (build)
#   dist/          the package, the repository index and the public key,
#                  for installing by hand (CI uploads these as an artifact)
#   dist/repo/     the signed apk repository: the package and packages.adb
#   dist/throwaway.pem  the public half of the throwaway key, when one
#                  signed them (scripts/test-openwrt.sh trusts it)
#
# Signing key (must match openwrt/keys/monokulo.pem), first found wins:
#   $APK_SIGNING_KEY       the PEM itself (how CI passes the secret)
#   $MONOKULO_SIGNING_KEY  path to the PEM
#   ~/.config/kringle/apk-signing-key.pem   (the same key signs monokulo and kringle)
# $APK_TOOLS, the path of an apk binary, is used instead of building one;
# it must be apk-tools $APK_TOOLS_VERSION too.
# Without one the package is signed with a throwaway key, made here: fine
# for testing, but routers that trust monokulo.pem will refuse it.
set -eu
cd "$(dirname "$0")/.."

# The key, if given in the environment, kept in a shell variable of this
# script alone: not exported, so neither cargo nor docker ever sees it.
env_key="${APK_SIGNING_KEY:-}"
unset APK_SIGNING_KEY

STAGE="${1:-all}"
case "$STAGE" in
build | apk-tools | sign | all) ;;
*)
	echo "usage: $0 [build|apk-tools|sign|all]" >&2
	exit 2
	;;
esac

# One OpenWrt release and CPU architecture per run; openwrt.yml's build matrix
# sets these, and the defaults are its entry for the Flint 2. The SDK image
# is pinned by digest: it compiles the C parts and holds the apk that signs.
SDK_IMAGE="${SDK_IMAGE:-openwrt/sdk:mediatek-filogic-25.12.5@sha256:011c367ac3e63ab3fd345bdb242564fedda033b40e73f883bd550fcf0d27bf9c}"
ARCH="${OPENWRT_ARCH:-aarch64_cortex-a53}"        # the SDK's package architecture
TARGET="${RUST_TARGET:-aarch64-unknown-linux-musl}"
TOOLCHAIN_PREFIX="${TOOLCHAIN_PREFIX:-aarch64-openwrt-linux-musl}"  # the SDK compiler's name
PUBKEY=openwrt/keys/monokulo.pem
PKG=monokulo-lws
# The image's tag (without the digest), naming the caches below.
ref=${SDK_IMAGE%@*}
tag=${ref##*:}

# The apk that signs: apk-tools built from upstream at this commit, the
# tag v3.0.5 (the release `apk --version` reports in the SDK images above;
# a new SDK may mean a new release here, and openwrt.yml's cache key names
# the commit too). The commit, not the tag, is what is trusted: a tag can
# be moved, a commit hash names its contents.
APK_TOOLS_VERSION=3.0.5
APK_TOOLS_COMMIT=b5a31c0d865342ad80be10d68f1bb3d3ad9b0866
APK_TOOLS_REPO=https://gitlab.alpinelinux.org/alpine/apk-tools.git
APK_TOOLS_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/monokulo-lws/apk-tools/$APK_TOOLS_COMMIT"

build() {
	triple=$(printf '%s' "$TARGET" | tr - _)
	TRIPLE=$(printf '%s' "$triple" | tr '[:lower:]' '[:upper:]')
	# The package version is the workspace's; the release number is the
	# commit count, so every build from main upgrades the one before it.
	VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)
	PKG_RELEASE=$(git rev-list --count HEAD 2>/dev/null || echo 1)
	# The commit, shown with the version on the router's LuCI page.
	COMMIT=$(git rev-parse HEAD 2>/dev/null || true)

	# The SDK's cross toolchain, copied out of its image once per image tag.
	# Kept outside target/ (about 900 MB), so CI's Rust cache doesn't carry it.
	toolchain_root="${XDG_CACHE_HOME:-$HOME/.cache}/monokulo-lws/openwrt-sdk/$tag"
	if [ ! -d "$toolchain_root/staging_dir" ]; then
		rm -rf "$toolchain_root"
		mkdir -p "$toolchain_root"
		container=$(docker create "$SDK_IMAGE")
		trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
		docker cp "$container:/builder/staging_dir" "$toolchain_root/staging_dir.partial" >/dev/null
		docker rm -f "$container" >/dev/null
		trap - EXIT
		mv "$toolchain_root/staging_dir.partial" "$toolchain_root/staging_dir"
	fi
	toolchain=$(ls -d "$toolchain_root"/staging_dir/toolchain-"$ARCH"_gcc-*_musl* | head -n 1)
	[ -x "$toolchain/bin/$TOOLCHAIN_PREFIX-gcc" ] || {
		echo "error: no $TOOLCHAIN_PREFIX-gcc in $SDK_IMAGE" >&2
		exit 1
	}

	rustup target add "$TARGET"
	(
		export STAGING_DIR="$toolchain_root/staging_dir"
		export PATH="$toolchain/bin:$PATH"
		export "CC_$triple=$TOOLCHAIN_PREFIX-gcc"
		export "AR_$triple=$TOOLCHAIN_PREFIX-ar"
		export "CARGO_TARGET_${TRIPLE}_LINKER=$TOOLCHAIN_PREFIX-gcc"
		export CARGO_PROFILE_RELEASE_STRIP=symbols
		cargo build --release --locked --target "$TARGET" -p monokulo-lws --bin monokulo-lws
	)
	bin="target/$TARGET/release/$PKG"
	# x86_64's musl target links a static PIE, aarch64's a plain static
	# executable: either runs on OpenWrt, a dynamic one doesn't. (The Vulkan
	# loader is opened at run time, which a static executable can't do, so
	# the GPU prefilter reports no Vulkan and the CPU scans: right for a
	# router.)
	if ! file "$bin" | grep -Eq 'statically linked|static-pie linked'; then
		echo "error: $PKG isn't a static executable, so it won't run on OpenWrt:" >&2
		file "$bin" >&2
		exit 1
	fi
	install -m 0755 "$bin" "openwrt/$PKG/files/$PKG"

	rm -rf dist
	mkdir -p dist/unsigned
	chmod 0777 dist dist/unsigned # the SDK runs as its own user

	# The SDK's working tree lives in a Docker volume so it is set up once,
	# not on every run. SDK_VOLUME= (empty) for a clean, throwaway SDK; CI
	# does that since each job starts fresh anyway.
	SDK_VOLUME="${SDK_VOLUME-monokulo-lws-sdk-$tag}"
	set -- -v "$PWD/openwrt:/feed:ro" -v "$PWD/dist:/dist"
	[ -n "$SDK_VOLUME" ] && set -- "$@" -v "$SDK_VOLUME:/builder"

	docker run --rm -e PKG="$PKG" \
		-e LWS_VERSION="$VERSION" -e LWS_RELEASE="$PKG_RELEASE" -e LWS_COMMIT="$COMMIT" \
		"$@" "$SDK_IMAGE" sh -euc '
		[ -x ./setup.sh ] && [ ! -f rules.mk ] && ./setup.sh
		# A key an earlier version of this script left in a persistent SDK
		# tree: the signing key never comes here now.
		rm -f private-key.pem public-key.pem

		# Only our own feed: the package needs nothing built from the others,
		# so the build never waits on git.openwrt.org.
		grep -q "^src-link monokulo " feeds.conf.default || echo "src-link monokulo /feed" >> feeds.conf.default
		./scripts/feeds update monokulo
		./scripts/feeds install $PKG
		make defconfig
		# Rebuild ours from scratch each time.
		rm -rf bin/packages/*/monokulo build_dir/target-*/$PKG-*
		make "package/$PKG/compile" -j"$(nproc)" \
			LWS_VERSION="$LWS_VERSION" LWS_RELEASE="$LWS_RELEASE" LWS_COMMIT="$LWS_COMMIT"
		cp bin/packages/*/monokulo/$PKG-[0-9]*.apk /dist/unsigned/
	'
	ls dist/unsigned/"$PKG"-[0-9]*.apk >/dev/null || {
		echo "error: the SDK built no $PKG package" >&2
		exit 1
	}
}

# Builds apk from apk-tools at the pinned commit into $APK_TOOLS_DIR, once.
apk_tools() {
	[ -n "${APK_TOOLS:-}" ] && return
	[ -x "$APK_TOOLS_DIR/apk" ] && return
	for tool in git meson ninja pkg-config; do
		command -v "$tool" >/dev/null || {
			echo "error: building apk-tools needs $tool (and a C compiler, and the openssl, zlib and zstd headers)" >&2
			exit 1
		}
	done
	src=$(mktemp -d)
	trap 'rm -rf "$src"' EXIT
	git -C "$src" init -q
	git -C "$src" fetch -q --depth 1 "$APK_TOOLS_REPO" "$APK_TOOLS_COMMIT"
	git -C "$src" -c advice.detachedHead=false checkout -q FETCH_HEAD
	if [ "$(git -C "$src" rev-parse HEAD)" != "$APK_TOOLS_COMMIT" ]; then
		echo "error: $APK_TOOLS_REPO didn't give commit $APK_TOOLS_COMMIT" >&2
		exit 1
	fi
	# A static libapk, so the binary needs no libapk.so installed; no Lua,
	# Python, docs or tests, which signing doesn't use.
	(cd "$src" && VERSION=$APK_TOOLS_VERSION meson setup build \
		--buildtype=release -Ddefault_library=static -Dcrypto_backend=openssl \
		-Dzstd=enabled -Dlua=disabled -Dhelp=disabled -Ddocs=disabled \
		-Dpython=disabled -Dtests=disabled >/dev/null)
	ninja -C "$src/build" src/apk >/dev/null
	mkdir -p "$APK_TOOLS_DIR"
	install -m 0755 "$src/build/src/apk" "$APK_TOOLS_DIR/apk.partial"
	mv "$APK_TOOLS_DIR/apk.partial" "$APK_TOOLS_DIR/apk"
	rm -rf "$src"
	trap - EXIT
}

sign() {
	ls dist/unsigned/"$PKG"-[0-9]*.apk >/dev/null 2>&1 || {
		echo "error: no unsigned package in dist/unsigned/: run $0 build first" >&2
		exit 1
	}
	key="$env_key"
	if [ -z "$key" ]; then
		keyfile="${MONOKULO_SIGNING_KEY:-$HOME/.config/kringle/apk-signing-key.pem}"
		[ -f "$keyfile" ] && key=$(cat "$keyfile")
	fi
	throwaway=
	if [ -n "$key" ]; then
		if ! printf '%s\n' "$key" | openssl ec -pubout 2>/dev/null | cmp -s - "$PUBKEY"; then
			echo "error: the signing key doesn't match $PUBKEY" >&2
			exit 1
		fi
	else
		echo "warning: no signing key, so the package is signed with a throwaway key" >&2
		key=$(openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null)
		throwaway=1
	fi

	apk_tools
	apk="${APK_TOOLS:-$APK_TOOLS_DIR/apk}"
	case "$("$apk" --version 2>/dev/null)" in
	"apk-tools $APK_TOOLS_VERSION,"*) ;;
	*)
		echo "error: $apk isn't apk-tools $APK_TOOLS_VERSION" >&2
		exit 1
		;;
	esac

	rm -rf dist/repo dist/*.apk dist/packages.adb dist/monokulo.pem dist/throwaway.pem dist/SHA256SUMS
	mkdir -p dist/repo

	# Signed here, on the host: no container sees the key. It goes into a
	# directory only this user can read, for apk (which takes it by path),
	# and is removed however this ends. Nothing runs with it but openssl
	# and apk.
	keys=$(mktemp -d)
	trap 'rm -rf "$keys"' EXIT
	trap 'exit 1' INT TERM
	(umask 077 && printf '%s\n' "$key" >"$keys/private-key.pem")
	openssl ec -in "$keys/private-key.pem" -pubout -out "$keys/monokulo.pem" 2>/dev/null
	cp dist/unsigned/*.apk dist/repo/
	(
		cd dist/repo
		# The SDK builds packages unsigned (only the index is signed). Sign
		# them too, so a downloaded .apk installs directly (apk add, or LuCI
		# Upload Package) on any router that trusts monokulo.pem. --root
		# keeps apk off the host's own /etc/apk.
		for f in ./*.apk; do
			"$apk" --root "$keys" --allow-untrusted adbsign --sign-key "$keys/private-key.pem" "$f"
			"$apk" --root "$keys" --keys-dir "$keys" verify "$f"
		done
		# The index, as the SDK make package/index makes it.
		"$apk" mkndx --root "$keys" --keys-dir "$keys" --allow-untrusted \
			--sign "$keys/private-key.pem" --output packages.adb ./*.apk
		"$apk" --root "$keys" --keys-dir "$keys" verify packages.adb
	)
	rm -rf "$keys"
	trap - EXIT INT TERM

	# index.json, made by the SDK's own script from the signed index: the
	# container gets the index's dump on its stdin and nothing more, after
	# the key is gone.
	"$apk" --root "$PWD/dist/repo" adbdump --format json dist/repo/packages.adb |
		docker run --rm -i "$SDK_IMAGE" /builder/scripts/make-index-json.py -f apk -a "$ARCH" - >dist/repo/index.json

	cp dist/repo/*.apk dist/repo/packages.adb dist/
	cp "$PUBKEY" dist/monokulo.pem
	if [ -n "$throwaway" ]; then
		printf '%s\n' "$key" | openssl ec -pubout 2>/dev/null >dist/throwaway.pem
	fi
	(cd dist && sha256sum ./*.apk packages.adb monokulo.pem | sed 's| \./| |' > SHA256SUMS)

	ls -l dist dist/repo
}

case "$STAGE" in
build) build ;;
apk-tools) apk_tools ;;
sign) sign ;;
all)
	apk_tools
	build
	sign
	;;
esac
