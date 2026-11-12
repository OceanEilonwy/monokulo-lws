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
# a fresh SDK container signs the package and the repository index.
#
# Usage: scripts/build-openwrt.sh [build|sign|all]   (default all)
#   build  the binary and the unsigned package, in dist/unsigned/. Never
#          reads the signing key: cargo runs every dependency's build
#          script and proc macro, and the SDK runs its own build, so no
#          signing key may be anywhere they could reach it.
#   sign   signs dist/unsigned/ into dist/ and dist/repo/, running nothing
#          but openssl and the SDK image's apk. CI runs it in a job of its
#          own, on a fresh runner that never built anything.
#   all    build, then sign: for local use. A key in $APK_SIGNING_KEY is
#          taken out of the environment before anything is built.
#
# Needs: docker, rustup (stable), openssl (build); docker, openssl (sign).
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
build | sign | all) ;;
*)
	echo "usage: $0 [build|sign|all]" >&2
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

	rm -rf dist/repo dist/*.apk dist/packages.adb dist/monokulo.pem dist/throwaway.pem dist/SHA256SUMS
	mkdir -p dist/repo
	chmod 0777 dist/repo # the SDK runs as its own user

	# A fresh container with no volume but dist/: the key is in its
	# environment and its own /tmp, and goes with it. It runs the SDK
	# image's apk alone (the image pinned by digest), no build. The key
	# reaches it through the environment (-e APK_KEY without a value),
	# never on docker's command line where other local users could see it.
	APK_KEY="$key" docker run --rm -e APK_KEY -e ARCH="$ARCH" \
		-v "$PWD/dist:/dist" "$SDK_IMAGE" sh -euc '
		apk=/builder/staging_dir/host/bin/apk
		keys=$(mktemp -d)
		(umask 077 && printf "%s\n" "$APK_KEY" >"$keys/private-key.pem")
		unset APK_KEY
		openssl ec -in "$keys/private-key.pem" -pubout -out "$keys/monokulo.pem" 2>/dev/null
		cp /dist/unsigned/*.apk /dist/repo/
		cd /dist/repo
		# The SDK builds packages unsigned (only the index is signed). Sign
		# them too, so a downloaded .apk installs directly (apk add, or LuCI
		# Upload Package) on any router that trusts monokulo.pem.
		for f in ./*.apk; do
			"$apk" --allow-untrusted adbsign --sign-key "$keys/private-key.pem" "$f"
			"$apk" --keys-dir "$keys" verify "$f"
		done
		# The index, as the SDK make package/index makes it.
		"$apk" mkndx --root "$keys" --keys-dir "$keys" --allow-untrusted \
			--sign "$keys/private-key.pem" --output packages.adb ./*.apk
		"$apk" --keys-dir "$keys" verify packages.adb
		"$apk" adbdump --format json packages.adb |
			/builder/scripts/make-index-json.py -f apk -a "$ARCH" - >index.json
		rm -rf "$keys"
	'

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
sign) sign ;;
all)
	build
	sign
	;;
esac
