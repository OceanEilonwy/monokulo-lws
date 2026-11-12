#!/bin/sh
# Build the GitHub Pages site: the signed apk repositories the OpenWrt
# workflow made, one per OpenWrt release and CPU architecture, and a page
# saying how to add them to a router, the same layout as monokulo's and
# Kringle's sites:
#   index.html                          the install page (pages/index.html)
#   monokulo.pem                        the public key the repositories are signed with
#   openwrt/<release>/<arch>/           a repository: the .apk, packages.adb, index.json
#   assets/                             the mark (docs/brand/)
#
# Usage: scripts/build-pages.sh <repos> <site>
#   repos: a folder holding a folder per repository, named
#          openwrt-repo-<release>-<arch> (the sign job's artifacts, as
#          actions/download-artifact lays them out), each with the .apk,
#          packages.adb and index.json
#   site:  the folder to build the site in (emptied first)
#
# PAGES_URL is where the site is served (default: the repository's GitHub
# Pages address, from GITHUB_REPOSITORY or the origin remote); REPO_URL the
# repository's page; COMMIT the commit it was built from.
set -eu
cd "$(dirname "$0")/.."

[ $# -eq 2 ] || {
	echo "usage: $0 <repos> <site>" >&2
	exit 2
}
REPOS=$1
SITE=$2
PUBKEY=openwrt/keys/monokulo.pem

slug=${GITHUB_REPOSITORY:-}
if [ -z "$slug" ]; then
	remote=$(git remote get-url origin 2>/dev/null || true)
	slug=$(printf '%s' "$remote" | sed -E 's#^(git@github\.com:|https://github\.com/)##; s#\.git$##')
fi
REPO_URL=${REPO_URL:-https://github.com/$slug}
if [ -z "${PAGES_URL:-}" ]; then
	owner=$(printf '%s' "${slug%%/*}" | tr '[:upper:]' '[:lower:]')
	PAGES_URL="https://$owner.github.io/${slug#*/}"
fi
PAGES_URL=${PAGES_URL%/}
COMMIT=${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo unknown)}

rm -rf "$SITE"
mkdir -p "$SITE/assets" "$SITE/openwrt"

# html <text>: escaped for HTML.
html() {
	printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

rows=
files=
found=0
for dir in "$REPOS"/openwrt-repo-*; do
	[ -d "$dir" ] || continue
	name=${dir##*/openwrt-repo-}
	# <release>-<arch>: the release has no '-', the architecture may.
	release=${name%%-*}
	arch=${name#*-}
	case "$release" in
	'' | *[!0-9.]*)
		echo "error: $dir doesn't name an OpenWrt release" >&2
		exit 1
		;;
	esac
	[ -s "$dir/packages.adb" ] && ls "$dir"/*.apk >/dev/null 2>&1 || {
		echo "error: $dir holds no packages.adb or .apk" >&2
		exit 1
	}
	path=openwrt/$release/$arch
	mkdir -p "$SITE/$path"
	cp "$dir"/*.apk "$dir/packages.adb" "$SITE/$path/"
	[ -f "$dir/index.json" ] && cp "$dir/index.json" "$SITE/$path/"
	url=$PAGES_URL/$path/packages.adb
	rows="$rows        <tr><td>$(html "$release")</td><td><code>$(html "$arch")</code></td><td><code>$(html "$url")</code></td></tr>
"
	for apk in "$SITE/$path"/*.apk; do
		apk=${apk##*/}
		files="$files    <li><a href=\"$(html "$path/$apk")\">$(html "$apk")</a>: OpenWrt $(html "$release"), $(html "$arch")</li>
"
	done
	files="$files    <li><a href=\"$(html "$path/packages.adb")\">$path/packages.adb</a>: its signed index</li>
"
	found=$((found + 1))
done
[ "$found" -gt 0 ] || {
	echo "error: no openwrt-repo-<release>-<arch> folders in $REPOS" >&2
	exit 1
}

cp "$PUBKEY" "$SITE/monokulo.pem"
cp docs/brand/lws-mark.svg docs/brand/lws-mark-on-dark.svg docs/brand/lws-mark-small.svg "$SITE/assets/"

# The page: each placeholder line or token filled in. awk takes the
# multi-line parts from the environment, so no character in them is special.
ROWS=$rows FILES=$files PUBKEY_TEXT=$(cat "$PUBKEY") \
	PAGES_URL_HTML=$(html "$PAGES_URL") REPO_URL_HTML=$(html "$REPO_URL") \
	COMMIT_HTML=$(html "$COMMIT") COMMIT_SHORT=$(printf '%s' "$COMMIT" | cut -c1-12) \
	awk '
	function sub_all(s, token, value,    out, i) {
		out = ""
		while ((i = index(s, token)) > 0) {
			out = out substr(s, 1, i - 1) value
			s = substr(s, i + length(token))
		}
		return out s
	}
	$0 == "@REPOS@" { printf "%s", ENVIRON["ROWS"]; next }
	$0 == "@FILES@" { printf "%s", ENVIRON["FILES"]; next }
	{
		line = $0
		line = sub_all(line, "@PUBKEY@", ENVIRON["PUBKEY_TEXT"])
		line = sub_all(line, "@PAGES_URL@", ENVIRON["PAGES_URL_HTML"])
		line = sub_all(line, "@REPO_URL@", ENVIRON["REPO_URL_HTML"])
		line = sub_all(line, "@COMMIT_SHORT@", ENVIRON["COMMIT_SHORT"])
		line = sub_all(line, "@COMMIT@", ENVIRON["COMMIT_HTML"])
		print line
	}
' pages/index.html >"$SITE/index.html"
if grep -q '@[A-Z_]*@' "$SITE/index.html"; then
	echo "error: a placeholder is left in $SITE/index.html:" >&2
	grep -n '@[A-Z_]*@' "$SITE/index.html" >&2
	exit 1
fi
touch "$SITE/.nojekyll"

find "$SITE" -type f | sort
