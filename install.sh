#!/bin/sh
# Installs the latest cvedex release into ~/.local/bin (or $CVEDEX_INSTALL_DIR).
set -eu

repo="Kludex/cvedex"
dest="${CVEDEX_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) echo "cvedex: unsupported OS $(uname -s); download a release from https://github.com/$repo/releases" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) echo "cvedex: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

tag=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
[ -n "$tag" ] || { echo "cvedex: could not find the latest release" >&2; exit 1; }
archive="cvedex-$tag-$arch-$os.tar.gz"
base="https://github.com/$repo/releases/download/$tag"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/$archive" "$base/$archive"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

expected=$(grep " $archive\$" "$tmp/SHA256SUMS" | cut -d ' ' -f 1)
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$tmp/$archive" | cut -d ' ' -f 1)
else
  actual=$(shasum -a 256 "$tmp/$archive" | cut -d ' ' -f 1)
fi
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "cvedex: checksum mismatch for $archive" >&2; exit 1; }
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh attestation verify "$tmp/$archive" --repo "$repo" >/dev/null || { echo "cvedex: $archive was not built by $repo's release workflow" >&2; exit 1; }
else
  echo "Install and log in to gh to also check that GitHub built $archive."
fi

mkdir -p "$dest"
tar -xzf "$tmp/$archive" -C "$tmp"
install -m 0755 "$tmp/cvedex" "$dest/cvedex"
echo "Installed cvedex $tag to $dest/cvedex"
case ":$PATH:" in *":$dest:"*) ;; *) echo "Add $dest to your PATH." ;; esac
