#!/bin/sh
# Builds macos/build/cvedex.app: the SwiftUI app with a universal cvedex next to it, signed ad hoc.
set -eu
cd "$(dirname "$0")"
version=${VERSION:-$(git describe --tags --always --dirty)}
app=build/cvedex.app

swift build -c release --arch arm64 --arch x86_64
bin=$(swift build -c release --arch arm64 --arch x86_64 --show-bin-path)
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp "$bin/CvedexMac" "$app/Contents/MacOS/"

for arch in arm64 amd64; do
    (cd .. && CGO_ENABLED=0 GOOS=darwin GOARCH=$arch go build -trimpath -o "macos/build/cvedex-$arch" \
        -ldflags "-s -w -X github.com/Kludex/cvedex/internal/cli.Version=$version" ./cmd/cvedex)
done
lipo -create -output "$app/Contents/MacOS/cvedex" build/cvedex-arm64 build/cvedex-amd64
rm build/cvedex-arm64 build/cvedex-amd64

cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>cvedex</string>
    <key>CFBundleIdentifier</key><string>com.kludex.cvedex</string>
    <key>CFBundleExecutable</key><string>CvedexMac</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${version#v}</string>
    <key>LSMinimumSystemVersion</key><string>15.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

codesign --force --sign - "$app/Contents/MacOS/cvedex"
codesign --force --sign - "$app"
echo "$app"
