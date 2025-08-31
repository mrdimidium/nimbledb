#!/usr/bin/env sh
set -eu

# Make sure ZIG_RELEASE here is greater than or equal to .minimum_zig_version
ZIG_RELEASE="0.15.1"
ZIG_CHECKSUMS=$(cat<<EOF
zig-aarch64-freebsd-0.15.1.tar.xz 4d9d25c775828d49ea037b2284310c295d951793da8ebe94827a54fed4cca3ce
zig-aarch64-linux-0.15.1.tar.xz bb4a8d2ad735e7fba764c497ddf4243cb129fece4148da3222a7046d3f1f19fe
zig-aarch64-macos-0.15.1.tar.xz c4bd624d901c1268f2deb9d8eb2d86a2f8b97bafa3f118025344242da2c54d7b
zig-aarch64-netbsd-0.15.1.tar.xz b2a528399777583b85b89c54ccd45488af7709d6dd29a27323ec2a229db40910
zig-aarch64-windows-0.15.1.zip 1f1bf16228b0ffcc882b713dc5e11a6db4219cb30997e13c72e8e723c2104ec6
zig-arm-freebsd-0.15.1.tar.xz 9707f3a5f7e1a3d99c40db9a74de1acc61016a197ad289c2ad964f93cb213a18
zig-arm-linux-0.15.1.tar.xz 3f4bf3b06b67d14e3f38be30798488c1abe3cf5b33de570cd0e87bbf09b978ad
zig-arm-netbsd-0.15.1.tar.xz 93dc70109cbf5d2e022d20dfb56211978c4ea3c0b1e67aaabff947d8d1583aab
zig-riscv64-freebsd-0.15.1.tar.xz ee9f864a6fd8b57c1f4fdbb11daa06578746a6f8253afe3f5ddb5a76f2eddd2d
zig-riscv64-linux-0.15.1.tar.xz 7ca7a3e621436fb31d66a253132fc39574a13d2a1b4d8458af4f2e7c6e4374fe
zig-x86-linux-0.15.1.tar.xz dff166f25fdd06e8341d831a71211b5ba7411463a6b264bdefa8868438690b6a
zig-x86-netbsd-0.15.1.tar.xz a91b26051822ff17f3143f859b87dce5b4a13e90928bd6daa6f07a895d3410f0
zig-x86-windows-0.15.1.zip fb1c07cffbb43615d3158ab8b8f5db5da1d48875eca99e1d7a8a0064ff63fc5b
zig-x86_64-freebsd-0.15.1.tar.xz 9714f8ac3d3dc908b1599837c6167f857c1efaa930f0cfa840699458de7c3cd0
zig-x86_64-linux-0.15.1.tar.xz c61c5da6edeea14ca51ecd5e4520c6f4189ef5250383db33d01848293bfafe05
zig-x86_64-macos-0.15.1.tar.xz 9919392e0287cccc106dfbcbb46c7c1c3fa05d919567bb58d7eb16bca4116184
zig-x86_64-netbsd-0.15.1.tar.xz 6d7ba6eca5b4434351ebdb971b7303c9934514f9bb8481852251dbd5b52b03d6
zig-x86_64-windows-0.15.1.zip 91e69e887ca8c943ce9a515df3af013d95a66a190a3df3f89221277ebad29e34
EOF
)

log () {
    echo "$*"
}

die () {
    echo
    echo "$*"
    echo
    exit 1
}

# Check that required tools is installed
if ! command -v curl > /dev/null; then
    die "Curl should be installed"
fi

# Determine the architecture:
case "$(uname -m)" in
  arm64|aarch64)
    ZIG_ARCH="aarch64"
    ;;
  armv7l|armv6l)
    ZIG_ARCH="arm"
    ;;
  x86_64|amd64)
    ZIG_ARCH="x86_64"
    ;;
  x86|i686|i386)
    ZIG_ARCH="x86"
    ;;
  riscv64)
    ZIG_ARCH="riscv64"
    ;;
  *)
    die "Unknown architecture"
    ;;
esac

# Determine the operating system:
case "$(uname)" in
    Linux)
        ZIG_OS="linux"
        ZIG_EXTENSION=".tar.xz"
        ;;
    Darwin)
        ZIG_OS="macos"
        ZIG_EXTENSION=".tar.xz"
        ;;
    CYGWIN*)
        ZIG_OS="windows"
        ZIG_EXTENSION=".zip"
        ;;
    *)
        die "Unknown OS"
        ;;
esac

log "Downloading Zig $ZIG_RELEASE release build..."

ZIG_ARCHIVE="zig-${ZIG_ARCH}-${ZIG_OS}-${ZIG_RELEASE}${ZIG_EXTENSION}"
ZIG_URL="https://ziglang.org/download/${ZIG_RELEASE}/${ZIG_ARCHIVE}"

# Work out the filename from the URL, as well as the directory without the ".tar.xz" file extension:
ZIG_DIRECTORY=$(basename "$ZIG_ARCHIVE" "$ZIG_EXTENSION")

# Download, making sure we download to the same output document
curl --silent --output "$ZIG_ARCHIVE" "$ZIG_URL"

# Verify the checksum.
ZIG_CHECKSUM_EXPECTED=$(echo "$ZIG_CHECKSUMS" | grep -F "$ZIG_ARCHIVE" | cut -d ' ' -f 2)
ZIG_CHECKSUM_ACTUAL=""
if command -v sha256sum > /dev/null; then
    ZIG_CHECKSUM_ACTUAL=$(sha256sum "$ZIG_ARCHIVE" | cut -d ' ' -f 1)
elif command -v shasum > /dev/null; then
    ZIG_CHECKSUM_ACTUAL=$(shasum -a 256 "$ZIG_ARCHIVE" | cut -d ' ' -f 1)
else
    die "Neither sha256sum nor shasum available."
fi

if [ "$ZIG_CHECKSUM_ACTUAL" != "$ZIG_CHECKSUM_EXPECTED" ]; then
    die "Checksum mismatch. Expected '$ZIG_CHECKSUM_EXPECTED' got '$ZIG_CHECKSUM_ACTUAL'."
fi

# Extract and then remove the downloaded archive:
log "Extracting $ZIG_ARCHIVE..."
case "$ZIG_EXTENSION" in
    ".tar.xz")
        tar -xf "$ZIG_ARCHIVE"
        ;;
    ".zip")
        unzip -q "$ZIG_ARCHIVE"
        ;;
    *)
        die "Unexpected error extracting Zig archive."
        ;;
esac
rm "$ZIG_ARCHIVE"

# Replace these existing directories and files so that we can install or upgrade:
rm -rf zig/doc
rm -rf zig/lib
mv "$ZIG_DIRECTORY/LICENSE" zig/
mv "$ZIG_DIRECTORY/README.md" zig/
mv "$ZIG_DIRECTORY/doc" zig/
mv "$ZIG_DIRECTORY/lib" zig/
mv "$ZIG_DIRECTORY/zig" zig/

# We expect to have now moved all directories and files out of the extracted directory.
# Do not force remove so that we can get an error if the above list of files ever changes:
rmdir "$ZIG_DIRECTORY"

# It's up to the user to add this to their path if they want to:
ZIG_BIN="$(pwd)/zig/zig"
log "Downloading completed ($ZIG_BIN)! Enjoy!"
