#!/usr/bin/env bash
# CANDIX cross-platform release builder.
#
# The default mode builds one target and embeds the already-exported frontend.
# `./build.sh --release` builds and packages all supported desktop/server targets.
#
# Environment variables:
#   CANDIX_ENGINE_TARGET_OS=linux             One target OS in single-target mode.
#   CANDIX_ENGINE_TARGET_ARCH=amd64           One target arch in single-target mode.
#   CANDIX_ENGINE_TARGETS=linux/amd64,...     Comma-separated targets for multi-target mode.
#   CANDIX_ENGINE_BUILD_VERSION=vX.Y.Z        Version embedded in the binary and archive name.
#   CANDIX_ENGINE_OUTPUT=/path/to/candix       Explicit binary path in single-target mode.
#   CANDIX_ENGINE_OUTPUT_DIR=dist             Directory for default binary paths.
#   CANDIX_ENGINE_PACKAGE=1                   Create a zip archive for each target.
#   CANDIX_ENGINE_PACKAGE_DIR=dist            Directory for release archives.
#   CANDIX_ENGINE_COMPRESS=off                UPX mode: off, auto, or required.
#   CANDIX_ENGINE_UPX_ARGS="--best --lzma"    Arguments passed to UPX.
#   CANDIX_ENGINE_SKIP_FRONTEND=1             Reuse server/webui/dist (for CI artifact builds).
#   CANDIX_ENGINE_SKIP_NPM_CI=1               Skip npm ci while rebuilding the frontend.
#   CANDIX_ENGINE_GOSUMDB=sum.golang.org      Go checksum database.
set -euo pipefail

cd "$(cd "$(dirname "$0")" && pwd)"

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok() { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  ./build.sh                         Build for the current OS and architecture
  ./build.sh --target linux/amd64   Build one specific target
  ./build.sh --release               Build and package all supported targets

Options:
  --release              Build the amd64/arm64 targets for Linux, macOS, and Windows, and generate zips
  --target OS/ARCH       Set a single target, e.g. windows/amd64
  --upx                  Force UPX compression of the binary (may affect compatibility on some Linux environments)
  --no-compress          No UPX; use only Go linker trimming and zip compression
  --help                 Show this help

The multi-target list can be overridden via CANDIX_ENGINE_TARGETS, e.g.:
  CANDIX_ENGINE_TARGETS=linux/amd64,windows/amd64 ./build.sh --release
EOF
}

RELEASE_TARGETS_DEFAULT="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
CANDIX_ENGINE_RELEASE="${CANDIX_ENGINE_RELEASE:-0}"
CANDIX_ENGINE_COMPRESS="${CANDIX_ENGINE_COMPRESS:-off}"
CANDIX_ENGINE_PACKAGE="${CANDIX_ENGINE_PACKAGE:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      CANDIX_ENGINE_RELEASE=1
      CANDIX_ENGINE_PACKAGE=1
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target requires an OS/ARCH argument"
      target_arg="$2"
      case "$target_arg" in
        */*)
          CANDIX_ENGINE_TARGET_OS="${target_arg%%/*}"
          CANDIX_ENGINE_TARGET_ARCH="${target_arg##*/}"
          CANDIX_ENGINE_TARGETS="$target_arg"
          ;;
        *) die "target must be OS/ARCH, e.g. linux/amd64" ;;
      esac
      shift 2
      ;;
    --no-compress)
      CANDIX_ENGINE_COMPRESS=0
      shift
      ;;
    --upx)
      CANDIX_ENGINE_COMPRESS=required
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) die "unknown argument: $1 (use --help for usage)" ;;
  esac
done

command -v go >/dev/null 2>&1 || die "Go not detected (the project requires Go 1.26 or newer)"

CANDIX_ENGINE_GOSUMDB="${CANDIX_ENGINE_GOSUMDB:-sum.golang.org}"
if [ -z "${CANDIX_ENGINE_BUILD_VERSION:-}" ]; then
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    CANDIX_ENGINE_BUILD_VERSION="$(git describe --tags --always --dirty)"
  else
    CANDIX_ENGINE_BUILD_VERSION="dev"
  fi
fi
# Release tags are commonly passed with a v prefix; keep the binary version consistent.
CANDIX_ENGINE_BUILD_VERSION="${CANDIX_ENGINE_BUILD_VERSION#v}"
CANDIX_ENGINE_OUTPUT_DIR="${CANDIX_ENGINE_OUTPUT_DIR:-dist}"
CANDIX_ENGINE_PACKAGE_DIR="${CANDIX_ENGINE_PACKAGE_DIR:-$CANDIX_ENGINE_OUTPUT_DIR}"
CANDIX_ENGINE_UPX_ARGS="${CANDIX_ENGINE_UPX_ARGS:---best --lzma}"

if [ "${CANDIX_ENGINE_RELEASE}" = "1" ]; then
  CANDIX_ENGINE_TARGETS="${CANDIX_ENGINE_TARGETS:-$RELEASE_TARGETS_DEFAULT}"
else
  CANDIX_ENGINE_TARGET_OS="${CANDIX_ENGINE_TARGET_OS:-$(GOSUMDB="$CANDIX_ENGINE_GOSUMDB" go env GOOS)}"
  CANDIX_ENGINE_TARGET_ARCH="${CANDIX_ENGINE_TARGET_ARCH:-$(GOSUMDB="$CANDIX_ENGINE_GOSUMDB" go env GOARCH)}"
  CANDIX_ENGINE_TARGETS="${CANDIX_ENGINE_TARGETS:-${CANDIX_ENGINE_TARGET_OS}/${CANDIX_ENGINE_TARGET_ARCH}}"
fi

if [ "${CANDIX_ENGINE_SKIP_FRONTEND:-0}" = "1" ]; then
  [ -d server/webui/dist ] || die "CANDIX_ENGINE_SKIP_FRONTEND=1 but server/webui/dist does not exist"
else
  command -v npm >/dev/null 2>&1 || die "npm not detected (building the frontend static assets requires Node.js/npm)"
  command -v rsync >/dev/null 2>&1 || die "rsync not detected"
  info "Building frontend static assets"
  if [ "${CANDIX_ENGINE_SKIP_NPM_CI:-0}" != "1" ]; then
    (cd web && npm ci)
  fi
  (cd web && npm run build:static)
  info "Syncing frontend assets to server/webui/dist"
  mkdir -p server/webui/dist
  rsync -a --delete web/out/ server/webui/dist/
fi

compress_binary() {
  binary="$1"
  goos="$2"
  case "$CANDIX_ENGINE_COMPRESS" in
    0|off|false|none)
      info "Skipping UPX: $binary"
      return 0
      ;;
    auto|required|true|1) ;;
    *) die "CANDIX_ENGINE_COMPRESS must be off, auto, or required" ;;
  esac

  if ! command -v upx >/dev/null 2>&1; then
    if [ "$CANDIX_ENGINE_COMPRESS" = "required" ]; then
      die "CANDIX_ENGINE_COMPRESS=required but upx was not detected"
    fi
    warn "upx not detected; keeping the linker-compressed result: $binary"
    return 0
  fi

  before=$(wc -c < "$binary" | tr -d ' ')
  upx_args="$CANDIX_ENGINE_UPX_ARGS"
  [ "$goos" = "darwin" ] && upx_args="$upx_args --force-macos"
  # shellcheck disable=SC2086
  if ! upx $upx_args -- "$binary"; then
    if [ "$CANDIX_ENGINE_COMPRESS" = "required" ]; then
      die "UPX compression failed: $binary"
    fi
    warn "UPX does not support this target format; keeping the uncompressed binary: $binary"
    return 0
  fi
  after=$(wc -c < "$binary" | tr -d ' ')
  ok "UPX compression done: $binary (${before} -> ${after} bytes)"
}

package_binary() {
  binary="$1"
  goos="$2"
  goarch="$3"
  package_name="candix-${CANDIX_ENGINE_BUILD_VERSION}-${goos}-${goarch}"
  package_root="${CANDIX_ENGINE_PACKAGE_DIR}/${package_name}"
  archive="${CANDIX_ENGINE_PACKAGE_DIR}/${package_name}.zip"

  command -v zip >/dev/null 2>&1 || die "packaging requires zip"
  rm -rf "$package_root" "$archive"
  mkdir -p "$package_root"
  cp "$binary" "$package_root/"
  # The guardian start script is the official entry point: the page's one-click
  # update relies on it to relaunch the process after it exits; running the candix
  # binary directly means it never comes back up after an update. Ship only the one
  # matching the target OS.
  if [ "$goos" = "windows" ]; then
    cp start.bat "$package_root/"
  else
    cp start.sh "$package_root/"
    chmod +x "$package_root/start.sh"
  fi
  cp -R skills "$package_root/"
  cp config.example.json "$package_root/"
  if [ -f README.md ]; then cp README.md "$package_root/"; fi
  (cd "$CANDIX_ENGINE_PACKAGE_DIR" && zip -q -r -9 "$(basename "$archive")" "$(basename "$package_root")")
  rm -rf "$package_root"
  ok "Release archive: $archive"
}

build_target() {
  target="$1"
  case "$target" in
    */*) ;;
    *) die "invalid target: $target (must be OS/ARCH)" ;;
  esac
  goos="${target%%/*}"
  goarch="${target##*/}"
  case "$goos" in
    linux|darwin|windows) ;;
    *) die "unsupported OS: $goos (supported: linux, darwin, windows)" ;;
  esac

  binary_name="candix"
  [ "$goos" = "windows" ] && binary_name="candix.exe"
  if [ -n "${CANDIX_ENGINE_OUTPUT:-}" ] && [ "$CANDIX_ENGINE_RELEASE" != "1" ]; then
    output="$CANDIX_ENGINE_OUTPUT"
  else
    output="${CANDIX_ENGINE_OUTPUT_DIR}/candix-${goos}-${goarch}/${binary_name}"
  fi
  mkdir -p "$(dirname "$output")"

  info "Compiling ${goos}/${goarch}, version ${CANDIX_ENGINE_BUILD_VERSION}"
  GOSUMDB="$CANDIX_ENGINE_GOSUMDB" \
  CGO_ENABLED=0 \
  GOOS="$goos" \
  GOARCH="$goarch" \
  go build \
    -tags embedui \
    -trimpath \
    -ldflags "-s -w -buildid= -X main.version=${CANDIX_ENGINE_BUILD_VERSION}" \
    -o "$output" \
    ./cmd/candix

  compress_binary "$output" "$goos"
  if command -v file >/dev/null 2>&1; then file "$output"; fi
  if [ "$CANDIX_ENGINE_PACKAGE" = "1" ]; then package_binary "$output" "$goos" "$goarch"; fi
  ok "Build complete: $output"
}

write_checksums() {
  [ "$CANDIX_ENGINE_PACKAGE" = "1" ] || return 0
  checksum_file="$CANDIX_ENGINE_PACKAGE_DIR/SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$CANDIX_ENGINE_PACKAGE_DIR" && for archive in *.zip; do sha256sum "$archive"; done > "$(basename "$checksum_file")")
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$CANDIX_ENGINE_PACKAGE_DIR" && for archive in *.zip; do shasum -a 256 "$archive"; done > "$(basename "$checksum_file")")
  else
    warn "Neither sha256sum nor shasum detected; skipping SHA256SUMS"
    return 0
  fi
  ok "Checksum file: $checksum_file"
}

mkdir -p "$CANDIX_ENGINE_OUTPUT_DIR"
if [ "$CANDIX_ENGINE_PACKAGE" = "1" ]; then mkdir -p "$CANDIX_ENGINE_PACKAGE_DIR"; fi

old_ifs="$IFS"
IFS=','
read -r -a targets <<< "$CANDIX_ENGINE_TARGETS"
IFS="$old_ifs"
[ "${#targets[@]}" -gt 0 ] || die "CANDIX_ENGINE_TARGETS must not be empty"
for target in "${targets[@]}"; do
  target="${target//[[:space:]]/}"
  [ -n "$target" ] || continue
  build_target "$target"
done

if [ "$CANDIX_ENGINE_PACKAGE" = "1" ]; then
  write_checksums
  info "Release packages generated in: $CANDIX_ENGINE_PACKAGE_DIR"
fi
