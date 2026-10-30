#!/usr/bin/env bash
# A disposable privileged container is a test lab for nested user namespaces,
# not a deployment requirement. Every test process runs as uid/gid 65534.
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(docker info --format '{{.Architecture}}')" in
  aarch64|arm64) target_arch=arm64 ;;
  x86_64|amd64) target_arch=amd64 ;;
  *) echo 'Unsupported Docker architecture' >&2; exit 1 ;;
esac
test_dir=$(mktemp -d)
chmod 755 "$test_dir"
trap 'rm -rf "$test_dir"' EXIT
for package in $(go list ./...); do
  package_name=${package//\//_}
  GOOS=linux GOARCH="$target_arch" CGO_ENABLED=0 go test -c -o "$test_dir/$package_name.test" "$package"
done
if [[ -n "${GUARD_LINUX_CONTAINER:-}" ]]; then
  remote_dir="/tmp/guard-tests-$(basename "$test_dir")"
  docker cp "$test_dir/." "$GUARD_LINUX_CONTAINER:$remote_dir"
  trap 'docker exec "$GUARD_LINUX_CONTAINER" rm -rf "$remote_dir"; rm -rf "$test_dir"' EXIT
  docker exec -u 65534:65534 "$GUARD_LINUX_CONTAINER" sh -c 'for test in "$1"/*.test; do "$test" -test.timeout=120s || exit; done' sh "$remote_dir"
else
  docker run --rm --privileged -v "$test_dir:/guard-tests:ro" "${GUARD_LINUX_IMAGE:-alpine:3.23}" sh -c '
    apk add --no-cache bubblewrap || exit
    for binary in /guard-tests/*.test; do
      su nobody -s /bin/sh -c "$binary -test.timeout=120s" || exit
    done'
fi
