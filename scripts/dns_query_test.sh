#!/usr/bin/env bash
#
# dns_query_test.sh — Generate DNS traffic for testing the eBPF DNS cache.
#
# Queries 20 well-known domain names, waiting 2 seconds between each query so
# the activity is easy to follow in the TUI while capturing it (e.g. via screen)
# for documentation.
#
# Usage:
#   ./scripts/dns_query_test.sh            # query @ system resolver
#   ./scripts/dns_query_test.sh 1.1.1.1    # query a specific resolver

set -u

RESOLVER="${1:-}"
DELAY="${DELAY:-1}"

NAMES=(
    ynet.co.il
    youtube.com
    facebook.com
    wikipedia.org
    amazon.com
    reddit.com
    github.com
    cloudflare.com
    microsoft.com
    apple.com
    netflix.com
    twitter.com
    instagram.com
    linkedin.com
    stackoverflow.com
    mozilla.org
    debian.org
    kernel.org
    archlinux.org
    rust-lang.org
)

dig_args=(+timeout=2 +tries=1)
[ -n "$RESOLVER" ] && dig_args+=("@$RESOLVER")

echo "Querying ${#NAMES[@]} names (delay ${DELAY}s)${RESOLVER:+ via $RESOLVER}..."

i=0
for name in "${NAMES[@]}"; do
    i=$((i + 1))
    addr=$(dig "${dig_args[@]}" +short "$name" A | grep -m1 -E '^[0-9]+\.' || true)
    printf '[%2d/%2d] %-20s -> %s\n' "$i" "${#NAMES[@]}" "$name" "${addr:-<no answer>}"
    [ "$i" -lt "${#NAMES[@]}" ] && sleep "$DELAY"
done

echo "Done."
