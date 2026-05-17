#!/usr/bin/env bash
# tls: per-process TLS handshake tracing (root + Linux).
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib.sh"; . "$DIR/lib_live.sh"
section "tls"
# Require a real captured handshake event, not just the startup banner.
live_test "tls" gen_tls 'SSL_write|SSL_read|ClientHello|example|github' -- tls
print_summary
