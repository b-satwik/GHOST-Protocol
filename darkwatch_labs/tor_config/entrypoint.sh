#!/bin/sh
set -e

mkdir -p /var/lib/tor/shadowboard \
         /var/lib/tor/services/hs_shadowboard \
         /var/lib/tor/services/hs_shadowforum \
         /var/lib/tor/services/hs_dreadlab \
         /var/lib/tor/services/hs_pastevault \
         /var/lib/tor/services/hs_leaklocker \
         /var/lib/tor/services/hs_forum

chown -R tor:root /var/lib/tor
chmod 700 /var/lib/tor/shadowboard /var/lib/tor/services/hs_* 2>/dev/null || true

# Background process to ensure generated hostname files are readable (644) while keeping directories strict 700
(
    while true; do
        sleep 2
        for dir in /var/lib/tor/shadowboard /var/lib/tor/services/hs_*; do
            if [ -f "$dir/hostname" ]; then
                chmod 644 "$dir/hostname" 2>/dev/null || true
            fi
        done
    done
) &

exec su-exec tor tor -f /etc/tor/torrc
