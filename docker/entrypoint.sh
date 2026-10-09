#!/bin/sh
# Reads the configuration anchor and renders the nginx config from it, so the
# anchor is the only input and the anchor and upstream cannot drift apart.
# Fails (non-zero exit, container stops) on a missing or malformed anchor.
set -eu

ANCHOR=/etc/verifier/anchor.xml
TEMPLATES=/usr/share/verifier/templates

die() {
    echo "verifier-entrypoint: FATAL: $*" >&2
    exit 1
}

xp() {
    xmllint --nonet --xpath "$1" "$ANCHOR" 2>/dev/null
}

[ -r "$ANCHOR" ] || die "anchor not readable at $ANCHOR"
xmllint --nonet --noout "$ANCHOR" >/dev/null 2>&1 || die "anchor $ANCHOR is not well-formed XML"
[ "$(xp 'local-name(/*)')" = configurationAnchor ] || die "anchor root element is not configurationAnchor"

# Prefer an https source; otherwise upgrade the first http one to https, as
# X-Road confclient does (ConfigurationDownloadUtils).
count=$(xp "count(/*/*[local-name()='source'])")
[ "${count:-0}" -gt 0 ] 2>/dev/null || die "anchor has no <source> elements"
chosen=
first=
i=1
while [ "$i" -le "$count" ]; do
    url=$(xp "normalize-space((/*/*[local-name()='source'])[$i]/*[local-name()='downloadURL'])")
    cert=$(xp "normalize-space((/*/*[local-name()='source'])[$i]/*[local-name()='verificationCert'])")
    if [ -n "$url" ] && [ -n "$cert" ]; then
        [ -n "$first" ] || first=$url
        case "$url" in https://*) chosen=$url; break ;; esac
    fi
    i=$((i + 1))
done
[ -n "$first" ] || die "anchor has no <source> with both downloadURL and verificationCert"
[ -n "$chosen" ] || chosen="https://${first#http://}"

# Strict URL shape: these values go into the nginx config verbatim.
re='^https://([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*)(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)+$'
echo "$chosen" | grep -Eq "$re" || die "unsupported downloadURL in anchor: $chosen"

rest=${chosen#https://}
hostport=${rest%%/*}
UPSTREAM_HOSTPORT=$hostport
UPSTREAM_HOST=${hostport%%:*}
UPSTREAM_ORIGIN="https://$hostport"
DIRECTORY_PATH="/${rest#*/}"

# The resolver comes from the container's resolv.conf (Docker DNS).
RESOLVER=$(awk '$1 == "nameserver" { a = $2; if (a ~ /:/) a = "[" a "]"; printf "%s ", a }' /etc/resolv.conf)
[ -n "$RESOLVER" ] || die "no nameserver in /etc/resolv.conf"

export UPSTREAM_ORIGIN UPSTREAM_HOST UPSTREAM_HOSTPORT DIRECTORY_PATH RESOLVER
vars='${UPSTREAM_ORIGIN} ${UPSTREAM_HOST} ${UPSTREAM_HOSTPORT} ${DIRECTORY_PATH} ${RESOLVER}'
envsubst "$vars" < "$TEMPLATES/default.conf.template" > /etc/nginx/conf.d/default.conf
envsubst "$vars" < "$TEMPLATES/proxy-common.conf.template" > /etc/nginx/verifier/proxy-common.conf

echo "verifier-entrypoint: anchor instance '$(xp "normalize-space(/*/*[local-name()='instanceIdentifier'])")'," \
     "upstream $UPSTREAM_ORIGIN, directory /globalconf$DIRECTORY_PATH -> $UPSTREAM_ORIGIN$DIRECTORY_PATH"

nginx -t -q || die "rendered nginx config is invalid"
exec "$@"
