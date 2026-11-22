#!/bin/ash
# NDM prefixes the interpreter path with /opt; /opt/bin points to /bin.
# Keep this event handler nonblocking so it does not delay other NDM hooks.
[ "$id" = Bridge0 ] || exit 0
/bin/ash /usr/libexec/kn3013-xray-service auto </dev/null >/dev/null 2>&1 &
exit 0
