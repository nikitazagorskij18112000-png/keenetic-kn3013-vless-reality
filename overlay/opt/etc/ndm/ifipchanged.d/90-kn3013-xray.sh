#!/bin/ash
[ "$id" = Bridge0 ] || exit 0
/bin/ash /usr/libexec/kn3013-xray-service auto </dev/null >/dev/null 2>&1 &
exit 0
