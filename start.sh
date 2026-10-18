#!/bin/sh
# Free mode: no local scanner, just start the website
if [ "$LOCAL_SCANNER" = "off" ]; then exec node server.js; fi

mkdir -p /var/run/clamav && chown clamav:clamav /var/run/clamav
(freshclam -d &) 2>/dev/null     # keep the virus database up to date
clamd                            # starts the scanner in the background
until clamdscan --ping 1:1 >/dev/null 2>&1; do sleep 2; done
exec node server.js
