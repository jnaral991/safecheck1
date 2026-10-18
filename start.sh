#!/bin/sh
mkdir -p /var/run/clamav && chown clamav:clamav /var/run/clamav
(freshclam -d &) 2>/dev/null     # keep the virus database up to date
clamd                            # starts the scanner in the background
until clamdscan --ping 1:1 >/dev/null 2>&1; do sleep 2; done
exec node server.js
