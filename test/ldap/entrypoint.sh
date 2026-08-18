#!/bin/sh
set -e

mkdir -p /var/lib/ldap /var/run/slapd

if [ ! -f /var/lib/ldap/data.mdb ]; then
  slapadd -f /etc/ldap/slapd.conf </dev/null
fi

exec slapd -f /etc/ldap/slapd.conf -d 256
