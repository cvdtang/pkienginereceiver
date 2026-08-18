FROM debian:stable-slim

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils

COPY slapd.conf /etc/ldap/slapd.conf
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 389

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
