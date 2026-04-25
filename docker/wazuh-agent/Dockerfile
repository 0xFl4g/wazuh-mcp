# Minimal Wazuh 4.9 agent image — Wazuh doesn't publish an official
# agent image (only manager/indexer/dashboard), so we build one from the
# .deb package for the integration fixture. Just enough to enroll
# against the test manager via authd and stay connected so M4b
# active-response/restart write tools have a peer to deliver to.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
        curl \
        gnupg \
        lsb-release \
    && rm -rf /var/lib/apt/lists/*

RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list

# WAZUH_MANAGER triggers auto-enrolment on install; the package's
# postinst hook drops the manager hostname into ossec.conf and registers
# the agent with the manager's authd on first start.
ARG WAZUH_AGENT_VERSION=4.9.0-1
RUN apt-get update \
    && WAZUH_MANAGER="wazuh-manager" \
       WAZUH_AGENT_NAME="web-01" \
       apt-get install -y wazuh-agent=${WAZUH_AGENT_VERSION} \
    && apt-mark hold wazuh-agent \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
