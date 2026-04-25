#!/usr/bin/env bash
# Boot the wazuh-agent in the foreground.
# `wazuh-control start` launches the agent daemons (ossec-agentd,
# ossec-execd, ossec-syscheckd, ...) which then enrol against the manager
# via authd and connect on UDP/TCP 1514. We tail ossec.log to keep PID 1
# alive — if a daemon dies the tail keeps running but the manager will
# stop seeing the agent as active, which surfaces in CI as an obvious
# "agent never went active" signal.
set -e

# wait until the manager is reachable on port 1515 (authd) before
# starting daemons; otherwise the first enrolment attempt hard-fails and
# the agent backs off for a long time.
echo "[agent] waiting for wazuh-manager:1515 (authd) ..."
for _ in $(seq 1 60); do
    if (echo > /dev/tcp/wazuh-manager/1515) >/dev/null 2>&1; then
        echo "[agent] authd reachable, enroling."
        break
    fi
    sleep 2
done

/var/ossec/bin/wazuh-control start

# Foreground keep-alive. If wazuh-control fails, the next docker logs
# inspection shows the failed start. If it succeeds, ossec.log streams.
exec tail -F /var/ossec/logs/ossec.log
