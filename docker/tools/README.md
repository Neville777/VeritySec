# Tool sandbox image

Base image for running VeritySec tools in Docker (`tool_execution.container_runtime: docker`).
Security tools are not installed in the Dockerfile yet; the tool list is added when the image is
built, and building downloads packages, so it needs explicit approval first.

## Build

    docker build -t veritysec-tools:latest docker/tools

## Flags used by the sandbox

- read-only root filesystem (`--read-only`)
- `--tmpfs /tmp`
- `--security-opt no-new-privileges`
- `--cap-drop ALL`, then `--cap-add NET_RAW` (configurable via `cap_add`)
- `--memory` (default 1g) and `--pids-limit` (default 256)
- `--network host` by default (`none` and `bridge` also allowed)
- a single work-directory mount at `/work`
- runs as non-root user `tools` (UID 10001)

## Isolated bridge network (optional)

1. Run once: `sudo docker/tools/network-setup.sh` (creates Docker network `veritysec-tools`,
   172.30.0.0/24, and DOCKER-USER DROP rules for the host's own addresses, 10.0.0.0/8,
   172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 and 172.17.0.0/16).
   Undo with `sudo docker/tools/network-setup.sh --remove`.
2. In config.yaml set `tool_execution.network: bridge` (network name is
   `tool_execution.bridge_network`, default `veritysec-tools`).

Limits: in bridge mode targets on the host (127.0.0.1, the host's own IPs) and on private/internal
ranges are unreachable by design; use `network: host` for localhost work. The rules are not
persistent across reboots if your iptables setup does not save them; re-run the script.

## Known limits

- The image bakes nuclei templates at build time (/opt/nuclei-templates); rebuild the image to refresh them.

- Host networking shares the host network stack with the container.
- Tools that need files outside the work directory fail.
- Membership in the `docker` group is root-equivalent on the host.
