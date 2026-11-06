import { mkdirSync, lstatSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
export function prepareBundleRoot(root) {
  root = resolve(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  const stat = lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) || (process.getuid && stat.uid !== process.getuid())) throw Error('Connector bundle directory must be owned by you, not a symlink, and private (mode 0700)');
  return root;
}
export function writeConnectorBundle(root, name, token) {
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(name) || typeof token !== 'string' || !token || /\s/.test(token)) throw Error('Invalid connector bundle input');
  root = prepareBundleRoot(root);
  const directory = mkdtempSync(join(root, name + '-'));
  const unit = `cloudflared-personalvpn-${name}`;
  const service = `# Managed by PersonalVPNWorker\n[Unit]\nDescription=PersonalVPNWorker Cloudflare Tunnel (${name})\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nDynamicUser=yes\nLoadCredential=tunnel-token:/etc/cloudflared-personalvpn/${name}/token\nExecStart=/usr/bin/cloudflared tunnel --no-autoupdate run --token-file %d/tunnel-token\nRestart=on-failure\nRestartSec=5s\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\n\n[Install]\nWantedBy=multi-user.target\n`;
  const install = `#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo 'Run with sudo on the target Linux device.' >&2; exit 1; }
command -v apt-get >/dev/null || { echo 'This installer requires Debian/Ubuntu/Raspberry Pi OS.' >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd is required.' >&2; exit 1; }
[ "$(systemctl --version | head -n 1 | awk '{print $2}')" -ge 247 ] || { echo 'systemd 247+ is required for protected credentials.' >&2; exit 1; }
bundle_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
unit_file='/etc/systemd/system/${unit}.service'
if [ -e "$unit_file" ] && ! head -n 1 "$unit_file" | grep -qx '# Managed by PersonalVPNWorker'; then
  echo 'Refusing to replace an unmanaged service.' >&2; exit 1
fi
apt-get update
apt-get install -y ca-certificates curl
install -d -m 0755 /usr/share/keyrings
key_file="$(mktemp)"
trap 'rm -f "$key_file"' EXIT
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o "$key_file"
install -m 0644 "$key_file" /usr/share/keyrings/cloudflare-main.gpg
printf '%s\\n' 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' > /etc/apt/sources.list.d/cloudflared.list
apt-get update
apt-get install -y cloudflared
[ -x /usr/bin/cloudflared ] || { echo 'Expected /usr/bin/cloudflared from the package.' >&2; exit 1; }
connector_version="$(/usr/bin/cloudflared --version | awk '{print $3}')"
dpkg --compare-versions "$connector_version" ge 2025.4.0 || { echo 'cloudflared 2025.4.0+ is required.' >&2; exit 1; }
install -d -m 0700 '/etc/cloudflared-personalvpn/${name}'
install -m 0600 "$bundle_dir/tunnel-token" '/etc/cloudflared-personalvpn/${name}/token'
install -m 0644 "$bundle_dir/${unit}.service" "$unit_file"
systemctl daemon-reload
systemctl enable '${unit}.service'
systemctl restart '${unit}.service'
systemctl is-active '${unit}.service'
echo 'Connector installed. Verify tunnel health and external allowed/denied access before completing rollout.'
`;
  try {
    writeFileSync(join(directory, 'tunnel-token'), token, { mode: 0o600, flag: 'wx' });
    writeFileSync(join(directory, `${unit}.service`), service, { mode: 0o600, flag: 'wx' });
    writeFileSync(join(directory, 'install.sh'), install, { mode: 0o700, flag: 'wx' });
    return directory;
  } catch (error) { rmSync(directory, { recursive: true, force: true }); throw error; }
}
