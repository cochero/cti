# Windows dev environment — Docker Engine in WSL2 (no Docker Desktop)

This project's dev stack runs in **Docker Engine inside a WSL2 Ubuntu distro**,
not Docker Desktop. On at least one team machine, Windows-side AF_UNIX socket
support was broken (every Unix-socket bind returned EACCES; socket files were
undeletable with error 1920), which crashes Docker Desktop's host-side
services on startup. Docker-in-WSL sidesteps the entire surface: all sockets
live on the Linux side, and WSL2 forwards published container ports to
`localhost` on Windows automatically.

## One-time setup
1. BIOS: Intel VT-x / virtualization **enabled** (check:
   `(Get-CimInstance Win32_ComputerSystem).HypervisorPresent` → True).
2. `wsl --install` + reboot, then `wsl --install -d Ubuntu --no-launch`.
3. Inside Ubuntu (as root): `apt-get install docker.io docker-compose-v2`.

## Daily use
```powershell
# keep the WSL VM alive for the session (it auto-terminates when idle,
# killing dockerd and every container with it)
Start-Process wsl.exe -ArgumentList "-d","Ubuntu","--exec","sleep","infinity" -WindowStyle Hidden

# bring up the stack
wsl -d Ubuntu -u root sh -c "cd /mnt/c/Projects/CTI/truvo && docker compose -f deploy/compose/docker-compose.yml up -d"
```
Services then answer on Windows `localhost`: Postgres `5432`, Redpanda
`9092` (console `8080`, schema registry `18081`), MinIO `9000`/`9001`.

Compose services carry `restart: unless-stopped`, so if the VM does cycle,
containers return as soon as dockerd does.

## Gotchas learned the hard way
- `wsl --cd <path>` can race drive automount on a cold VM start; prefer
  `sh -c "cd /mnt/c/... && ..."`.
- "connection refused" from Windows usually means the VM idled out and took
  the stack down — check the keeper process before debugging networking.
- Two stale AV registrations (Security Center) can linger after uninstalls;
  `fltmc filters` (elevated) shows what's actually loaded.
