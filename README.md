# ctiapp-authproxy

Authentication proxy for Acrobits application.

This application acts as a middleware to authenticate users. It validates
incoming POST requests containing a username, password, and a shared secret
token. If the token matches the configured secret, it attempts to authenticate
the user against a remote service.

## API Usage

**Authentication Endpoint**: POST to root path `/`

Each request must be a POST request containing a JSON object with the following
fields:
- `username`
- `password`
- `token`: it's a SHA256 hash, it must be the same passed to the application at
  startup

**Examples:**
```bash
# HTTP (redirects to HTTPS)
curl -d '{"username": "myuser@demo.example.com", "password": "mypass", "token": "11223344"}' \
  http://localhost:8080

# HTTPS with self-signed certificate
curl -k -d '{"username": "myuser@demo.example.com", "password": "mypass", "token": "11223344"}' \
  https://localhost:8443

# HTTPS production example
curl -d '{"username": "myuser@demo.example.com", "password": "mypass", "token": "11223344"}' \
  https://ctiapp-authproxy.example.com
```

**Health Check**: GET `/index.php/healthcheck`

```bash
curl http://localhost:8080/index.php/healthcheck
curl -k https://localhost:8443/index.php/healthcheck
curl https://ctiapp-authproxy.example.com/index.php/healthcheck
```

## Settings

The application is configured using environment variables. You can create a
`.env` file based on `.env.example`.

| Variable | Description | Default / Example |
|----------|-------------|-------------------|
| `APP_HOSTNAME` | The hostname where the application is reachable. | `app.example.com` |
| `TOKEN` | A shared secret token (SHA256 hash) used to validate requests. | `your_token_here` |
| `DEBUG` | Enable debug logging. | `false` |
| `VALIDATE_LK_URL` | URL used to validate the license key/token. | `https://example.com/validate` |

## Development

This project uses `just` as a command runner to simplify development tasks.

### Prerequisites

- `just` installed (see [just installation guide](https://github.com/casey/just?tab=readme-ov-file#installation))
- `podman`
- `podman-compose`
- `podlet` installed (see [podlet installation guide](https://github.com/containers/podlet?tab=readme-ov-file#install))
- `git`

### Common Commands

- **Start Development Environment**:
  ```bash
  just dev-start
  ```
  Starts the application and Traefik reverse proxy in the background.

- **Stop Development Environment**:
  ```bash
  just dev-stop
  ```
  Stops and removes the running containers.

- **View Logs**:
  ```bash
  just dev-logs
  ```
  Follows the logs of the application and Traefik.

- **Rebuild and Restart**:
  ```bash
  just dev-rebuild
  ```
  Rebuilds the container images without cache and restarts the environment.

- **Run Checks**:
  ```bash
  just check
  ```
  Runs configuration and dependency checks.

## Deployment

Deployment is automated using Ansible and Podman Quadlet, targeting Rocky Linux systems.

### Prerequisites

- `ansible` installed on the deployment machine.
- `ansible-lint` (optional)
- SSH access to the target Rocky Linux server.

### Deployment Steps

1.  **Configure settings** Ensure the `.env` file is properly set up with your desired configuration.
1.  **Run Deployment**:
    ```bash
    just deploy
    ```
    This command executes the `deploy/deploy.yml` playbook which:
    -   **Host Setup**: Prepares the Rocky Linux host (updates packages, installs Podman).
    -   **App Deploy**: Deploys the application using Podman Quadlet files located in the `quadlet/` directory.
1.  **Verify Deployment**:
    After deployment, the service runs as a systemd user service.
    -   Check status: `systemctl --user status app.service`
    -   View logs: `journalctl --user -u app.service -f`

### Deploy a Local Image to a Remote Host (Test Only)

Use this flow when you want to test a local image build on a remote machine.
The deployment step is still done with `just deploy`, after setting the image
tag in `quadlet/app.container`.

1.  **Set test image tag in Quadlet**:
    Edit `quadlet/app.container` and update:
    ```ini
    Image=localhost/ctiapp-authproxy:<your-test-tag>
    ```
1.  **Build the local image with the same tag**:
    ```bash
    podman build -t localhost/ctiapp-authproxy:<your-test-tag> .
    ```
1.  **Export the image to a tar archive**:
    ```bash
    podman save -o /tmp/ctiapp-authproxy-test.tar localhost/ctiapp-authproxy:<your-test-tag>
    ```
1.  **Copy the archive to the remote host**:
    ```bash
    scp /tmp/ctiapp-authproxy-test.tar root@"$APP_HOSTNAME":/tmp/
    ```
1.  **Load image in the `app` user's Podman storage**:
    ```bash
    ssh root@"$APP_HOSTNAME" 'sudo -u app podman load -i /tmp/ctiapp-authproxy-test.tar'
    ```
1.  **Run deployment**:
    ```bash
    just deploy
    ```
1.  **Verify the running image**:
    ```bash
    ssh root@"$APP_HOSTNAME" 'sudo -u app podman images | grep ctiapp-authproxy'
    ssh root@"$APP_HOSTNAME" 'sudo -u app XDG_RUNTIME_DIR=/run/user/$(id -u app) systemctl --user status app.service'
    ```

Notes:
- This procedure is intended for temporary test deployments.
- Keep `quadlet/app.container` aligned with the tag you loaded remotely.
- The loaded image can be replaced by `podman auto-update` if a newer registry image is detected.
- To keep the test image pinned, temporarily disable auto-update for `app.service`.

### Auto-Update Mechanism

The deployment includes an automatic update mechanism for the application
containers using Podman's auto-update feature.

- **Configuration**: The `app.container` is configured with
  `AutoUpdate=registry`, which means Podman will check the container registry
  for newer images.
- **Timer**: A systemd timer (`podman-auto-update.timer`) is enabled for the
  application user. It triggers the update check daily (or as configured).
- **Process**: When the timer fires, Podman checks if a new image is
  available in the registry. If an update is found, Podman pulls the new
  image and restarts the container automatically.
- **Manual Trigger**: You can manually trigger an update check by running as
  the application user:
    ```bash
    podman auto-update
    ```
