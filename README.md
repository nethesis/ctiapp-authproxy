# ctiapp-authproxy

Authentication proxy for Acrobits application.
This repository contains a PHP proxy used to authenticate against a CTI cloud and return configuration to clients (SIP credentials, phonebook, quick dials). The main logic is in `app/index.php`.

The application needs the following environment variable on startup:
- `TOKEN`: a secret token used to validate incoming requests
- `VALIDATE_LK_URL`: URL to validate user credentials against a remote server
- `DEBUG`: optional, if set to "true" enables debug logging

Each request must be a POST request containing a JSON object.
The object must have the following fields:
- `username`
- `password`
- `token`: it's a SHA256 hash, it must be the same passed to the application at startup

## Local testing

Below are minimal steps and examples to test the application locally without Docker. These examples assume you have PHP 8+ installed and are running them from the repository root.

1) Set environment variables required by the app (example values):

```bash
export TOKEN="localtesttoken"
export VALIDATE_LK_URL="https://httpbin.org/status/200" # This is a fake endpoint for testing
export DEBUG="true"
```

2) Start a built-in PHP web server to serve the `app` directory:

```bash
php -S 127.0.0.1:8000 -t app/
```

3) Healthcheck (quick):

```bash
curl -i http://127.0.0.1:8000/index.php/healthcheck
```

4) Test the `login` flow (replace with real or mocked endpoints):

```bash
curl -i -X POST http://127.0.0.1:8000/index.php \
  -H "Content-Type: application/json" \
  -d '{"username":"alice@cti.example.com","password":"secret","token":"localtesttoken","app":"login"}'
```

5) Test the `contacts` flow:

```bash
curl -i -X POST http://127.0.0.1:8000/index.php \
  -H "Content-Type: application/json" \
  -d '{"username":"alice@cti.example.com","password":"secret","token":"localtesttoken","app":"contacts"}'
```

6) Test the `quickdial` flow:

```bash
curl -i -X POST http://127.0.0.1:8000/index.php \
  -H "Content-Type: application/json" \
  -d '{"username":"alice@cti.example.com","password":"secret","token":"localtesttoken","app":"quickdial"}'
```
