# ctiapp-authproxy

Authentication proxy for Acrobits application.

The application needs a `TOKEN` environment application on startup.

Each request must be a POST request containing a JSON object.
The object must have the following fields:
- `username`
- `password`
- `token`: it's a SHA256 hash, it must be the same passed to the application at startup

Example with curl:
```
curl -d '{"username": "myuser@demo.example.com", "password": "mypass", "token": "11223344"}' https://ctiapp-authproxy.example.com
```
