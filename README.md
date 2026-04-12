# TLS Test Tools

This project is a library of tools for managing ephemeral TLS secrets in unit tests.

When writing code that needs to either host a server with TLS enabled or make connections to a TLS enabled server, it's
often difficult to write succinct unit tests that exercise these connections. This package aims to fix that! It provides
utilities for auto-generating self-signed CAs and derived server/client pairs. It also provides tools for finding open
ports to host temporary servers on.

## Installation

To install, simply use `pip`:

```sh
pip install tls-test-tools
```

Or use `uv` for faster installation:

```sh
uv add tls-test-tools
```

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on setting up a development environment and contributing to this project.
