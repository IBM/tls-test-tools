# TLS Test Tools

This project is a collection of tools for managing ephemeral TLS secrets in unit tests.

When writing code that needs to either host a server with TLS enabled or make connections to a TLS enabled server, it's
often difficult to write succinct unit tests that exercise these connections. This package aims to fix that! It provides
utilities for auto-generating self-signed CAs and derived server/client pairs. It also provides tools for finding open
ports to host temporary servers on.
