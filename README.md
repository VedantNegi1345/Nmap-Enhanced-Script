# Nmap Enhanced NSE Scripts

## Overview

This project extends Nmap's scripting capabilities with custom NSE scripts for inspecting robots.txt directives, probing listed paths, and analyzing sitemap information.

The scripts were developed and tested locally using Nmap 7.99.

## Project Structure

```text
Nmap-Enhanced-Scripts/
├── http-robots.txt.nse
├── http-robots-probe.nse
├── http-robots-sitemap.nse
├── testserver.py
└── README.md
```

## Scripts

### 1. http-robots.txt.nse

Inspects robots.txt information and its directives.

### 2. http-robots-probe.nse

Checks paths listed in robots.txt and reports their HTTP responses.

### 3. http-robots-sitemap.nse

Inspects sitemap-related information.

### 4. testserver.py

Runs a local HTTP test server for testing the scripts in a controlled environment.

## Requirements

* Nmap 7.99 or a compatible version
* Python 3
* Windows, or another environment compatible with the required tools

## Testing

Start the local test server:

```bash
py testserver.py 8080
```

Keep the server running in a separate terminal.

Run the relevant NSE scripts against the local test server using the appropriate Nmap command and script arguments.

Ensure the server is listening on the expected port before testing.

## Disclaimer

These scripts are intended for educational purposes and authorized security testing. Test them only against systems you own or have explicit permission to assess.
