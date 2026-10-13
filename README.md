# Nmap Enhanced NSE Scripts

A cybersecurity project focused on extending existing Nmap Scripting Engine (NSE) scripts with additional functionality for robots.txt inspection, HTTP path probing, and sitemap analysis.

The project includes a Python-based local testing server for testing the modified scripts in a controlled environment.

## Overview

Nmap is an open-source network scanning tool that supports the Nmap Scripting Engine (NSE) for automating network discovery and security-related tasks.

This project explores the modification and enhancement of existing NSE scripts to extend their functionality and improve their usefulness during HTTP-related assessments.

The repository contains modified NSE scripts and a local Python testing server.

## Project Objectives

- Study the functionality of existing Nmap NSE scripts.
- Identify opportunities to extend their functionality.
- Implement and evaluate selected enhancements.
- Test script behaviour in a controlled local environment.
- Document the implementation and testing process.

## Scripts

### 1. http-robots.txt.nse

An NSE script associated with inspecting robots.txt information.

This project includes modifications to the original script. Refer to the implementation and accompanying blog for details of the changes.

### 2. http-robots-probe.nse

An NSE script for examining HTTP responses associated with paths identified through robots.txt.

Refer to the source code and blog for details of the implemented enhancements and supported options.

### 3. http-robots-sitemap.nse

An NSE script for inspecting robots.txt directives and sitemap-related information.

Refer to the source code and blog for details of the implemented functionality.

### 4. testserver.py

A Python-based local HTTP server designed to provide a controlled environment for testing the scripts.

## Technologies Used

- **Nmap:** Network scanning and NSE script execution.
- **Lua:** Language used for NSE scripts.
- **Python 3:** Local HTTP testing server.
- **Git:** Version control.
- **GitHub:** Source code hosting and project documentation.

## Repository Structure

```text
Nmap-Enhanced-Script/
├── http-robots.txt.nse
├── http-robots-probe.nse
├── http-robots-sitemap.nse
├── testserver.py
└── README.md
```

## Prerequisites

- Nmap installed on the system.
- Python 3 installed.
- A terminal compatible with the installed tools.

## Installation

Clone the repository:

```bash
git clone https://github.com/VedantNegi1345/Nmap-Enhanced-Script.git
```

Navigate to the project directory:

```bash
cd Nmap-Enhanced-Script
```

## Testing Environment

The repository includes `testserver.py`, which provides a local HTTP server for testing.

Start the server using:

```bash
python testserver.py 8080
```

On Windows, the following command may also be used:

```powershell
py testserver.py 8080
```

Keep the server running in a separate terminal.

The server binds to localhost, providing a local environment for testing the scripts.

## Running the NSE Scripts

NSE script execution depends on the script's supported arguments and requirements.

Use the commands and options documented in the accompanying blog and source code. Test against localhost or another system for which you have explicit authorization.

## Testing and Evaluation

The scripts can be evaluated in a controlled environment using different robots.txt directives, HTTP responses, and sitemap configurations.


## How to Run

### Step 1: Start the Local Test Server

Open a terminal in the project directory and run:

```bash
python testserver.py 8080
```

On Windows, you can also use:

```powershell
py testserver.py 8080
```

The server runs on `127.0.0.1:8080`. Keep this terminal open.

### Step 2: Open a Second Terminal

Navigate to the cloned repository directory:

```powershell
cd Nmap-Enhanced-Script
```

### Step 3: Run the NSE Scripts

Execute the required script against the local test server.

For example, to run the robots.txt inspection script:

```powershell
nmap -p 8080 --script ./http-robots.txt.nse 127.0.0.1
```

To run the HTTP path probing script:

```powershell
nmap -p 8080 --script ./http-robots-probe.nse 127.0.0.1
```

To run the sitemap analysis script:

```powershell
nmap -p 8080 --script ./http-robots-sitemap.nse 127.0.0.1
```

**Note:** These commands are examples. Verify each script's supported arguments and execution requirements before running it. Script names and paths must match the files in the repository.

### Step 4: Review the Output

Check the terminal output to observe the information reported by each script.

The Python server provides a controlled local environment for testing HTTP responses and robots.txt or sitemap-related behaviour.

Relevant test cases may include:

- Valid and missing robots.txt files.
- Different HTTP status codes.
- Duplicate or missing paths.
- Redirect responses.
- Valid and invalid sitemap content.
- Error handling and unexpected responses.

Actual results should be documented after executing the corresponding tests.

## Attribution

This project modifies existing Nmap NSE scripts.

Original authorship, copyright notices, and applicable licensing information should be preserved. Modifications are documented as contributions made within this project.

Refer to the individual source files for their original attribution and licensing information.

## Blog

For a detailed explanation of the original scripts, implemented enhancements, execution steps, and testing process, visit the accompanying project blog:

**Blog:** Add your published blog link here.

## Limitations

- Script behaviour depends on the implementation and server responses.
- HTTP response codes alone do not establish whether a resource is vulnerable.
- Testing results may vary with server configuration and network conditions.

## Disclaimer

This project is intended for educational purposes and authorized security testing.

Use the scripts only against systems you own or have explicit permission to assess.