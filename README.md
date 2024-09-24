
# Reconnaissance Automation Tool

## Overview

```

       _______   _____  __         /\      /\  .__        _____                           
  _____\   _  \_/ ____\/  |_      / /     / /  |__| _____/ ____\____   ____ ______  ______
 /  ___/  /_\  \   __\\   __\    / /     / /   |  |/    \   __\/  _ \ /  _ \\____ \/  ___/
 \___ \\  \_/   \  |   |  |     / /     / /    |  |   |  \  | (  <_> |  <_> )  |_> >___ \ 
/____  >\_____  /__|   |__|    / /     / /     |__|___|  /__|  \____/ \____/|   __/____  >
     \/       \/               \/      \/              \/                   |__|       \/ 

```

This tool automates various reconnaissance tasks for Capture The Flag (CTF) challenges, HackTheBox, TryHackMe, and similar environments. It integrates multiple scanning tools to discover subdomains, directories, API endpoints, and potential vulnerabilities.

## Features

- **WAF Detection:** Identifies if the target is behind a Web Application Firewall (WAF) using `wafw00f`.
- **Subdomain Fuzzing:** Discovers subdomains using `ffuf` with primary and fallback wordlists.
- **Directory Fuzzing:** Identifies directories and recursively scans them.
- **API Endpoint Discovery:** Uncovers hidden API endpoints.
- **Port Scanning:** Performs comprehensive port scans using `nmap`.
- **Sensitive Information Detection:** Scans for potential sensitive data leaks.
- **JWT Analysis:** Analyzes JSON Web Tokens for vulnerabilities.
- **IDOR Testing:** Tests for Insecure Direct Object References by manipulating parameters.
- **Web Technology Detection:** Utilizes `WhatWeb` to detect underlying technologies.
- **Adaptive Scanning:** Adjusts scanning behavior based on response times and WAF presence using a machine learning model.
- **Comprehensive Reporting:** Generates reports in HTML, JSON, and CSV formats.
- **Logging:** Detailed logs with rotating file handlers for easy debugging.
- **Unit Testing:** Ensures reliability and functionality through automated tests.
- **Continuous Integration (CI):** Automated testing via GitHub Actions to maintain code quality.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Info0ps/recon_tool.git
cd recon_tool
```

### 2. Install Python Dependencies

Given the externally-managed-environment issue on Kali, it's recommended to use a virtual environment.

#### Using a Virtual Environment (Recommended):

**Create a Virtual Environment**

```bash
python3 -m venv venv
```

**Activate the Virtual Environment**

```bash
source venv/bin/activate
```

**Upgrade pip Inside the Virtual Environment**

```bash
pip install --upgrade pipS
```

**Install Dependencies**

```bash
pip install -r requirements.txt
```

#### Alternative: Using `--user` Flag (Not Recommended):

If you prefer not to use a virtual environment, install dependencies system-wide with the `--user` flag:

```bash
python3 -m pip install --user -r requirements.txt
```

**Caution:** This method may lead to package conflicts. Using a virtual environment is safer.

### 3. Install External Tools

Ensure the following tools are installed and accessible in your PATH:

- `nmap`
- `ffuf`
- `wafw00f`
- `whatweb`

#### Installation Examples:

**Nmap:**

```bash
sudo apt-get install nmap
```

**FFUF:**

```bash
sudo apt-get install ffuf
```

If `ffuf` isn't available via `apt`, install it manually:

```bash
sudo apt-get install git
git clone https://github.com/ffuf/ffuf.git
cd ffuf
go build
sudo mv ffuf /usr/local/bin/
```

**wafw00f:**

```bash
sudo apt-get install wafw00f
```

**WhatWeb:**

```bash
sudo apt-get install whatweb
```

### 4. Configure the Tool

Modify the configuration file at `config/config.ini` as needed. Adjust settings like `MaxThreads`, `MinRate`, wordlist paths, etc., based on your requirements and system capabilities.

### 5. Train the Machine Learning Model

If you haven't trained your ML model yet:

#### Prepare Training Data:

Ensure you have a dataset at `data/scan_data.csv` with the following columns:

- `response_time` (float)
- `status_code` (int)
- `content_length` (int)
- `waf_detected` (bool: 0 or 1)
- `stealthy_mode` (bool: 0 or 1) — This is your target variable.

#### Run the Training Script:

```bash
python3 recon_tool/train_model.py
```

This will create `models/stealthy_mode_model.pkl`.

### 6. Populate Wordlists

Ensure that the `wordlists/` directory contains comprehensive wordlists for subdomain, directory, and API endpoint fuzzing. Use well-maintained lists from sources like SecLists.

### 7. Run the Tool

Execute your reconnaissance tool as follows:

```bash
python3 main.py --target 10.129.147.53 --verbose
```

#### Parameters:

- `--target`: (Required) The target domain, IP address, or URL.
- `--config`: (Optional) Path to the configuration file. Defaults to `config/config.ini`.
- `--verbose`: (Optional) Enable verbose logging for more detailed output.

#### Example:

```bash
python3 main.py --target example.com --verbose
```

**Note:** If using a virtual environment, ensure it's activated before running the script.

## 11. Additional Recommendations

### a. Verify Python Package Paths

Since packages installed via `apt` reside in `/usr/lib/python3/dist-packages`, and user-installed packages are in `~/.local/lib/python3.12/site-packages`, ensure that both are included in `sys.path` if necessary. This was handled in the updated `main.py` by appending the system site-packages directory.

### b. Monitor System Resources

After reducing concurrency, monitor your system's CPU, memory, and network usage to ensure that the tool operates within safe limits. Use tools like `htop`, `top`, or `vmstat` for real-time monitoring.

### c. Adjust Configuration as Needed

The provided configuration settings (`MaxThreads`, `MinRate`) are starting points. Depending on your system's performance and the target's responsiveness, you may need to fine-tune these values for optimal performance.

### d. Logging and Debugging

Review the log files generated in the `logs/` directory to troubleshoot any issues or to gain insights into the tool's operations. Ensure that logging levels (`INFO`, `DEBUG`) are set appropriately based on your needs.

### e. Testing on Controlled Environments

Before deploying the tool against critical or sensitive targets, test it in a controlled environment to ensure that all functionalities work as expected without causing unintended disruptions.

