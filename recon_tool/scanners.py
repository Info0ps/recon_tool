# recon_tool/recon_tool/scanners.py

import asyncio
import subprocess
import shutil
import json
import os
import logging
from typing import List, Optional
from collections import defaultdict
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import csv
import re
from .ml_model import MLModel
from .utils import is_valid_url, randomize_case, is_ip_address
import aiohttp
import aiofiles
from tqdm.asyncio import tqdm
import time
import base64
import random


class ReconRunner:
    """
    Main class to run reconnaissance tasks.
    """

    def __init__(self, target: str, config, ml_model: MLModel, verbose: bool = False):
        self.target = target
        self.config = config
        self.results = defaultdict(list)
        self.stealthy_mode = False
        self.session = None  # Initialized in async context
        self.headers = self.build_headers()
        self.output_dir = self.config.get('DEFAULT', 'OutputDir')
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.ml_model = ml_model
        self.waf_detected = False
        self.scan_start_time = time.time()
        self.max_scan_time = self.config.getint('DEFAULT', 'MaxScanTime', fallback=3600)
        self.verbose = verbose

        # Resource management variables
        self.high_response_time_threshold = float(self.config.get('DEFAULT', 'HighResponseTimeThreshold', fallback='1.5'))
        self.low_response_time_threshold = float(self.config.get('DEFAULT', 'LowResponseTimeThreshold', fallback='0.5'))
        self.min_threads = self.parse_int(self.config.get('DEFAULT', 'MinThreads', fallback='5'), default=5, config_name='MinThreads')
        self.max_threads = self.parse_int(self.config.get('DEFAULT', 'MaxThreads', fallback='20'), default=20, config_name='MaxThreads')  # Reduced from 100 to 20
        self.current_threads = self.max_threads
        self.semaphore = asyncio.Semaphore(self.current_threads)

        # Initialize cache
        self.cache = defaultdict(str)  # Cache URL to content mapping

        # Read MinRate from config
        self.min_rate = self.parse_int(self.config.get('DEFAULT', 'MinRate', fallback='1000'), default=1000, config_name='MinRate')  # Reduced from 2000 to 1000

    def parse_int(self, value_str: str, default: int, config_name: str) -> int:
        """
        Parses an integer from a string, removing any inline comments or non-digit characters.

        Args:
            value_str (str): The string containing the integer value.
            default (int): The default value to return if parsing fails.
            config_name (str): The name of the configuration parameter (for logging).

        Returns:
            int: The parsed integer value.
        """
        try:
            # Split the string on whitespace and take the first part
            sanitized_str = value_str.split()[0]
            return int(sanitized_str)
        except (ValueError, IndexError):
            logging.error(f"Invalid value for {config_name}: '{value_str}'. Using default: {default}")
            return default

    def build_headers(self) -> dict:
        """
        Build HTTP headers for requests.

        Returns:
            dict: Dictionary of HTTP headers.
        """
        user_agent = self.config.get('DEFAULT', 'UserAgent')
        if self.config.getboolean('DEFAULT', 'RandomizeUserAgent'):
            user_agent = randomize_case(user_agent)
        return {
            'User-Agent': user_agent,
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.google.com/',
        }

    async def detect_waf(self):
        """
        Detect if a WAF is present using wafw00f.
        """
        print(f"[*] Detecting WAF for {self.target}...")
        try:
            if shutil.which("wafw00f") is None:
                logging.error("wafw00f is not installed.")
                print("Error: wafw00f is not installed. Please install it to proceed.")
                return False

            wafw00f_command = [
                "wafw00f", f"http://{self.target}"
            ]
            logging.debug(f"Running wafw00f command: {' '.join(wafw00f_command)}")

            # TODO: subprocess.Popen(["/bin/zsh", "-i", "-c", " ".join(command_as_a_list)])
            process = await asyncio.create_subprocess_exec(
                *wafw00f_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            wafw00f_stdout = stdout.decode().strip()
            logging.debug(f"wafw00f output: {wafw00f_stdout}")

            if not wafw00f_stdout:
                logging.error("wafw00f did not return any output.")
                print("Error: wafw00f did not return any output. Check network connectivity and target availability.")
                return False

            # Check for WAF detection in the standard output
            if "is behind" in wafw00f_stdout:
                waf_name = wafw00f_stdout.split("is behind")[1].strip()
                logging.info(f"WAF detected: {waf_name}")
                print(f"[*] WAF detected ({waf_name})! Switching to stealthy mode...")
                self.stealthy_mode = True
                self.waf_detected = True
                return True
            else:
                logging.info("No WAF detected. Running in aggressive mode.")
                self.stealthy_mode = False
                self.waf_detected = False
                return False
        except subprocess.CalledProcessError as e:
            logging.error(f"wafw00f failed: {e}")
            print("Error: wafw00f failed to run. Please ensure it is installed and accessible.")
            return False
        except Exception as e:
            logging.exception("An unexpected error occurred during WAF detection.")
            print("An unexpected error occurred during WAF detection. Check logs for details.")
            return False

    async def adaptive_get(self, url: str) -> Optional[str]:
        """
        Perform an HTTP GET request with adaptive error handling, stealthy mode, and caching.

        Args:
            url (str): The URL to fetch.

        Returns:
            Optional[str]: The response text if successful, None otherwise.
        """
        if url in self.cache:
            logging.debug(f"Cache hit for URL: {url}")
            return self.cache[url]

        retries = 0
        max_retries = self.parse_int(self.config.get('DEFAULT', 'MaxRetries', fallback='3'), default=3, config_name='MaxRetries')
        backoff_factor = 2

        while retries < max_retries:
            try:
                # Check if max scan time exceeded
                if time.time() - self.scan_start_time > self.max_scan_time:
                    logging.warning("Maximum scan time exceeded.")
                    return None

                start_time = time.time()
                if self.stealthy_mode:
                    await asyncio.sleep(random.uniform(1.0, 3.0))
                async with self.semaphore, self.session.get(url, headers=self.headers, timeout=self.parse_int(self.config.get('DEFAULT', 'Timeout', fallback='20'), default=20, config_name='Timeout')) as response:
                    end_time = time.time()
                    response_time = end_time - start_time
                    content = await response.text()
                    content_length = len(content)
                    # Collect additional features (e.g., number of headers)
                    num_headers = len(response.headers)
                    # Predict stealthy mode based on response time, status code, content length, and WAF detection
                    self.stealthy_mode = self.ml_model.predict_stealthy_mode(response_time, response.status, content_length, self.waf_detected)
                    # Adjust concurrency based on response time
                    self.adjust_concurrency(response_time)
                    if response.status in [429, 503]:
                        wait_time = backoff_factor ** retries
                        logging.warning(f"Received status code {response.status}. Retrying after {wait_time} seconds...")
                        await asyncio.sleep(wait_time)
                        retries += 1
                        continue
                    # Log scan data for ML training
                    await self.log_scan_data_async({
                        'response_time': response_time,
                        'status_code': response.status,
                        'content_length': content_length,
                        'waf_detected': int(self.waf_detected),
                        'stealthy_mode': int(self.stealthy_mode),
                        'num_headers': num_headers
                    })
                    # Cache the content
                    self.cache[url] = content
                    return content
            except aiohttp.ClientConnectorError as e:
                logging.error(f"Connection error to {url}: {e}")
                retries += 1
            except asyncio.TimeoutError:
                logging.error(f"Request to {url} timed out.")
                retries += 1
            except Exception as e:
                logging.exception(f"An unexpected error occurred: {e}")
                retries += 1
            await asyncio.sleep(backoff_factor ** retries)
        return None

    def adjust_concurrency(self, response_time: float):
        """
        Adjust the concurrency level based on response time.

        Args:
            response_time (float): Time taken for the response.
        """
        if response_time > self.high_response_time_threshold:
            if self.current_threads > self.min_threads:
                self.current_threads -= 1
                self.semaphore = asyncio.Semaphore(self.current_threads)
                logging.debug(f"Decreased threads to {self.current_threads} due to high response time.")
        elif response_time < self.low_response_time_threshold:
            if self.current_threads < self.max_threads:
                self.current_threads += 1
                self.semaphore = asyncio.Semaphore(self.current_threads)
                logging.debug(f"Increased threads to {self.current_threads} due to low response time.")

    async def log_scan_data_async(self, data: dict):
        """
        Asynchronously log scan data for machine learning model training.

        Args:
            data (dict): Data to log.
        """
        log_file = os.path.join(self.output_dir, 'scan_data.csv')
        file_exists = os.path.isfile(log_file)
        async with aiofiles.open(log_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data.keys())
            if not file_exists:
                await writer.writeheader()
            await writer.writerow(data)

    async def run_ffuf(self, ffuf_command: List[str]) -> Optional[str]:
        """
        Run FFUF command asynchronously and return its output.

        Args:
            ffuf_command (List[str]): The FFUF command to execute.

        Returns:
            Optional[str]: The output from FFUF if successful, None otherwise.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *ffuf_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logging.error(f"FFUF failed with return code {process.returncode}. Error: {stderr.decode().strip()}")
                return None
            return stdout.decode().strip()
        except Exception as e:
            logging.exception(f"An error occurred while running FFUF: {e}")
            return None

    async def run_nmap(self, nmap_command: List[str]) -> Optional[str]:
        """
        Run Nmap command asynchronously and return its output.

        Args:
            nmap_command (List[str]): The Nmap command to execute.

        Returns:
            Optional[str]: The output from Nmap if successful, None otherwise.
        """
        try:
            process = await asyncio.create_subprocess_exec(
                *nmap_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logging.error(f"Nmap failed with return code {process.returncode}. Error: {stderr.decode().strip()}")
                return None
            return stdout.decode().strip()
        except Exception as e:
            logging.exception(f"An error occurred while running Nmap: {e}")
            return None

    async def subdomain_fuzzing(self):
        """
        Perform subdomain fuzzing using ffuf with fallback wordlists.
        """
        print(f"[*] Starting subdomain fuzzing for {self.target}...")
        primary_wordlist = os.path.join(self.config.get('DEFAULT', 'WordlistsDir'), self.config.get('DEFAULT', 'SubdomainWordlist'))
        fallback_wordlist = os.path.join(self.config.get('DEFAULT', 'WordlistsDir'), self.config.get('DEFAULT', 'SubdomainFallbackWordlist'))
        threads = str(self.current_threads)
        wordlists = [primary_wordlist, fallback_wordlist]

        for wordlist in wordlists:
            if not os.path.isfile(wordlist):
                logging.error(f"Wordlist not found: {wordlist}")
                print(f"Error: Wordlist not found at {wordlist}. Please ensure the wordlist exists.")
                continue

            try:
                ffuf_command = [
                    "ffuf",
                    "-ic",                      # Ignore wordlist comments
#                    "-s",                       # Silent mode
                    "-u", f"http://{self.target}",
                    "-w", wordlist,
                    "-t", threads,
                    "-mc", "200,301",
                    "-of", "json",
                    "-o", "output/subdomain_fuzzing.json"                   # Output to stdout for easy parsing
                ]
                if not is_ip_address(self.target):
                    ffuf_command.extend(["-H", f"Host: FUZZ.{self.target}"])

                output = await self.run_ffuf(ffuf_command)
                if output is None:
                    continue

                try:
                    ffuf_results = json.loads(output)
                    for result in ffuf_results.get('results', []):
                        subdomain = result['input']['FUZZ']
                        full_domain = f"{subdomain}.{self.target}" if not is_ip_address(self.target) else self.target
                        if full_domain not in self.results['subdomains']:
                            print(f"[*] Subdomain found: {full_domain}")
                            self.results['subdomains'].append(full_domain)
                except json.JSONDecodeError:
                    # Handle plain text output
                    for line in output.splitlines():
                        line = line.strip()
                        if line:
                            full_domain = f"{line}.{self.target}" if not is_ip_address(self.target) else self.target
                            if full_domain not in self.results['subdomains']:
                                print(f"[*] Subdomain found: {full_domain}")
                                self.results['subdomains'].append(full_domain)

            except Exception as e:
                logging.exception("Subdomain fuzzing failed.")
                print("An unexpected error occurred during subdomain fuzzing. Check logs for details.")

    async def directory_fuzzing(self, url: str, depth: int = 2, current_depth: int = 0):
        """
        Perform directory fuzzing using ffuf with fallback wordlists.

        Args:
            url (str): The base URL to start fuzzing from.
            depth (int): Maximum recursion depth.
            current_depth (int): Current recursion depth.
        """
        if current_depth >= depth:
            return

        primary_wordlist = os.path.join(self.config.get('DEFAULT', 'WordlistsDir'), self.config.get('DEFAULT', 'DirectoryWordlist'))
        fallback_wordlist = os.path.join(self.config.get('DEFAULT', 'WordlistsDir'), self.config.get('DEFAULT', 'DirectoryFallbackWordlist'))
        threads = str(self.current_threads)

        wordlists = [primary_wordlist, fallback_wordlist]
        for wordlist in wordlists:
            if not os.path.isfile(wordlist):
                logging.error(f"Wordlist not found: {wordlist}")
                print(f"Error: Wordlist not found at {wordlist}. Please ensure the wordlist exists.")
                continue

            try:
                ffuf_command = [
                    "ffuf",
                    "-ic",                      # Ignore wordlist comments
#                    "-s",                       # Silent mode
                    "-u", f"{url.rstrip('/')}/FUZZ",
                    "-w", wordlist,
                    "-t", threads,
                    "-mc", "200,301,302,403",
                    "-of", "json",
                    "-o", "output/directory_fuzzing.json"                   # Output to stdout for easy parsing
                ]

                output = await self.run_ffuf(ffuf_command)
                if output is None:
                    continue

                try:
                    ffuf_results = json.loads(output)
                    directories = []
                    for result in ffuf_results.get('results', []):
                        directory = result['input']['FUZZ']
                        full_url = f"{url.rstrip('/')}/{directory}"
                        if full_url not in self.results['directories']:
                            print(f"[*] Directory found: {full_url}")
                            directories.append(directory)
                            self.results['directories'].append(full_url)

                    # Recursively fuzz discovered directories
                    tasks = [self.directory_fuzzing(f"{url.rstrip('/')}/{directory}", depth, current_depth + 1) for directory in directories]
                    await asyncio.gather(*tasks)

                except json.JSONDecodeError:
                    # Handle plain text output
                    for line in output.splitlines():
                        line = line.strip()
                        if line:
                            full_url = f"{url.rstrip('/')}/{line}"
                            if full_url not in self.results['directories']:
                                print(f"[*] Directory found: {full_url}")
                                self.results['directories'].append(full_url)

            except Exception as e:
                logging.exception(f"Directory fuzzing failed at depth {current_depth}.")
                print("An unexpected error occurred during directory fuzzing. Check logs for details.")

    async def api_fuzzing(self):
        """
        Perform API fuzzing to discover hidden API endpoints.
        """
        print(f"[*] Starting API fuzzing for {self.target}...")
        wordlist = os.path.join(self.config.get('DEFAULT', 'WordlistsDir'), self.config.get('DEFAULT', 'ApiWordlist'))
        threads = str(self.current_threads)

        if not os.path.isfile(wordlist):
            logging.error(f"API wordlist not found: {wordlist}")
            print(f"Error: API wordlist not found at {wordlist}. Please ensure the wordlist exists.")
            return

        try:
            ffuf_command = [
                "ffuf",
                "-ic",                      # Ignore wordlist comments
#                "-s",                       # Silent mode
                "-u", f"http://{self.target}/FUZZ",
                "-w", wordlist,
                "-t", threads,
                "-mc", "200,201,202,204,301,302,307,401,403",
                "-of", "json",
                "-o", "output/api_fuzzing.json"                   # Output to stdout for easy parsing
            ]

            output = await self.run_ffuf(ffuf_command)
            if output is None:
                return

            try:
                ffuf_results = json.loads(output)
                for result in ffuf_results.get('results', []):
                    endpoint = result['input']['FUZZ']
                    full_url = f"http://{self.target}/{endpoint}"
                    if full_url not in self.results['api_endpoints']:
                        print(f"[*] API endpoint found: {full_url}")
                        self.results['api_endpoints'].append(full_url)
            except json.JSONDecodeError:
                # Handle plain text output
                for line in output.splitlines():
                    line = line.strip()
                    if line:
                        full_url = f"http://{self.target}/{line}"
                        if full_url not in self.results['api_endpoints']:
                            print(f"[*] API endpoint found: {full_url}")
                            self.results['api_endpoints'].append(full_url)

        except Exception as e:
            logging.exception("API fuzzing failed.")
            print("An unexpected error occurred during API fuzzing. Check logs for details.")

    async def port_scan_nmap(self):
        """
        Perform port scanning using Nmap asynchronously with updated parameters.
        """
        print(f"[*] Starting Nmap port scan for {self.target}...")
        output_file = os.path.join(self.output_dir, 'nmap_scan.txt')

        try:
            nmap_command = [
                "nmap",
                "-Pn",                  # Treat all hosts as online, skip host discovery
                "-p-",                  # Scan all ports
                "--min-rate", str(self.min_rate),   # Set minimum packet rate from config
                "-sC",                  # Equivalent to --script=default
                "-sV",                  # Version detection
                "-oN", output_file,     # Output in normal format to specified file
                self.target             # Target host
            ]

            output = await self.run_nmap(nmap_command)
            if output is None:
                print("Nmap scan failed. Check logs for details.")
                return

            logging.info(f"Nmap scan results:\n{output}")
            self.results['nmap_scan'] = output
            print(f"[*] Nmap scan completed. Results saved to {output_file}")
        except Exception as e:
            logging.exception("Nmap scanning failed.")
            print("An unexpected error occurred during Nmap scanning. Check logs for details.")

    async def sensitive_info_check(self, url: str):
        """
        Check for sensitive information in the given URL.

        Args:
            url (str): URL to check for sensitive information.
        """
        print(f"[*] Checking for sensitive information in {url}...")
        content = await self.adaptive_get(url)
        if content:
            # Extended sensitive information keyword list
            sensitive_info_keywords = [
                "password", "username", "credentials", "token", "secret", "key",
                "apikey", "auth", "private", "admin", "root", "access_key",
                "secret_key", "password_hash", "db_password", "ftp_password"
            ]

            soup = BeautifulSoup(content, 'html.parser')
            text_content = soup.get_text().lower()

            # Check for sensitive keywords in the page text
            found_keywords = [keyword for keyword in sensitive_info_keywords if keyword in text_content]

            # If found, log the result
            if found_keywords:
                logging.warning(f"Sensitive information detected at {url} with keywords: {found_keywords}")
                self.results['sensitive_info'].append({'url': url, 'keywords': found_keywords})
                print(f"[*] Sensitive information found in {url}: {found_keywords}")
            else:
                logging.info(f"No sensitive information detected in {url}.")
        else:
            logging.error(f"Failed to retrieve {url} for sensitive info check.")

    async def extract_linked_resources(self, url: str):
        """
        Extract linked .js and .css files from the page source.

        Args:
            url (str): URL to extract resources from.
        """
        content = await self.adaptive_get(url)
        if content:
            soup = BeautifulSoup(content, 'html.parser')
            resources = set()

            # Find all script and link tags
            for script in soup.find_all('script', src=True):
                resource_url = urljoin(url, script['src'])
                resources.add(resource_url)

            for link in soup.find_all('link', href=True):
                if 'stylesheet' in link.get('rel', []):
                    resource_url = urljoin(url, link['href'])
                    resources.add(resource_url)

            # Store the resources
            self.results['linked_resources'] = list(resources)

            # Analyze the resources
            await self.analyze_resources(resources)

    async def analyze_resources(self, resources: set):
        """
        Analyze linked resources for sensitive information.

        Args:
            resources (set): Set of resource URLs to analyze.
        """
        tasks = [self.scan_resource_content(resource_url) for resource_url in resources]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def scan_resource_content(self, resource_url: str):
        """
        Scan the content of a resource for potential sensitive information.

        Args:
            resource_url (str): URL of the resource to scan.
        """
        content = await self.adaptive_get(resource_url)
        if content:
            sensitive_patterns = [
                r'api_key\s*=\s*["\']\w+["\']',
                r'api_secret\s*=\s*["\']\w+["\']',
                r'password\s*=\s*["\'].*["\']',
                r'aws_access_key_id\s*=\s*["\']\w+["\']',
                r'aws_secret_access_key\s*=\s*["\']\w+["\']',
                # Add more patterns as needed
            ]

            findings = []
            for pattern in sensitive_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.extend(matches)

            if findings:
                logging.warning(f"Sensitive information found in {resource_url}: {findings}")
                self.results['resource_issues'].append({
                    'url': resource_url,
                    'findings': findings,
                })

    async def jwt_analysis(self, url: str):
        """
        Analyze JWT tokens in the content of a given URL.

        Args:
            url (str): URL to analyze for JWT tokens.
        """
        content = await self.adaptive_get(url)
        if content:
            jwt_tokens = re.findall(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', content)
            for token in jwt_tokens:
                try:
                    header_b64, payload_b64, signature = token.split('.')
                    header_padding = '=' * (-len(header_b64) % 4)
                    header_json = base64.urlsafe_b64decode(header_b64 + header_padding).decode('utf-8')
                    header = json.loads(header_json)
                    alg = header.get('alg', 'unknown')
                    if alg.lower() == 'none':
                        logging.warning(f"JWT token with 'none' algorithm found at {url}")
                        self.results['jwt_vulnerabilities'].append({'url': url, 'issue': 'Insecure JWT algorithm (none)'})
                except Exception as e:
                    logging.error(f"Error decoding JWT token at {url}: {e}")

    async def idor_testing(self, url: str):
        """
        Test for Insecure Direct Object References by manipulating numeric parameters.

        Args:
            url (str): URL to test for IDOR vulnerabilities.
        """
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        for key, values in params.items():
            for value in values:
                if value.isdigit():
                    original_value = value
                    altered_value = str(int(value) + 1)
                    params[key] = [altered_value]
                    new_query = urlencode(params, doseq=True)
                    new_url = parsed_url._replace(query=new_query).geturl()
                    original_content = await self.adaptive_get(url)
                    new_content = await self.adaptive_get(new_url)
                    if new_content and original_content and new_content != original_content:
                        logging.warning(f"Potential IDOR vulnerability at {new_url}")
                        self.results['idor_vulnerabilities'].append({
                            'url': new_url,
                            'parameter': key,
                            'original_value': original_value,
                            'altered_value': altered_value
                        })

    async def whatweb_scan(self, url: str):
        """
        Perform web technology detection using WhatWeb.

        Args:
            url (str): URL to scan with WhatWeb.
        """
        if not self.config.getboolean('DEFAULT', 'WhatWebEnabled'):
            return

        try:
            if shutil.which("whatweb") is None:
                logging.error("WhatWeb is not installed.")
                print("Error: WhatWeb is not installed. Please install it to proceed.")
                return

            output_file = os.path.join(self.output_dir, 'whatweb_results.json')
            whatweb_command = [
                "whatweb", "--log-json", output_file, url
            ]

            process = await asyncio.create_subprocess_exec(
                *whatweb_command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.communicate()

            if process.returncode != 0:
                logging.error(f"WhatWeb failed with return code {process.returncode}.")
                return

            if not os.path.exists(output_file):
                logging.error("WhatWeb did not produce any output.")
                return

            async with aiofiles.open(output_file, 'r') as f:
                whatweb_results = json.loads(await f.read())
            self.results['whatweb'].append(whatweb_results)
            logging.info(f"WhatWeb scan results for {url}: {whatweb_results}")
            print(f"[*] WhatWeb scan completed for {url}.")

        except subprocess.CalledProcessError as e:
            logging.error(f"WhatWeb failed: {e}")
            print("Error: WhatWeb failed to run. Check logs for details.")
        except Exception as e:
            logging.exception("WhatWeb scanning failed.")
            print("An unexpected error occurred during WhatWeb scanning. Check logs for details.")
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)

    async def generate_reports(self):
        """
        Generate reports summarizing the findings in HTML, JSON, and CSV formats.
        """
        if not self.config.getboolean('DEFAULT', 'GenerateHTMLReport'):
            return

        report_file_html = os.path.join(self.output_dir, 'recon_report.html')
        report_file_json = os.path.join(self.output_dir, 'recon_report.json')
        report_file_csv = os.path.join(self.output_dir, 'recon_report.csv')

        # Generate HTML report using Jinja2
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
        except ImportError:
            logging.error("Jinja2 is not installed. HTML reports will not be generated.")
            print("Error: Jinja2 is not installed. Install it using 'pip install jinja2' to generate HTML reports.")
            return

        env = Environment(
            loader=FileSystemLoader(searchpath="./templates"),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template('report_template.html')
        html_content = template.render(target=self.target, results=self.results)

        async with aiofiles.open(report_file_html, 'w') as f:
            await f.write(html_content)
        print(f"[*] Generated HTML report at {report_file_html}")

        # Generate JSON report
        try:
            async with aiofiles.open(report_file_json, 'w') as f:
                await f.write(json.dumps(self.results, indent=4))
            print(f"[*] Generated JSON report at {report_file_json}")
        except Exception as e:
            logging.error(f"Failed to generate JSON report: {e}")
            print("Error: Failed to generate JSON report. Check logs for details.")

        # Generate CSV report (basic)
        try:
            async with aiofiles.open(report_file_csv, 'w', newline='') as f:
                fieldnames = ['Type', 'Data']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                await writer.writeheader()
                for key, values in self.results.items():
                    for value in values:
                        await writer.writerow({'Type': key, 'Data': str(value)})
            print(f"[*] Generated CSV report at {report_file_csv}")
        except Exception as e:
            logging.error(f"Failed to generate CSV report: {e}")
            print("Error: Failed to generate CSV report. Check logs for details.")

    async def run(self):
        """
        Run all reconnaissance tasks concurrently.
        """
        self.session = aiohttp.ClientSession()

        async with self.session:
            await self.detect_waf()

            tasks = [
#                self.port_scan_nmap(),
#                self.subdomain_fuzzing(),
                self.directory_fuzzing(f"http://{self.target}", depth=self.config.getint('DEFAULT', 'MaxScanDepth', fallback='2')),
                self.api_fuzzing(),
                self.extract_linked_resources(f"http://{self.target}")
            ]

            # Use tqdm for progress indication
            for coro in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Main Scanning Tasks"):
                await coro

            # Additional tasks that depend on previous results
            sensitive_info_tasks = [self.sensitive_info_check(url) for url in self.results['directories']]
            await asyncio.gather(*sensitive_info_tasks, return_exceptions=True)

            jwt_analysis_tasks = [self.jwt_analysis(url) for url in self.results['directories']]
            await asyncio.gather(*jwt_analysis_tasks, return_exceptions=True)

            idor_testing_tasks = [self.idor_testing(url) for url in self.results['directories']]
            await asyncio.gather(*idor_testing_tasks, return_exceptions=True)

            whatweb_tasks = [self.whatweb_scan(url) for url in self.results['directories']]
            await asyncio.gather(*whatweb_tasks, return_exceptions=True)

            await self.generate_reports()
