# recon_tool/setup.py

import os
import logging

def create_directories(base_dir):
    """
    Create necessary directories if they don't exist.
    
    Args:
        base_dir (str): The base directory of the project.
    """
    directories = ['config', 'data', 'logs', 'models', 'templates', 'wordlists', 'output']
    for directory in directories:
        path = os.path.join(base_dir, directory)
        os.makedirs(path, exist_ok=True)
        logging.info(f"Ensured directory exists: {path}")

def create_template_files(base_dir):
    """
    Create template files if they don't exist.
    
    Args:
        base_dir (str): The base directory of the project.
    """
    # Template for scan_data.csv
    data_file = os.path.join(base_dir, 'data', 'scan_data.csv')
    if not os.path.isfile(data_file):
        import pandas as pd
        df = pd.DataFrame(columns=['response_time', 'status_code', 'content_length', 'waf_detected', 'stealthy_mode'])
        df.to_csv(data_file, index=False)
        logging.info(f"Created template for scan_data.csv at: {data_file}")
        print(f"Created a template for scan_data.csv at: {data_file}. Please populate it with relevant data and rerun the setup.")
    
    # Template for report_template.html
    report_template = os.path.join(base_dir, 'templates', 'report_template.html')
    if not os.path.isfile(report_template):
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Reconnaissance Report for {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f4f4f4; }
        .section { margin-bottom: 40px; }
    </style>
</head>
<body>
    <h1>Reconnaissance Report for {{ target }}</h1>

    <div class="section">
        <h2>Subdomains</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Subdomain</th>
            </tr>
            {% for subdomain in results.subdomains %}
            <tr>
                <td>{{ loop.index }}</td>
                <td>{{ subdomain }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>Directories</h2>
        <table>
            <tr>
                <th>#</th>
                <th>Directory URL</th>
            </tr>
            {% for directory in results.directories %}
            <tr>
                <td>{{ loop.index }}</td>
                <td><a href="{{ directory }}">{{ directory }}</a></td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>API Endpoints</h2>
        <table>
            <tr>
                <th>#</th>
                <th>API Endpoint</th>
            </tr>
            {% for api in results.api_endpoints %}
            <tr>
                <td>{{ loop.index }}</td>
                <td><a href="{{ api }}">{{ api }}</a></td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>Nmap Scan Results</h2>
        <pre>{{ results.nmap_scan }}</pre>
    </div>

    <div class="section">
        <h2>Sensitive Information</h2>
        {% if results.sensitive_info %}
        <table>
            <tr>
                <th>#</th>
                <th>URL</th>
                <th>Keywords Found</th>
            </tr>
            {% for info in results.sensitive_info %}
            <tr>
                <td>{{ loop.index }}</td>
                <td><a href="{{ info.url }}">{{ info.url }}</a></td>
                <td>{{ info.keywords | join(', ') }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No sensitive information detected.</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>JWT Vulnerabilities</h2>
        {% if results.jwt_vulnerabilities %}
        <table>
            <tr>
                <th>#</th>
                <th>URL</th>
                <th>Issue</th>
            </tr>
            {% for vuln in results.jwt_vulnerabilities %}
            <tr>
                <td>{{ loop.index }}</td>
                <td><a href="{{ vuln.url }}">{{ vuln.url }}</a></td>
                <td>{{ vuln.issue }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No JWT vulnerabilities detected.</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>IDOR Vulnerabilities</h2>
        {% if results.idor_vulnerabilities %}
        <table>
            <tr>
                <th>#</th>
                <th>URL</th>
                <th>Parameter</th>
                <th>Original Value</th>
                <th>Altered Value</th>
            </tr>
            {% for idor in results.idor_vulnerabilities %}
            <tr>
                <td>{{ loop.index }}</td>
                <td><a href="{{ idor.url }}">{{ idor.url }}</a></td>
                <td>{{ idor.parameter }}</td>
                <td>{{ idor.original_value }}</td>
                <td>{{ idor.altered_value }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No IDOR vulnerabilities detected.</p>
        {% endif %}
    </div>

    <div class="section">
        <h2>Web Technologies Detected (WhatWeb)</h2>
        {% if results.whatweb %}
            {% for webtech in results.whatweb %}
                <pre>{{ webtech }}</pre>
            {% endfor %}
        {% else %}
            <p>No web technologies detected or WhatWeb was disabled.</p>
        {% endif %}
    </div>
</body>
</html>
"""
        with open(report_template, 'w') as f:
            f.write(html_content)
        logging.info(f"Created report_template.html at: {report_template}")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Determine the base directory (recon_tool/)
    base_directory = os.path.dirname(os.path.abspath(__file__))

    # Setup environment
    create_directories(base_directory)
    create_template_files(base_directory)

    print("Setup complete. Please ensure that 'data/scan_data.csv' is populated with relevant data before training the model.")
