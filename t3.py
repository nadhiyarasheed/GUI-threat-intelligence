import requests
import re
import urllib.parse
from prettytable import PrettyTable
import csv
from collections import Counter
from fpdf import FPDF

# Replace with your AbuseIPDB API key
abuse_api_key = "   "

# Replace with your VirusTotal API key
virus_api_key = "   "

# Replace with your AlienVault OTX API key
otx_api_key = "     "

# Function to get AbuseIPDB report for an IP address
def get_abuseipdb_report(indicator):
    url = f'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': indicator,
        'maxAgeInDays': 90,  # You can adjust the time window for the report
        'verbose': True
    }
    headers = {
        'Key': abuse_api_key,
        'Accept': 'application/json'
    }

    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return None

# Function to get VirusTotal report for an indicator
def get_virustotal_report(indicator, indicator_type):
    url = f'https://www.virustotal.com/api/v3/{indicator_type}/{indicator}'
    headers = {
        'x-apikey': virus_api_key,
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return None

# Function to get AlienVault OTX report for an indicator
def get_otx_indicator(indicator, indicator_type):
    url = f'https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general'
    headers = {'X-OTX-API-KEY': otx_api_key}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        return None

# Function to identify indicator type
def identify_indicator_type(indicator):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    url_pattern = r'\bhttps?://[^\s]+\b'
    file_hash_pattern = r'\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b'

    if re.fullmatch(ip_pattern, indicator):
        return 'IP Address'
    elif re.fullmatch(domain_pattern, indicator):
        return 'Domain'
    elif re.fullmatch(url_pattern, indicator):
        return 'URL'
    elif re.fullmatch(file_hash_pattern, indicator):
        return 'File'
    else:
        return ''

# Function to label IP based on percentage
def label_ip(source, percentage):
    if source in ["AbuseIPDB", "VirusTotal", "AlienVault OTX"]:
        if percentage <= 30:
            return "benign"
        elif percentage <= 70:
            return "suspicious"
        else:
            return "malicious"
    else:
        return "Unknown source"

# Function to determine final conclusion based on votes
def vote(results):
    class_counts = Counter(results)
    max_count = max(class_counts.values())
    majority_classes = [label for label, count in class_counts.items() if count == max_count]

    if len(majority_classes) == 1:
        return majority_classes[0]
    else:
        return "Could be malicious, Please verify manually."

# Function to create a PDF report
def create_pdf(table1, table2):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)

    pdf.cell(200, 10, "Threat Intelligence Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Analysis Results", ln=True, align="L")
    pdf.ln(5)

    pdf.set_font("Arial", "", 10)
    
    # Add analysis results table
    for row in table1._rows:
        pdf.cell(50, 10, row[0], border=1)
        pdf.cell(40, 10, row[1], border=1)
        pdf.cell(40, 10, row[2], border=1)
        pdf.cell(40, 10, row[3], border=1)
        pdf.cell(40, 10, row[4], border=1)
        pdf.ln()

    pdf.ln(10)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(200, 10, "Additional Information", ln=True, align="L")
    pdf.ln(5)

    pdf.set_font("Arial", "", 10)
    
    # Add additional info table
    for row in table2._rows:
        pdf.cell(50, 10, row[0], border=1)
        pdf.cell(50, 10, row[1], border=1)
        pdf.cell(50, 10, row[2], border=1)
        pdf.cell(50, 10, row[3], border=1)
        pdf.ln()

    pdf.output("threat_intelligence_report.pdf")
    print("PDF report saved as 'threat_intelligence_report.pdf'.")

def main():
    # Ask user for choice of input
    input_choice = input("Enter '1' for manual input, '2' for CSV file input, or '3' for text file input: ")

    if input_choice == '1':
        print("Enter the indicators, one per line. Press Enter after each indicator. Enter 'done' when finished.")
        indicators = []
        while True:
            indicator = input().strip()
            if indicator.lower() == 'done':
                break
            indicators.append(indicator)
    elif input_choice == '2':
        csv_file = input("Enter the path to the CSV file: ")
        with open(csv_file, "r") as file:
            reader = csv.reader(file)
            indicators = [row[0] for row in reader]
    elif input_choice == '3':
        text_file = input("Enter the path to the text file: ")
        with open(text_file, "r") as file:
            indicators = [line.strip() for line in file]
    else:
        print("Invalid input choice.")
        return

    table1 = PrettyTable(["Indicator", "AbuseIPDB", "VirusTotal", "AlienVault OTX", "Final Conclusion"])
    table2 = PrettyTable(["Indicator", "Location", "ISP", "Usage Type"])

    for indicator in indicators:
        indicator_type = identify_indicator_type(indicator)
        print(f"Processing {indicator_type}: {indicator}")
        print("\n")

        if indicator_type == 'IP Address':
            abuseipdb_report = get_abuseipdb_report(indicator)
            virustotal_report = get_virustotal_report(indicator, "ip_addresses")
            otx_indicator_info = get_otx_indicator(indicator, "IPv4")

            