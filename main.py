import fitz
import re
import spacy
import os
from collections import defaultdict
import requests

# Load spaCy model
nlp = spacy.load('en_core_web_sm')

# Function to extract text from PDF
def extract_text_from_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    text = ""
    for page in doc:
        text += page.get_text()
    return text

# Enhanced Malware Enrichment via VirusTotal
def enrich_malware(hash):
    vt_api_key = 'YOUR_VIRUSTOTAL_API_KEY'
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"x-apikey": vt_api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return {"error": "Malware details not found."}

# Enhanced Threat Intelligence Extraction
def extract_threat_intelligence_from_pdf(pdf_path):
    text = extract_text_from_pdf(pdf_path)

    # Initialize result dictionary
    result = {
        'IoCs': {
            'IP addresses': [],
            'Domains': [],
            'File Hashes': [],
            'Email Addresses': []
        },
        'TTPs': {
            'Tactics': [],
            'Techniques': []
        },
        'Threat Actor(s)': [],
        'Malware': [],
        'Targeted Entities': []
    }

    # IoCs regex patterns
    patterns = {
        'IP addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'Domains': r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b',
        'File Hashes': r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b',
        'Email Addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    }

    for key, pattern in patterns.items():
        result['IoCs'][key] = list(set(re.findall(pattern, text)))

    # Extract named entities
    doc = nlp(text)
    for ent in doc.ents:
        if ent.label_ == "ORG":
            result['Targeted Entities'].append(ent.text)
        elif ent.label_ == "PERSON":
            result['Threat Actor(s)'].append(ent.text)

    # Map TTPs to MITRE ATT&CK Framework
    mitre_ttp_mapping = {
        'Initial Access': {'keywords': ['phishing', 'exploit'], 'id': 'TA0001'},
        'Execution': {'keywords': ['payload', 'command'], 'id': 'TA0002'},
        'Lateral Movement': {'keywords': ['pivot', 'network traversal'], 'id': 'TA0008'}
    }
    for tactic, data in mitre_ttp_mapping.items():
        for keyword in data['keywords']:
            if keyword in text.lower():
                result['TTPs']['Tactics'].append({data['id']: tactic})

    # Malware enrichment
    for file_hash in result['IoCs']['File Hashes']:
        enriched_data = enrich_malware(file_hash)
        result['Malware'].append(enriched_data)

    return result

# Directory paths
input_folder = r'C3i_HACKATHON_FINAL_ROUND_Q1_DATA'
output_folder = r'Outputs'

# Create output folder if it doesn't exist
os.makedirs(output_folder, exist_ok=True)

# Process all PDF files in the input folder
for pdf_file in os.listdir(input_folder):
    if pdf_file.endswith('.pdf'):
        pdf_path = os.path.join(input_folder, pdf_file)
        extracted_data = extract_threat_intelligence_from_pdf(pdf_path)

        # Save the output to a text file
        output_file_path = os.path.join(output_folder, f"{os.path.splitext(pdf_file)[0]}.txt")
        with open(output_file_path, 'w', encoding='utf-8') as output_file:
            for key, value in extracted_data.items():
                output_file.write(f"{key}:\n")
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        output_file.write(f"  {sub_key}: {sub_value}\n")
                else:
                    output_file.write(f"  {value}\n")

print(f"Processing complete. Extracted data saved to {output_folder}")