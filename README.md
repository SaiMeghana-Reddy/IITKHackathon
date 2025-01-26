# IITKHackathon
Uncovering Threat Intelligence from  Cybersecurity Reports
# README: PS1 Uncovering Threat Intelligence from Cybersecurity Reports

## Project Overview
This project implements an automated system to extract key threat intelligence data from cybersecurity reports using natural language processing (NLP) techniques and external data sources. The solution focuses on identifying Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), Threat Actors, Malware, and Targeted Entities.

The code was developed for Problem Statement 1 (PS1) of the Cybersecurity Challenge Hackathon.

---

## Features
1. **IoCs Extraction**:
   - Detects IP addresses, domains, file hashes (MD5, SHA1, SHA256), and email addresses using regular expressions.
   - Handles text normalization and deduplication for cleaner results.

2. **TTPs Mapping**:
   - Matches tactics and techniques to the MITRE ATT&CK framework based on predefined keyword mappings.

3. **Threat Actors**:
   - Identifies named entities related to known threat actors using spaCy's Named Entity Recognition (NER).

4. **Malware Enrichment**:
   - Queries VirusTotal's API to enrich file hash details with metadata such as malware family, tags, and other attributes.

5. **Targeted Entities**:
   - Extracts organizations, industries, and other targeted entities from the report text using NER.

---

## Input and Output Format
### Input
The program accepts the path to a PDF report containing natural language descriptions of cyberattacks.

### Example Input
```python
pdf_path = r'C3i_HACKATHON_FINAL_ROUND_Q1_DATA\Ahnlab_Lazarus-using-public-certificate-vulnerability(02-27-2023).pdf'
```

### Output
The function returns a dictionary containing extracted threat intelligence data. Example:
```python
{
    'IoCs': {
        'IP addresses': [...],
        'Domains': [...],
        'File Hashes': [...],
        'Email Addresses': []
    },
    'TTPs': {
        'Tactics': [{'TA0001': 'Initial Access'}, {'TA0002': 'Execution'}],
        'Techniques': ['T1071', 'T1083']
    },
    'Threat Actor(s)': ['Lazarus'],
    'Malware': [
        {'error': 'NotFoundError: File not found in VirusTotal database'}
    ],
    'Targeted Entities': ['ASEC', 'KISA', 'AhnLab']
}
```

---

## Installation
1. **Clone the Repository**:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. **Set Up Python Environment**:
   - Python 3.8 or higher is recommended.
   - Install dependencies:
     ```bash
     pip install -r requirements.txt
     ```

   **Dependencies:**
   - PyMuPDF (`pip install pymupdf`)
   - spaCy (`pip install spacy`)
   - requests (`pip install requests`)

3. **Download spaCy Model**:
   ```bash
   python -m spacy download en_core_web_sm
   ```

4. **Set VirusTotal API Key**:
   - Replace `YOUR_VIRUSTOTAL_API_KEY` in the code with your valid API key.

---

## How to Run
1. Place the PDF report in the specified directory.
2. Update the `pdf_path` variable in the script with the path to your report.
3. Execute the script:
   ```bash
   python <script_name>.py
   ```

4. View the output in the console or save it as needed.

---

## Known Limitations
1. **Malware Enrichment**:
   - VirusTotal queries returned `NotFoundError` for all file hashes, possibly due to API key restrictions or missing entries in the database.

2. **Noise in Extracted Data**:
   - Some irrelevant entries (e.g., filenames in the `Domains` section, generic terms in `Threat Actor(s)`) were included. These can be refined with better filtering and validation.

3. **Missing Email Addresses**:
   - The dataset did not include email addresses, or regex patterns may require adjustment.

4. **Limited TTP Coverage**:
   - TTP mapping was limited to predefined keywords. Expanding the keyword list can improve accuracy.

---

## Future Enhancements
1. **Improved Data Filtering**:
   - Implement stricter validation for domains, threat actors, and targeted entities to reduce noise.

2. **Enhanced Malware Details**:
   - Address VirusTotal integration issues and include additional metadata like `tags`, `TLSH`, etc.

3. **Custom NER Models**:
   - Train spaCy or other NLP models with cybersecurity-specific datasets to improve detection accuracy.

4. **Scalable API Integration**:
   - Use rate-limited API handling or batch queries for VirusTotal enrichment.

---

## Acknowledgments
- **Hackathon Challenge Document**: Provided by the organizers.
- **Libraries**: spaCy, PyMuPDF, VirusTotal API, Python Standard Library.

---

## Contact
For queries or support, please contact:
- **Name**: SaiMeghana
- **Email**: saimeghanareddy1075@gmail.com
- **GitHub**:https://github.com/SaiMeghana-Reddy

---

Thank you for reviewing this submission!

