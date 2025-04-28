# Email Phishing Detector

A sophisticated Python-based tool for detecting potential phishing attempts in emails using various analysis techniques and machine learning.

## Features

- Sender Analysis
  - Domain age verification
  - Trusted domain checking
  - Typosquatting detection
  - Domain reputation checking (via VirusTotal API)

- Content Analysis
  - Suspicious keyword detection
  - Urgency indicator analysis
  - Sentiment analysis using SpaCy
  - Pattern matching for common phishing attempts

- URL Analysis
  - URL validation and parsing
  - URL shortener detection
  - Domain reputation checking
  - Suspicious pattern detection

- Email Header Analysis
  - SPF record verification
  - DKIM signature checking
  - DMARC policy validation
  - Suspicious header pattern detection

- Comprehensive Reporting
  - Risk score calculation
  - Detailed analysis results
  - JSON report generation
  - Colored console output

## Requirements

- Python 3.7+
- Required Python packages (install via requirements.txt)
- SpaCy English language model
- VirusTotal API key (optional, for enhanced domain checking)

## Installation

1. Clone this repository:
```bash
git clone <repository-url>
cd phishing_detector
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Download SpaCy English language model:
```bash
python -m spacy download en_core_web_sm
```

4. (Optional) Set up VirusTotal API:
   - Get an API key from [VirusTotal](https://www.virustotal.com/gui/join-us)
   - Create a `.env` file in the project directory
   - Add your API key: `VIRUSTOTAL_API_KEY=your_api_key_here`

## Usage

1. Run the script:
```bash
python phishing_detector.py
```

2. Choose analysis mode:
   - Option 1: Analyze email from file
   - Option 2: Analyze email from direct input
   - Option 3: Exit

### Analyzing Email from File

1. Save the email content in a text file (including headers)
2. Choose Option 1
3. Enter the path to your email file
4. Review the analysis results

### Analyzing Email from Input

1. Choose Option 2
2. Paste or type the email content (including headers)
3. Press Ctrl+D (Unix) or Ctrl+Z (Windows) when finished
4. Review the analysis results

## Output

The tool provides:
- Real-time console output with color-coded risk levels
- Detailed analysis of each component (sender, content, URLs, headers)
- JSON report saved in `analysis_results` directory
- Log file with detailed execution information

## Risk Score Interpretation

- 0-39%: Low Risk (Green)
- 40-69%: Medium Risk (Yellow)
- 70-100%: High Risk (Red)

## Example Email Format

```
From: sender@example.com
To: recipient@example.com
Subject: Important Account Notice
Date: Thu, 1 Jan 2024 12:00:00 +0000

Email body content here...
```

## Security Considerations

- This tool is for educational and defensive purposes only
- Always handle suspicious emails with caution
- Do not click on suspicious links or download attachments
- Keep the tool and its dependencies updated

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
