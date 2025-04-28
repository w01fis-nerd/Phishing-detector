#!/usr/bin/env python3

import re
import whois
import requests
import dns.resolver
import validators
import json
import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from tld import get_tld
import spacy
import numpy as np
from colorama import Fore, Style, init
import pyfiglet
import logging
from email import message_from_string
from email.parser import Parser
from pathlib import Path
import os
from dotenv import load_dotenv

# Initialize colorama
init()

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    filename='phishing_detector.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'account', 'banking', 'secure', 'update', 'login',
            'alert', 'unauthorized', 'suspended', 'unusual activity',
            'security', 'password', 'credit card', 'ssn', 'urgently'
        ]
        self.trusted_domains = set([
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
            'aol.com', 'protonmail.com'
        ])
        # Load SpaCy model for text analysis
        try:
            self.nlp = spacy.load('en_core_web_sm')
        except:
            os.system('python -m spacy download en_core_web_sm')
            self.nlp = spacy.load('en_core_web_sm')
        
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

    def display_banner(self):
        banner = pyfiglet.figlet_format("Phishing Detector")
        print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Email Phishing Detection System{Style.RESET_ALL}\n")

    def analyze_email(self, email_content):
        """Main method to analyze an email for phishing indicators"""
        try:
            # Parse email content
            email_msg = message_from_string(email_content)
            
            results = {
                'sender_analysis': self.analyze_sender(email_msg),
                'content_analysis': self.analyze_content(email_msg),
                'url_analysis': self.analyze_urls(email_msg),
                'header_analysis': self.analyze_headers(email_msg),
                'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Calculate overall risk score
            risk_score = self.calculate_risk_score(results)
            results['risk_score'] = risk_score
            
            self.display_results(results)
            self.save_results(results)
            
            return results
            
        except Exception as e:
            logging.error(f"Error analyzing email: {str(e)}")
            print(f"{Fore.RED}Error analyzing email: {str(e)}{Style.RESET_ALL}")
            return None

    def analyze_sender(self, email_msg):
        """Analyze the sender's email address and domain"""
        sender = email_msg.get('From', '')
        results = {
            'sender': sender,
            'suspicious_patterns': [],
            'domain_age': None,
            'domain_reputation': None
        }
        
        try:
            # Extract domain
            domain = sender.split('@')[-1].strip('>')
            
            # Check domain age
            try:
                domain_info = whois.whois(domain)
                if domain_info.creation_date:
                    if isinstance(domain_info.creation_date, list):
                        domain_age = datetime.datetime.now() - domain_info.creation_date[0]
                    else:
                        domain_age = datetime.datetime.now() - domain_info.creation_date
                    results['domain_age'] = domain_age.days
            except:
                results['suspicious_patterns'].append('Unable to verify domain age')

            # Check if domain is trusted
            if domain not in self.trusted_domains:
                results['suspicious_patterns'].append('Sender domain not in trusted list')

            # Check for domain typosquatting
            for trusted_domain in self.trusted_domains:
                if self.is_typosquatting(domain, trusted_domain):
                    results['suspicious_patterns'].append(f'Possible typosquatting of {trusted_domain}')

        except Exception as e:
            logging.error(f"Error in sender analysis: {str(e)}")
            results['suspicious_patterns'].append('Error analyzing sender')

        return results

    def analyze_content(self, email_msg):
        """Analyze email content for suspicious patterns"""
        results = {
            'suspicious_keywords': [],
            'urgency_indicators': [],
            'sentiment_analysis': None
        }
        
        try:
            # Get email body
            body = self.get_email_body(email_msg)
            
            # Check for suspicious keywords
            for keyword in self.suspicious_keywords:
                if keyword.lower() in body.lower():
                    results['suspicious_keywords'].append(keyword)

            # Check for urgency indicators
            urgency_patterns = [
                r'urgent',
                r'immediate action',
                r'account.*suspend',
                r'within \d+ hours?',
                r'expires? soon'
            ]
            
            for pattern in urgency_patterns:
                if re.search(pattern, body.lower()):
                    results['urgency_indicators'].append(pattern)

            # Perform sentiment analysis using SpaCy
            doc = self.nlp(body)
            results['sentiment_analysis'] = self.analyze_sentiment(doc)

        except Exception as e:
            logging.error(f"Error in content analysis: {str(e)}")
            results['error'] = str(e)

        return results

    def analyze_urls(self, email_msg):
        """Analyze URLs found in the email"""
        results = {
            'urls_found': [],
            'suspicious_urls': []
        }
        
        try:
            body = self.get_email_body(email_msg)
            urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', body)
            
            for url in urls:
                url_info = {
                    'url': url,
                    'suspicious_patterns': []
                }
                
                # Validate URL
                if not validators.url(url):
                    url_info['suspicious_patterns'].append('Invalid URL format')
                    continue

                # Parse URL
                parsed_url = urlparse(url)
                domain = parsed_url.netloc

                # Check for URL shorteners
                if self.is_url_shortener(domain):
                    url_info['suspicious_patterns'].append('URL shortener detected')

                # Check domain reputation using VirusTotal if API key is available
                if self.virustotal_api_key:
                    reputation = self.check_virustotal(domain)
                    if reputation:
                        url_info['reputation'] = reputation

                results['urls_found'].append(url_info)
                if url_info['suspicious_patterns']:
                    results['suspicious_urls'].append(url_info)

        except Exception as e:
            logging.error(f"Error in URL analysis: {str(e)}")
            results['error'] = str(e)

        return results

    def analyze_headers(self, email_msg):
        """Analyze email headers for suspicious patterns"""
        results = {
            'suspicious_headers': [],
            'spf_result': None,
            'dkim_result': None,
            'dmarc_result': None
        }
        
        try:
            # Check SPF
            spf_header = email_msg.get('Received-SPF', '')
            if 'fail' in spf_header.lower():
                results['suspicious_headers'].append('SPF verification failed')
            results['spf_result'] = spf_header

            # Check DKIM
            dkim_header = email_msg.get('DKIM-Signature', '')
            if not dkim_header:
                results['suspicious_headers'].append('No DKIM signature')
            results['dkim_result'] = bool(dkim_header)

            # Check DMARC
            dmarc_header = email_msg.get('DMARC-Result', '')
            if 'fail' in dmarc_header.lower():
                results['suspicious_headers'].append('DMARC verification failed')
            results['dmarc_result'] = dmarc_header

        except Exception as e:
            logging.error(f"Error in header analysis: {str(e)}")
            results['error'] = str(e)

        return results

    def get_email_body(self, email_msg):
        """Extract email body from message"""
        if email_msg.is_multipart():
            for part in email_msg.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_payload()
        return email_msg.get_payload()

    def is_typosquatting(self, domain1, domain2):
        """Check if domain1 might be typosquatting domain2"""
        # Simple Levenshtein distance check
        def levenshtein(s1, s2):
            if len(s1) < len(s2):
                return levenshtein(s2, s1)
            if len(s2) == 0:
                return len(s1)
            previous_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row
            return previous_row[-1]

        return levenshtein(domain1, domain2) <= 2

    def is_url_shortener(self, domain):
        """Check if domain is a known URL shortener"""
        shorteners = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd'}
        return domain in shorteners

    def check_virustotal(self, domain):
        """Check domain reputation using VirusTotal API"""
        if not self.virustotal_api_key:
            return None

        try:
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            logging.error(f"Error checking VirusTotal: {str(e)}")
        return None

    def analyze_sentiment(self, doc):
        """Analyze text sentiment using SpaCy"""
        # Simple sentiment analysis based on specific words
        sentiment_score = 0
        urgency_words = {'urgent', 'immediate', 'warning', 'alert', 'attention'}
        threat_words = {'suspend', 'terminate', 'block', 'unauthorized', 'suspicious'}
        
        for token in doc:
            if token.text.lower() in urgency_words:
                sentiment_score -= 1
            if token.text.lower() in threat_words:
                sentiment_score -= 1

        return sentiment_score

    def calculate_risk_score(self, results):
        """Calculate overall risk score based on all analyses"""
        score = 0
        
        # Sender analysis
        if results['sender_analysis']['suspicious_patterns']:
            score += len(results['sender_analysis']['suspicious_patterns']) * 2
        if results['sender_analysis']['domain_age'] and results['sender_analysis']['domain_age'] < 30:
            score += 3

        # Content analysis
        score += len(results['content_analysis']['suspicious_keywords'])
        score += len(results['content_analysis']['urgency_indicators']) * 2

        # URL analysis
        score += len(results['url_analysis']['suspicious_urls']) * 3

        # Header analysis
        score += len(results['header_analysis']['suspicious_headers']) * 2

        # Normalize score to 0-100 range
        normalized_score = min(100, (score / 20) * 100)
        return round(normalized_score, 2)

    def display_results(self, results):
        """Display analysis results in a formatted way"""
        risk_score = results['risk_score']
        
        # Determine risk level color
        if risk_score >= 70:
            risk_color = Fore.RED
        elif risk_score >= 40:
            risk_color = Fore.YELLOW
        else:
            risk_color = Fore.GREEN

        print("\n" + "="*50)
        print(f"{risk_color}Risk Score: {risk_score}%{Style.RESET_ALL}")
        print("="*50)

        # Display sender analysis
        print(f"\n{Fore.CYAN}Sender Analysis:{Style.RESET_ALL}")
        print(f"Sender: {results['sender_analysis']['sender']}")
        if results['sender_analysis']['suspicious_patterns']:
            print(f"Suspicious patterns found: {', '.join(results['sender_analysis']['suspicious_patterns'])}")

        # Display content analysis
        print(f"\n{Fore.CYAN}Content Analysis:{Style.RESET_ALL}")
        if results['content_analysis']['suspicious_keywords']:
            print(f"Suspicious keywords: {', '.join(results['content_analysis']['suspicious_keywords'])}")
        if results['content_analysis']['urgency_indicators']:
            print(f"Urgency indicators: {', '.join(results['content_analysis']['urgency_indicators'])}")

        # Display URL analysis
        print(f"\n{Fore.CYAN}URL Analysis:{Style.RESET_ALL}")
        if results['url_analysis']['suspicious_urls']:
            print("Suspicious URLs found:")
            for url_info in results['url_analysis']['suspicious_urls']:
                print(f"- {url_info['url']}")
                print(f"  Issues: {', '.join(url_info['suspicious_patterns'])}")

        # Display header analysis
        print(f"\n{Fore.CYAN}Header Analysis:{Style.RESET_ALL}")
        if results['header_analysis']['suspicious_headers']:
            print(f"Suspicious headers: {', '.join(results['header_analysis']['suspicious_headers'])}")

    def save_results(self, results):
        """Save analysis results to a JSON file"""
        output_dir = Path('analysis_results')
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = output_dir / f"analysis_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        print(f"\n{Fore.GREEN}Results saved to: {output_file}{Style.RESET_ALL}")

def main():
    detector = PhishingDetector()
    detector.display_banner()
    
    while True:
        print("\nOptions:")
        print("1. Analyze email from file")
        print("2. Analyze email from input")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == '1':
            file_path = input("Enter email file path: ")
            try:
                with open(file_path, 'r') as f:
                    email_content = f.read()
                detector.analyze_email(email_content)
            except Exception as e:
                print(f"{Fore.RED}Error reading file: {str(e)}{Style.RESET_ALL}")
        
        elif choice == '2':
            print("Enter email content (press Ctrl+D or Ctrl+Z when finished):")
            email_lines = []
            try:
                while True:
                    line = input()
                    email_lines.append(line)
            except EOFError:
                email_content = '\n'.join(email_lines)
                detector.analyze_email(email_content)
        
        elif choice == '3':
            print(f"{Fore.YELLOW}Exiting...{Style.RESET_ALL}")
            break
        
        else:
            print(f"{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 