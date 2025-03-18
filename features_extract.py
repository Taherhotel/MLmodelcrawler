from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup
import socket
import ssl
from datetime import datetime
import whois
from datetime import datetime
import dns.resolver

def extract_url_features(url):
    parsed_url = urlparse(url)
    
    # URL-based features
    length = len(url)
    num_dots = url.count('.')
    num_slashes = url.count('/')
    num_subdomains = parsed_url.netloc.count('.') - 1
    has_ip = bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc))
    has_https = url.startswith('https')
    has_at = '@' in url
    tld = parsed_url.netloc.split('.')[-1] if '.' in parsed_url.netloc else ''
    
    return {
        'length': length,
        'num_dots': num_dots,
        'num_slashes': num_slashes,
        'num_subdomains': num_subdomains,
        'has_ip': int(has_ip),
        'has_https': int(has_https),
        'has_at': int(has_at),
        'tld': tld
    }
def extract_keyword_features(url):
    # List of suspicious keywords
    keywords = [
        'login', 'secure', 'account', 'bank', 'verify', 'password', 'update',
        'confirm', 'click', 'free', 'win', 'prize', 'submit', 'checkout', 'access','otp'
    ]
    
    # Count the number of keywords found in the URL
    keyword_count = sum([1 for keyword in keywords if keyword in url.lower()])
    
    # Binary flags for important keywords
    has_login = int('login' in url.lower())
    has_verify = int('verify' in url.lower())
    has_bank = int('bank' in url.lower())
    
    return {
        'keyword_count': keyword_count,
        'has_login': has_login,
        'has_verify': has_verify,
        'has_bank': has_bank
    }
# List of suspicious TLDs commonly used for phishing
suspicious_tlds = ['.xyz', '.tk', '.cf', '.ml', '.ga']

def extract_domain_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Split domain into subdomains
    subdomains = domain.split('.')
    
    # Feature extraction
    domain_length = len(domain)
    num_subdomains = len(subdomains) - 2  # Remove main domain and TLD
    has_hyphen = int('-' in domain)
    tld = '.' + subdomains[-1] if len(subdomains) > 1 else ''
    suspicious_tld = int(tld in suspicious_tlds)
    
    return {
        'domain_length': domain_length,
        'num_subdomains': num_subdomains,
        'has_hyphen': has_hyphen,
        'suspicious_tld': suspicious_tld
    }

def get_dns_record_count(domain):
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    total_records = 0
    
    try:
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record, raise_on_no_answer=False)
                if answers:
                    total_records += len(answers)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                pass
    
    except Exception as e:
        print(f"DNS Error: {e}")
        total_records = 0
    
    return {'dns_record_count': total_records}
def check_spf_dmarc(domain):
    spf_present = 0
    dmarc_present = 0
    
    try:
        # Check SPF record (TXT record starting with 'v=spf1')
        answers = dns.resolver.resolve(domain, 'TXT', raise_on_no_answer=False)
        for txt in answers:
            if txt.to_text().startswith('"v=spf1'):
                spf_present = 1
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        spf_present = 0
    
    try:
        # Check DMARC record (_dmarc subdomain)
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', raise_on_no_answer=False)
        for txt in answers:
            if txt.to_text().startswith('"v=DMARC1'):
                dmarc_present = 1
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        dmarc_present = 0
    
    return {'spf_present': spf_present, 'dmarc_present': dmarc_present}
import requests
from bs4 import BeautifulSoup
import re

def extract_content_features(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Count number of forms
        num_forms = len(soup.find_all('form'))
        
        # Count hidden iframes
        hidden_iframes = len(soup.find_all('iframe', style=re.compile(r'display:\s*none')))
        
        # Suspicious JavaScript functions
        script_content = ' '.join([script.text for script in soup.find_all('script')])
        eval_count = script_content.count('eval(')
        escape_count = script_content.count('escape(')
        settimeout_count = script_content.count('setTimeout(')
        
        # Count number of external links
        external_links = sum(1 for a in soup.find_all('a', href=True) if url not in a['href'])

        return {
            'num_forms': num_forms,
            'hidden_iframes': hidden_iframes,
            'eval_count': eval_count,
            'escape_count': escape_count,
            'settimeout_count': settimeout_count,
            'external_links': external_links
        }
    
    except Exception as e:
        return {
            'num_forms': -1,
            'hidden_iframes': -1,
            'eval_count': -1,
            'escape_count': -1,
            'settimeout_count': -1,
            'external_links': -1
        }

def extract_redirection_count(url):
    try:
        # Follow redirects and count them
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirection_count = len(response.history)
        final_url = response.url
        
        return {
            'redirection_count': redirection_count,
            'final_domain': final_url.split('/')[2] if '//' in final_url else final_url
        }
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        return {
            'redirection_count': -1,
            'final_domain': 'Unknown'
        }
def is_shortened_url(url):
    # List of common URL shorteners
    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'buff.ly',
        'is.gd', 't.co', 'shorte.st', 'cutt.ly', 'adf.ly'
    ]
    
    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        if domain in shorteners:
            return {'is_shortened': 1}
        else:
            return {'is_shortened': 0}
    except Exception as e:
        print(f"Error: {e}")
        return {'is_shortened': -1}

def get_domain_age(url):
    try:
        domain = url.split('/')[2] if '//' in url else url.split('/')[0]
        w = whois.whois(domain)
        
        creation_date = w.creation_date
        if isinstance(creation_date, list): 
            creation_date = creation_date[0]
        
        if creation_date:
            age = (datetime.now() - creation_date).days
        if age < 50:
            print("likely a suspicious website")
            return {'domain_age_days': age}
        if age > 50:
            return {'domain_age_days': age}
        else :
            return {'domain_age_days': "error"}
    except Exception as e:
        print(f"Error: {e}")
        return {'domain_age_days': -1}
    
ssl_context = ssl.create_default_context()

def get_certificate_info(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_to_expiry = (valid_to - datetime.utcnow()).days
                
                is_self_signed = issuer == dict(x[0] for x in cert['subject']).get('organizationName', '')

                return {
                    'cert_issuer': issuer,
                    'cert_validity_days': (valid_to - valid_from).days,
                    'days_to_expiry': days_to_expiry,
                    'is_self_signed': int(is_self_signed)
                }
    except (socket.timeout, ssl.SSLError, ssl.CertificateError) as e:
        # More specific exception handling for better debugging and control
        return {
            'cert_issuer': 'Unknown',
            'cert_validity_days': 0,
            'days_to_expiry': 0,
            'is_self_signed': 0
        }
def extract_ip_from_url(url):
    # Remove protocol and path
    domain = re.sub(r'^https?:\/\/', '', url).split('/')[0]
    
    try:
        # If it's already an IP address, use it directly
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return domain
        else:
            # Resolve domain to IP address
            ip = socket.gethostbyname(domain)
            return ip
    except Exception as e:
        print(f"Failed to resolve domain: {e}")
        return None

def check_ip_reputation(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        'Key': '7f8cb73c95faef17aa333f7df53181de2af99fb4926b53d4d25a846c22cb85d1dde3c4a0dd52abfa',
        'Accept': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            abuse_score = result['data']['abuseConfidenceScore']
            is_malicious = int(abuse_score > 50)
            return {
                'ip_abuse_score': abuse_score,
                'is_malicious_ip': is_malicious
            }
        else:
            print(f"API Error: {response.status_code} - {response.json()}")
    except Exception as e:
        print(f"API request failed: {e}")
    return {'ip_abuse_score': -1, 'is_malicious_ip': -1}

# Example usage:
url = 'http://allegro.pl-ogloszenia2891.icu'
ip = extract_ip_from_url(url)
if ip:
    result = check_ip_reputation(ip)
    print(f"IP: {ip} | Abuse Score: {result['ip_abuse_score']} | Malicious: {result['is_malicious_ip']}")
else:
    print("Failed to extract IP.")

# Run all feature extraction functions
print(
    get_certificate_info(url), 
    extract_url_features(url), 
    extract_keyword_features(url), 
    extract_content_features(url), 
    extract_domain_features(url),
    get_dns_record_count(url), 
    check_spf_dmarc(url), 
    extract_redirection_count(url), 
    is_shortened_url(url),
    get_domain_age(url), 
    extract_ip_from_url(url)
)