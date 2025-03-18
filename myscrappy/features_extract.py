from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup
import socket
import ssl
from datetime import datetime
import whois
import dns.resolver

app = Flask(__name__)

# Suspicious TLDs and URL shorteners
suspicious_tlds = ['.xyz', '.tk', '.cf', '.ml', '.ga']
shorteners = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'buff.ly',
    'is.gd', 't.co', 'shorte.st', 'cutt.ly', 'adf.ly'
]

# SSL context
ssl_context = ssl.create_default_context()

# ✅ URL-based features
def extract_url_features(url):
    parsed_url = urlparse(url)
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

# ✅ Keyword-based features
def extract_keyword_features(url):
    keywords = [
        'login', 'secure', 'account', 'bank', 'verify', 'password', 'update',
        'confirm', 'click', 'free', 'win', 'prize', 'submit', 'checkout', 'access', 'otp'
    ]
    keyword_count = sum([1 for keyword in keywords if keyword in url.lower()])
    
    return {
        'keyword_count': keyword_count,
        'has_login': int('login' in url.lower()),
        'has_verify': int('verify' in url.lower()),
        'has_bank': int('bank' in url.lower())
    }

# ✅ Domain-based features
def extract_domain_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    subdomains = domain.split('.')
    
    domain_length = len(domain)
    num_subdomains = len(subdomains) - 2
    has_hyphen = int('-' in domain)
    tld = '.' + subdomains[-1] if len(subdomains) > 1 else ''
    suspicious_tld = int(tld in suspicious_tlds)
    
    return {
        'domain_length': domain_length,
        'num_subdomains': num_subdomains,
        'has_hyphen': has_hyphen,
        'suspicious_tld': suspicious_tld
    }

# ✅ DNS-based features
def get_dns_record_count(domain):
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    total_records = 0
    
    try:
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record, raise_on_no_answer=False)
                if answers:
                    total_records += len(answers)
            except:
                pass
    except:
        total_records = 0
    
    return {'dns_record_count': total_records}

# ✅ SPF/DMARC check
def check_spf_dmarc(domain):
    spf_present = 0
    dmarc_present = 0
    
    try:
        answers = dns.resolver.resolve(domain, 'TXT', raise_on_no_answer=False)
        for txt in answers:
            if txt.to_text().startswith('"v=spf1'):
                spf_present = 1
                break
    except:
        pass
    
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', raise_on_no_answer=False)
        for txt in answers:
            if txt.to_text().startswith('"v=DMARC1'):
                dmarc_present = 1
                break
    except:
        pass
    
    return {'spf_present': spf_present, 'dmarc_present': dmarc_present}

# ✅ SSL-based features
def get_certificate_info(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                
                return {'cert_issuer': issuer}
    except:
        return {'cert_issuer': 'Unknown'}

# ✅ Redirection-based features
def extract_redirection_count(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirection_count = len(response.history)
        
        return {'redirection_count': redirection_count}
    except:
        return {'redirection_count': -1}

# ✅ URL shortener check
def is_shortened_url(url):
    try:
        domain = urlparse(url).netloc
        return {'is_shortened': int(domain in shorteners)}
    except:
        return {'is_shortened': -1}

# ✅ Risk score calculation
def calculate_risk_score(features):
    score = 0
    
    score += features['length'] > 75
    score += features['num_dots'] > 3
    score += features['has_ip']
    score += not features['has_https']
    score += features['suspicious_tld']
    score += features['redirection_count'] > 3
    score += features['is_shortened']
    score += features['has_at']
    score += features['keyword_count'] > 2
    
    return min(score * 10, 100)

# ✅ Combined analysis endpoint
@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    features = {}
    features.update(extract_url_features(url))
    features.update(extract_keyword_features(url))
    features.update(extract_domain_features(url))
    features.update(get_dns_record_count(urlparse(url).netloc))
    features.update(check_spf_dmarc(urlparse(url).netloc))
    features.update(get_certificate_info(url))
    features.update(extract_redirection_count(url))
    features.update(is_shortened_url(url))
    
    risk_score = calculate_risk_score(features)
    
    return jsonify({**features, 'risk_score': risk_score})

# ✅ Flask app starter
if __name__ == '_main_':
    app.run(debug=True)