from urllib.parse import urlparse
import re
import requests
from bs4 import BeautifulSoup
import socket
import ssl
from datetime import datetime
import whois
import dns.resolver

# URL feature extraction
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

# Keyword features
def extract_keyword_features(url):
    keywords = ['login', 'secure', 'account', 'bank', 'verify', 'password', 'update',
                'confirm', 'click', 'free', 'win', 'prize', 'submit', 'checkout', 'access', 'otp']
    keyword_count = sum([1 for keyword in keywords if keyword in url.lower()])
    return {
        'keyword_count': keyword_count,
        'has_login': int('login' in url.lower()),
        'has_verify': int('verify' in url.lower()),
        'has_bank': int('bank' in url.lower())
    }

# Domain features
suspicious_tlds = ['.xyz', '.tk', '.cf', '.ml', '.ga']
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

# DNS record count
def get_dns_record_count(url):
    domain = urlparse(url).netloc
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

# SPF/DMARC check
def check_spf_dmarc(url):
    domain = urlparse(url).netloc
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

# Content feature extraction
def extract_content_features(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        num_forms = len(soup.find_all('form'))
        hidden_iframes = len(soup.find_all('iframe', style=re.compile(r'display:\s*none')))
        script_content = ' '.join([script.text for script in soup.find_all('script')])
        return {
            'num_forms': num_forms,
            'hidden_iframes': hidden_iframes,
            'eval_count': script_content.count('eval('),
            'escape_count': script_content.count('escape('),
            'settimeout_count': script_content.count('setTimeout('),
            'external_links': sum(1 for a in soup.find_all('a', href=True) if url not in a['href'])
        }
    except:
        return dict.fromkeys([
            'num_forms', 'hidden_iframes', 'eval_count',
            'escape_count', 'settimeout_count', 'external_links'
        ], -1)

# Redirection count
def extract_redirection_count(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return {
            'redirection_count': len(response.history),
            'final_domain': urlparse(response.url).netloc
        }
    except:
        return {'redirection_count': -1, 'final_domain': 'Unknown'}

# Shortened URL
def is_shortened_url(url):
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'buff.ly',
                  'is.gd', 't.co', 'shorte.st', 'cutt.ly', 'adf.ly']
    try:
        domain = urlparse(url).netloc
        return {'is_shortened': int(domain in shorteners)}
    except:
        return {'is_shortened': -1}

# Domain age
def get_domain_age(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        age = (datetime.now() - creation_date).days if creation_date else -1
        return {'domain_age_days': age}
    except:
        return {'domain_age_days': -1}

# SSL certificate info
ssl_context = ssl.create_default_context()
def get_certificate_info(url):
    try:
        hostname = urlparse(url).netloc
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')
                valid_from = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                valid_to = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return {
                    'cert_issuer': issuer,
                    'cert_validity_days': (valid_to - valid_from).days,
                    'days_to_expiry': (valid_to - datetime.utcnow()).days,
                    'is_self_signed': int(issuer == dict(x[0] for x in cert['subject']).get('organizationName', ''))
                }
    except:
        return {
            'cert_issuer': 'Unknown',
            'cert_validity_days': 0,
            'days_to_expiry': 0,
            'is_self_signed': 0
        }

# Risk score calculation
def calculate_risk_score(features):
    score = 0
    if features['url']['has_ip']:
        score += 15
    score += features['keywords']['keyword_count'] * 2
    if features['keywords']['has_login'] or features['keywords']['has_bank'] or features['keywords']['has_verify']:
        score += 5
    if features['domain_age']['domain_age_days'] != -1 and features['domain_age']['domain_age_days'] < 50:
        score += 10
    if features['domain']['suspicious_tld']:
        score += 10
    if features['certificate']['is_self_signed']:
        score += 10
    if features['redirection']['redirection_count'] > 2:
        score += 5
    if features['content']['hidden_iframes'] > 0 or features['content']['eval_count'] > 0:
        score += 10
    if not features['email']['spf_present']:
        score += 3
    if not features['email']['dmarc_present']:
        score += 2
    if features['shortener']['is_shortened']:
        score += 5
    if features['dns']['dns_record_count'] < 2:
        score += 5
    if features['url']['length'] > 75:
        score += 5
    return min(score, 100)

# Main analysis wrapper
def analyze_url(url):
    return {
        'certificate': get_certificate_info(url),
        'url': extract_url_features(url),
        'keywords': extract_keyword_features(url),
        'content': extract_content_features(url),
        'domain': extract_domain_features(url),
        'dns': get_dns_record_count(url),
        'email': check_spf_dmarc(url),
        'redirection': extract_redirection_count(url),
        'shortener': is_shortened_url(url),
        'domain_age': get_domain_age(url)
    }
