from flask import Flask, request, render_template
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

def extract_keyword_features(url):
    keywords = ['login', 'secure', 'account', 'bank', 'verify', 'password', 'update',
                'confirm', 'click', 'free', 'win', 'prize', 'submit', 'checkout', 'access', 'otp']
    keyword_count = sum([1 for keyword in keywords if keyword in url.lower()])
    has_login = int('login' in url.lower())
    has_verify = int('verify' in url.lower())
    has_bank = int('bank' in url.lower())
    return {
        'keyword_count': keyword_count,
        'has_login': has_login,
        'has_verify': has_verify,
        'has_bank': has_bank
    }

def extract_domain_features(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    domain_length = len(domain)
    num_subdomains = domain.count('.') - 1
    has_hyphen = int('-' in domain)
    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    suspicious_tlds = ['.xyz', '.tk', '.cf', '.ml', '.ga']
    suspicious_tld = int(tld in suspicious_tlds)
    return {
        'domain_length': domain_length,
        'num_subdomains': num_subdomains,
        'has_hyphen': has_hyphen,
        'suspicious_tld': suspicious_tld
    }
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
        return {'domain_age_days':-1}

def extract_content_features(url):
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        num_forms = len(soup.find_all('form'))
        hidden_iframes = len(soup.find_all('iframe', style=re.compile(r'display:\s*none')))
        script_content = ' '.join([script.text for script in soup.find_all('script')])
        eval_count = script_content.count('eval(')
        escape_count = script_content.count('escape(')
        settimeout_count = script_content.count('setTimeout(')
        external_links = sum(1 for a in soup.find_all('a', href=True) if url not in a['href'])
        return {
            'num_forms': num_forms,
            'hidden_iframes': hidden_iframes,
            'eval_count': eval_count,
            'escape_count': escape_count,
            'settimeout_count': settimeout_count,
            'external_links': external_links
        }
    except Exception:
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
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirection_count = len(response.history)
        final_url = response.url
        return {
            'redirection_count': redirection_count,
            'final_domain': final_url.split('/')[2] if '//' in final_url else final_url
        }
    except requests.exceptions.RequestException:
        return {
            'redirection_count': -1,
            'final_domain': 'Unknown'
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


def get_certificate_info(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        ssl_context = ssl.create_default_context()
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
    except (socket.timeout, ssl.SSLError, ssl.CertificateError):
        return {
            'cert_issuer': 'Unknown',
            'cert_validity_days': 0,
            'days_to_expiry': 0,
            'is_self_signed': 0
        }

@app.route('/', methods=['GET', 'POST'])  # Add this line
@app.route('/index', methods=['GET', 'POST'])

def index():
    if request.method == 'POST':
        url = request.form['url']
        features = {
            "url_features": extract_url_features(url),
            "keyword_features": extract_keyword_features(url),
            "content_features": extract_content_features(url),
            "domain_features": extract_domain_features(url),
            "redirection_count": extract_redirection_count(url),
            "certificate_info": get_certificate_info(url),
            "domain_age": get_domain_age(url),
            "extract_ip": extract_ip_from_url(url),
            "ip reputation": check_ip_reputation(url)


        }
        return render_template('result.html', url=url, features=features)
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)
