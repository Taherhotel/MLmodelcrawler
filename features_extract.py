from urllib.parse import urlparse
import re, requests, socket, ssl , whois , base64 , dns.resolver
from bs4 import BeautifulSoup
from datetime import datetime
from datetime import datetime

def extract_url_features(url):
    parsed_url = urlparse(url)

    length = len(url)
    num_dots = url.count('.')
    num_slashes = url.count('/')
    num_subdomains = parsed_url.netloc.count('.') - 1
    has_ip = bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc))
    has_http = url.startswith('http')
    has_https = url.startswith('https')
    has_at = '@' in url
    tld = parsed_url.netloc.split('.')[-1] if '.' in parsed_url.netloc else ''
    
    return {
        'length': length,
        'num_dots': num_dots,
        'num_slashes': num_slashes,
        'num_subdomains': num_subdomains,
        'has_ip': int(has_ip),
        'has_http': int(has_http),
        'has_https': int(has_https),
        'has_at': int(has_at),
        'tld': tld
    }
def extract_keyword_features(url):
    keywords = [
        'login', 'secure', 'account', 'bank', 'verify', 'password', 'update',
        'confirm', 'click', 'free', 'win', 'prize', 'submit', 'checkout', 'access','otp'
    ]
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
        answers = dns.resolver.resolve(domain, 'TXT', raise_on_no_answer=False)
        for txt in answers:
            if txt.to_text().startswith('"v=spf1'):
                spf_present = 1
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        spf_present = 0
    
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT', raise_on_no_answer=False)
        for txt in answers:
            if txt.to_text().startswith('"v=DMARC1'):
                dmarc_present = 1
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        dmarc_present = 0
    
    return {'spf_present': spf_present, 'dmarc_present': dmarc_present}

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
        else:
            age = -1
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
        
        # Skip if not HTTPS
        if parsed_url.scheme != 'https':
            return {
                'cert_issuer': 'No SSL (HTTP only)',
                'cert_validity_days': 0,
                'days_to_expiry': 0,
                'is_self_signed': 0
            }

        hostname = parsed_url.netloc or parsed_url.path  # fallback if netloc is empty

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
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

    except (socket.timeout, ssl.SSLError, ssl.CertificateError, socket.gaierror, ConnectionResetError) as e:
        return {
            'cert_issuer': f'Error: {str(e)}',
            'cert_validity_days': 0,
            'days_to_expiry': 0,
            'is_self_signed': 0
        }
    
def check_google_safe_browsing(url):
    API_KEY = "AIzaSyAjRuN1xaitK3kZ3X0fTGRlDwO8msOKKPE"
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"
    body = {
        "client": {
            "clientId": "your-app-name",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(api_url, json=body)
        if response.status_code == 200:
            result = response.json()
            is_unsafe = "matches" in result
            return {"safe_browsing_flag": 0 if is_unsafe else 1}
        else:
            print("Safe Browsing API error:", response.text)
            return {"safe_browsing_flag": -1}
    except Exception as e:
        print("Safe Browsing check failed:", e)
        return {"safe_browsing_flag": -1}

API_KEY = "7c1f98fba460c2f18afa6da7021766c026920900a6bfad758036d8a3e6bc2a70"
def check_url_virustotal(url):
    headers = {
        "x-apikey": API_KEY
    }
    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code == 200:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            report = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers
            )

            try:
                data = report.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]

                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }

            except (KeyError, TypeError) as e:
                print(f"\n⚠ Unexpected response format: {e}")
                print(report.json())
                return {"error": "Unexpected response structure"}

        else:
            print(f"\n❌ Error submitting URL. Status Code: {response.status_code}")
            print(response.text)
            return {"error": f"Submission failed with status code {response.status_code}"}

    except Exception as e:
        print(f"\n❌ Exception occurred during VirusTotal check: {e}")
        return {"error": str(e)}

def calculate_risk_score(features):
    score = 0
    if features['url']['has_ip']:
        score += 15
    if features['url']['has_http']:
        score += 20
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
    if isinstance(features['virus_total'], dict) and 'malicious' in features['virus_total']:
        if features['virus_total']['malicious'] > 0:
            score += 90
    if isinstance(features['virus_total'], dict) and 'suspicious' in features['virus_total']:
        if features['virus_total']['suspicious']>0:
            score +=30

    return min(score, 100)

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
        'domain_age': get_domain_age(url),
        'virus_total': check_url_virustotal(url),
        'google_safe_browsing': check_google_safe_browsing(url)        
    }
