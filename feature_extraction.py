import math
from collections import Counter
import joblib
import pandas as pd
import whois
from urllib.parse import urlparse
import tldextract
import re

shorteners = {"bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly"}
keywords = {"secure","account","update","free","lucky","bonus","click","offer","winner","login","verify","banking","confirm","password","signin"}

# Vytvor extractor raz na začiatku s cache
_extractor = tldextract.TLDExtract(cache_dir='.tld_cache', suffix_list_urls=None)

# Prekompiluj regex pre IP adresy
_ip_pattern = re.compile(r'^\d+\.\d+\.\d+\.\d+$')

# Prekompiluj keywords do set pre rýchlejšie vyhľadávanie
_keywords_set = set(kw.lower() for kw in keywords)  # predpokladám že keywords existuje

# Prekompiluj shorteners do set
_shorteners_set = set(shorteners)  # predpokladám že shorteners existuje

def url_entropy(s: str) -> float:
    if not s:
        return 0;
    probs = [c/len(s) for c in Counter(s).values()]
    return -sum(p*math.log2(p) for p in probs)

def normalize_date(value):
    """Vráti jeden datetime alebo None zo WHOIS hodnoty."""
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        return value.to_pydatetime()
    if isinstance(value, list):
        # rozbaľ vnorené listy
        flat = []
        for v in value:
            if isinstance(v, list):
                flat.extend(v)
            else:
                flat.append(v)
        # zober prvý validný datetime
        flat = [v for v in flat if v is not None]
        if not flat:
            return None
        return flat[0]  # alebo min(flat), ak chceš najstarší
    return value  # ak je to už datetime


def extract_whois_features(features: dict, url: str) -> dict:
    try:
        w = whois.whois(url)

        creation = normalize_date(w.creation_date)
        expiration = normalize_date(w.expiration_date)

        now = pd.Timestamp.now(tz='UTC').tz_localize(None)

        if creation is not None:
            c = pd.Timestamp(creation).tz_localize(None)
            domain_age = (now - c).days
        else:
            domain_age = -1

        if expiration is not None:
            e = pd.Timestamp(expiration).tz_localize(None)
            days_to_expire = (e - now).days
        else:
            days_to_expire = -1

        if creation is not None and expiration is not None:
            registration_length = (e - c).days
        else:
            registration_length = -1

        # domain age
        #domain_age = (pd.Timestamp.now() - pd.Timestamp(creation)).days if creation else -1
        features['domain_age'] = domain_age

        # days to expire
        #days_to_expire = (pd.Timestamp(expiration) - pd.Timestamp.now()).days if expiration else -1
        features['days_to_expire'] = days_to_expire

        # registration length
        #if creation and expiration:
        #    registration_length = (pd.Timestamp(expiration) - pd.Timestamp(creation)).days
        #else:
        #    registration_length = -1
        features['registration_length'] = registration_length

    except Exception as e:
        print(f"Chyba pri spracovaní {url}: {e}")
        features['domain_age'] = -1
        features['days_to_expire'] = -1
        features['registration_length'] = -1

    return features

def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    
    # Použij cache-ovaný extractor
    ext = _extractor(url)
    
    # Lowercase URL raz na začiatku
    url_lower = url.lower()
    
    # Spočítaj znaky v jednom prechode
    count_digits = 0
    count_hyphen = 0
    count_at = 0
    count_qm = 0
    count_eq = 0
    count_slash = 0
    
    for c in url:
        if c.isdigit():
            count_digits += 1
        elif c == '-':
            count_hyphen += 1
        elif c == '@':
            count_at += 1
        elif c == '?':
            count_qm += 1
        elif c == '=':
            count_eq += 1
        elif c == '/':
            count_slash += 1
    
    # Skombinuj domain + suffix raz
    full_domain = f"{ext.domain}.{ext.suffix}"
    
    # Vytvor features dict naraz
    features = {
        'url': url,
        'url_len': len(url),
        'host_len': len(hostname),
        'path_len': len(path),
        'query_len': len(query),
        'is_https': 1 if parsed.scheme == 'https' else 0,
        'count_dots': hostname.count('.'),
        'count_hyphen': count_hyphen,
        'count_at': count_at,
        'count_qm': count_qm,
        'count_eq': count_eq,
        'count_slash': count_slash,
        'count_digits': count_digits,
        'has_ip': 1 if _ip_pattern.match(hostname) else 0,
        'has_https': 1 if url_lower.startswith("https") else 0,
        'has_shortener': 1 if full_domain in _shorteners_set else 0,
        'has_keyword': 1 if any(kw in url_lower for kw in _keywords_set) else 0,
        'subdomain_len': len(ext.subdomain),
        'domain': ext.domain,
        'suffix': ext.suffix,
        'domain_entropy': url_entropy(hostname)
    }

    extract_whois_features(features, full_domain)
    
    return features