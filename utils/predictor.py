import os
import sys
import re
import joblib
import pandas as pd
from urllib.parse import urlparse
import socket

# Ensure models module can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.feature_extraction import extract_features

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models', 'phishing_model.pkl')

def get_domain_and_ip(url):
    """Extracts domain and attempts to resolve IP address."""
    if not url.startswith(('http://', 'https://')):
        url_for_parse = 'http://' + url
    else:
        url_for_parse = url
    
    parsed = urlparse(url_for_parse)
    domain = parsed.netloc.split(':')[0] if parsed.netloc else ''
    
    ip_address = 'N/A'
    if domain:
        try:
            ip_address = socket.gethostbyname(domain)
        except Exception:
            ip_address = 'Unresolved'
            
    return domain, ip_address

def predict_url(url):
    """
    Predicts whether a given URL is Safe or Phishing.
    Returns dictionary with: prediction, confidence, features, domain, ip_address, url_length, is_https.
    """
    if not url or not isinstance(url, str) or len(url.strip()) == 0:
        return {
            'error': 'Invalid URL input.',
            'prediction': 'Unknown',
            'confidence': 0.0,
            'features': {},
            'domain': '',
            'ip_address': 'N/A',
            'url_length': 0,
            'is_https': False
        }

    url = url.strip()
    features = extract_features(url)
    domain, ip_address = get_domain_and_ip(url)
    url_length = features['url_length']
    is_https = bool(features['is_https'])

    # Attempt to load trained ML model
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            feature_df = pd.DataFrame([features])
            
            # Predict class and probability
            prediction_num = model.predict(feature_df)[0]
            probabilities = model.predict_proba(feature_df)[0]
            
            prediction = "Phishing" if prediction_num == 1 else "Safe"
            confidence = round(max(probabilities) * 100, 2)
        except Exception as e:
            # Fallback heuristic if model fails to load/predict
            prediction, confidence = _heuristic_predict(features)
    else:
        # Fallback rule-based heuristic when model is not yet trained/saved
        prediction, confidence = _heuristic_predict(features)

    return {
        'prediction': prediction,
        'confidence': confidence,
        'features': features,
        'domain': domain,
        'ip_address': ip_address,
        'url_length': url_length,
        'is_https': is_https
    }

def _heuristic_predict(features):
    """Basic fallback rule-based score when ML model file isn't loaded."""
    risk_score = 0
    if features['has_at_symbol']: risk_score += 25
    if features['is_ip_address']: risk_score += 30
    if features['has_hyphen_in_domain']: risk_score += 15
    if not features['is_https']: risk_score += 15
    if features['suspicious_word_count'] > 0: risk_score += 20 * features['suspicious_word_count']
    if features['url_length'] > 75: risk_score += 15

    if risk_score >= 40:
        prediction = "Phishing"
        confidence = min(99.0, 50.0 + (risk_score / 2.0))
    else:
        prediction = "Safe"
        confidence = min(99.0, 100.0 - (risk_score / 2.0))

    return prediction, round(confidence, 2)
