"""
run.py — Single entry point for the full pipeline.

Steps:
  python run.py --prepare                        → clean & merge PhishTank + Tranco
  python run.py --train                          → extract features & train models
  python run.py --app                            → launch web app
  python run.py --predict "https://example.com" → quick CLI prediction
  python run.py --evaluate                       → print accuracy, precision, etc.
  python run.py --debug "https://example.com"   → show feature breakdown for a URL
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description='Phishing Detection System')
    parser.add_argument('--prepare',  action='store_true', help='Prepare dataset')
    parser.add_argument('--train',    action='store_true', help='Train models')
    parser.add_argument('--app',      action='store_true', help='Launch web app')
    parser.add_argument('--predict',  type=str, help='Predict a single URL')
    parser.add_argument('--evaluate', action='store_true', help='Evaluate model metrics')
    parser.add_argument('--debug',    type=str, help='Show feature breakdown for a URL')
    args = parser.parse_args()

    if args.prepare:
        print("=== Step 1: Data Preparation ===")
        from src.data_preparation import clean_and_merge
        clean_and_merge('data/phishtank.csv', 'data/tranco.csv')

    elif args.train:
        print("=== Step 2: Training Models ===")
        from src.train import train
        train()

    elif args.predict:
        from src.predict import load_models, predict_url
        load_models()
        result = predict_url(args.predict)
        print(f"\nURL: {result['url']}")
        print(f"Prediction: {result['prediction']}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Anti-Phishing Score: {result['anti_phishing_score']}")
        print(f"Confidence: {result['confidence']}%")
        if result['red_flags']:
            print(f"Red Flags: {', '.join(result['red_flags'])}")

    elif args.evaluate:
        print("=== Model Evaluation ===")
        from src.evaluate import evaluate
        evaluate()

    elif args.debug:
        url = args.debug.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        from src.feature_extractor import extract_features
        features = extract_features(url)

        print(f"\nFeature breakdown for:\n  {url}\n")
        print(f"  {'Feature':<28} {'Value':>6}   Notes")
        print(f"  {'-'*65}")

        notes = {
            'has_ip':                  'IP as host instead of domain',
            'is_shortener':            'Known URL shortener service',
            'has_at_symbol':           '@ forces browser to ignore prefix',
            'has_double_slash':        '// redirect after protocol',
            'dash_in_sld':             'Hyphen in main domain name',
            'subdomain_depth':         '0=none/www, 1=one sub, 2+=suspicious',
            'has_https':               '1=https, 0=http only',
            'https_in_domain':         '"https" word inside domain name',
            'has_non_std_port':        'Port other than 80/443',
            'suspicious_tld':          'Free/disposable TLD like .tk .ml .xyz',
            'trusted_tld':             'Common trusted TLD like .com .org',
            'brand_spoofing':          'Brand name in URL but not the real domain',
            'phishing_keyword':        'Phishing-specific keyword combo in URL',
            'digit_ratio_sld':         'Ratio of digits in domain name',
            'long_hyphenated_sld':     'Domain is long AND has hyphens',
            'dots_in_domain':          'Number of dots in domain part',
            'hyphens_in_domain':       'Number of hyphens in domain',
            'suspicious_query_params': 'Redirect/cmd params in query string',
            'has_encoded_chars':       'Percent-encoded chars in path',
            'has_hex':                 'Hex encoding like %2F in URL',
            'repeated_chars':          'Repeated chars like gooogle, paypaall',
            'domain_token_count':      'Parts when domain split by dot',
            'numeric_domain':          'Domain is purely numeric/IP-like',
            'brand_hyphen_pattern':    'paypal-, -amazon, apple- in domain',
            'has_fragment':            'Has # fragment in URL',
            'special_chars_in_domain': 'Unusual chars in domain',
            'suspicious_path':         '2+ suspicious words in URL path',
            'has_www':                 'Has www prefix',
            'underscore_in_domain':    'Underscore in domain name',
            'multi_dot_suffix':        'TLD itself has dots like .com.tk',
        }

        # Features where value=1 means phishing signal
        bad_if_1 = {
            'has_ip', 'is_shortener', 'has_at_symbol', 'has_double_slash',
            'dash_in_sld', 'https_in_domain', 'has_non_std_port',
            'suspicious_tld', 'brand_spoofing', 'phishing_keyword',
            'long_hyphenated_sld', 'suspicious_query_params', 'has_hex',
            'repeated_chars', 'numeric_domain', 'brand_hyphen_pattern',
            'special_chars_in_domain', 'suspicious_path',
            'underscore_in_domain', 'multi_dot_suffix'
        }
        # Features where value >= threshold means phishing signal
        bad_if_high = {
            'subdomain_depth':    2,
            'dots_in_domain':     4,
            'hyphens_in_domain':  2,
            'domain_token_count': 5,
            'digit_ratio_sld':    0.5,
        }
        # Features where value=0 means phishing signal
        bad_if_0 = {'has_https', 'trusted_tld'}

        phishing_signals   = []
        legitimate_signals = []

        for feature, value in features.items():
            note   = notes.get(feature, '')
            is_bad = False

            if feature in bad_if_1 and value == 1:
                is_bad = True
                phishing_signals.append(feature)
            elif feature in bad_if_high and value >= bad_if_high[feature]:
                is_bad = True
                phishing_signals.append(feature)
            elif feature in bad_if_0 and value == 0:
                is_bad = True
                phishing_signals.append(feature)
            elif feature in ('has_https', 'trusted_tld') and value == 1:
                legitimate_signals.append(feature)

            marker = '  🚨' if is_bad else ''
            print(f"  {feature:<28} {str(value):>6}   {note}{marker}")

        print(f"\n  {'─'*65}")
        print(f"  🚨 Phishing signals   ({len(phishing_signals)}): "
              f"{', '.join(phishing_signals) if phishing_signals else 'none'}")
        print(f"  ✅ Legitimate signals ({len(legitimate_signals)}): "
              f"{', '.join(legitimate_signals) if legitimate_signals else 'none'}")
        print()

    elif args.app:
        print("=== Step 3: Launching Web App ===")
        from src.predict import load_models
        load_models()
        import app as flask_app
        flask_app.app.run(debug=False, port=5000)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()