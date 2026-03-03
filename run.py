"""
run.py — Single entry point for the full pipeline.

Steps:
  python run.py --prepare   → clean & merge PhishTank + Tranco
  python run.py --train     → extract features & train models
  python run.py --app       → launch web app
  python run.py --predict "https://example.com"  → quick CLI prediction
"""

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description='Phishing Detection System')
    parser.add_argument('--prepare', action='store_true', help='Prepare dataset')
    parser.add_argument('--train', action='store_true', help='Train models')
    parser.add_argument('--app', action='store_true', help='Launch web app')
    parser.add_argument('--predict', type=str, help='Predict a single URL')
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