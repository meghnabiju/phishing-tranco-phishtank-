import pandas as pd
import re
from urllib.parse import urlparse

def load_phishtank(filepath):
    """Load and clean PhishTank dataset."""
    df = pd.read_csv(filepath)
    print(f"PhishTank raw: {len(df)} rows")

    # Keep only verified + online phishing URLs
    if 'verified' in df.columns:
        df = df[df['verified'] == 'yes']
    if 'online' in df.columns:
        df = df[df['online'] == 'yes']

    df = df[['url']].copy()
    df['label'] = 1  # 1 = phishing
    df['url'] = df['url'].str.strip().str.lower()

    print(f"PhishTank after filter: {len(df)} rows")
    return df


def load_tranco(filepath):
    """Load Tranco - generate realistic URL variants."""
    df = pd.read_csv(filepath, header=None, names=['rank', 'domain'])
    print(f"Tranco raw: {len(df)} rows")

    # Take top 60K to have buffer after generating variants
    df = df.head(60000)
    df['domain'] = df['domain'].str.strip().str.lower()

    urls = []
    # Generate realistic variants so model sees www + paths too
    for domain in df['domain']:
        urls.append(f'https://{domain}')           # bare
        urls.append(f'https://www.{domain}')        # with www
        urls.append(f'https://{domain}/')           # trailing slash
        urls.append(f'https://www.{domain}/home')   # with path

    result = pd.DataFrame({'url': urls})
    result = result.drop_duplicates()
    # Sample 50K from expanded set
    result = result.sample(n=min(50000, len(result)), random_state=42)
    result['label'] = 0
    print(f"Tranco after expansion: {len(result)} rows")
    return result


def is_valid_url(url):
    """Check if URL is valid and has proper structure."""
    try:
        result = urlparse(url)
        return (
            result.scheme in ('http', 'https') and
            bool(result.netloc) and
            len(url) > 10 and
            len(url) < 2000
        )
    except:
        return False


def clean_and_merge(phishtank_path, tranco_path, output_path='data/dataset.csv'):
    """Full pipeline: load, clean, deduplicate, balance, save."""

    phish_df = load_phishtank(phishtank_path)
    legit_df = load_tranco(tranco_path)

    # Combine
    combined = pd.concat([phish_df, legit_df], ignore_index=True)
    print(f"\nCombined raw: {len(combined)} rows")

    # Step 1: Remove nulls
    combined.dropna(subset=['url'], inplace=True)
    combined = combined[combined['url'].str.strip() != '']
    print(f"After null removal: {len(combined)} rows")

    # Step 2: Validate URLs
    combined = combined[combined['url'].apply(is_valid_url)]
    print(f"After URL validation: {len(combined)} rows")

    # Step 3: Remove exact duplicates
    before = len(combined)
    combined.drop_duplicates(subset=['url'], keep='first', inplace=True)
    print(f"After dedup: {len(combined)} rows (removed {before - len(combined)})")

    # Step 4: Remove contradictory labels (same URL, different label)
    label_counts = combined.groupby('url')['label'].nunique()
    contradictory = label_counts[label_counts > 1].index
    if len(contradictory) > 0:
        print(f"Removing {len(contradictory)} contradictory URLs")
        combined = combined[~combined['url'].isin(contradictory)]

    # Step 5: Check balance
    print(f"\nClass distribution:")
    print(combined['label'].value_counts())
    print(combined['label'].value_counts(normalize=True).mul(100).round(2))

    # Step 6: Balance dataset - take min count from each class, max 50K each
    phish_count = min(len(combined[combined['label'] == 1]), 50000)
    legit_count = min(len(combined[combined['label'] == 0]), 50000)
    final_count = min(phish_count, legit_count)

    phish_sample = combined[combined['label'] == 1].sample(n=final_count, random_state=42)
    legit_sample = combined[combined['label'] == 0].sample(n=final_count, random_state=42)

    final_df = pd.concat([phish_sample, legit_sample], ignore_index=True)
    final_df = final_df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

    print(f"\nFinal balanced dataset: {len(final_df)} rows")
    print(final_df['label'].value_counts())

    # Save
    final_df.to_csv(output_path, index=False)
    print(f"\nSaved to {output_path}")
    return final_df


if __name__ == '__main__':
    clean_and_merge('data/phishtank.csv', 'data/tranco.csv')