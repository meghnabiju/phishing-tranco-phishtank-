import pandas as pd
import re
from urllib.parse import urlparse


def load_phishtank(filepath):
    """Load and clean PhishTank dataset."""
    df = pd.read_csv(filepath)
    print(f"PhishTank raw: {len(df)} rows")
    if 'verified' in df.columns:
        df = df[df['verified'] == 'yes']
    if 'online' in df.columns:
        df = df[df['online'] == 'yes']
    df = df[['url']].copy()
    df['label'] = 1
    df['url'] = df['url'].str.strip().str.lower()
    print(f"PhishTank after filter: {len(df)} rows")
    return df


def generate_phishing_samples():
    """Synthetic phishing URLs to supplement PhishTank."""
    import random
    random.seed(99)

    suspicious_tlds = [
        'tk','ml','ga','cf','gq','xyz','top','icu','buzz',
        'lat','cam','cyou','monster','vip','work','party','win','loan'
    ]
    trusted_tld_list = ['com', 'net', 'org']
    single_words = [
        'phish','hack','steal','fraud','scam','fake','login','secure',
        'verify','account','update','free','win','prize','click',
        'bank','wallet','portal','alert','support'
    ]
    hyphenated = [
        'free-prize','login-verify','secure-account','win-now',
        'free-offer','claim-prize','verify-now','account-alert',
        'secure-login','bank-alert','update-now','confirm-account',
        'paypal-secure','amazon-login','apple-verify',
        'microsoft-alert','google-secure','facebook-login',
        'netflix-update','account-suspended','billing-update',
        'payment-failed','action-required'
    ]
    brands = [
        'paypal','amazon','apple','microsoft','google',
        'facebook','netflix','instagram','twitter','ebay'
    ]
    brand_suffixes = [
        '-secure','-login','-verify','-update','-alert',
        '-support','-account','-confirm','-signin'
    ]
    brand_actions = [
        'account-update','secure-login','account-verify',
        'login-secure','verify-account','update-billing',
        'account-suspended','signin-verify','billing-update',
        'payment-update','account-confirm'
    ]
    paths = [
        '','/','/login','/verify','/secure','/account',
        '/update','/signin','/confirm','/validate',
        '/login.php','/verify.html','/secure/login',
        '/account/verify','/signin?next=home'
    ]

    urls = []

    for _ in range(3000):
        word = random.choice(single_words)
        tld  = random.choice(suspicious_tlds)
        path = random.choice(paths)
        num  = str(random.randint(1, 999)) if random.random() > 0.5 else ''
        urls += [f'https://{word}{num}.{tld}{path}'] * 2
        urls.append(f'http://{word}{num}.{tld}{path}')

    for _ in range(3000):
        combo = random.choice(hyphenated)
        tld   = random.choice(suspicious_tlds)
        path  = random.choice(paths)
        urls += [f'https://{combo}.{tld}{path}'] * 2
        urls.append(f'http://{combo}.{tld}{path}')

    for _ in range(2000):
        brand  = random.choice(brands)
        suffix = random.choice(brand_suffixes)
        tld    = random.choice(suspicious_tlds)
        path   = random.choice(paths)
        urls += [f'https://{brand}{suffix}.{tld}{path}'] * 2

    for _ in range(2000):
        combo = random.choice(hyphenated)
        tld   = random.choice(trusted_tld_list)
        path  = random.choice(paths)
        urls.append(f'https://{combo}.{tld}{path}')

    for _ in range(4000):
        brand  = random.choice(brands)
        action = random.choice(brand_actions)
        tld    = random.choice(trusted_tld_list)
        path   = random.choice(paths)
        urls += [f'https://{brand}-{action}.{tld}{path}'] * 2
        urls.append(f'https://{action}-{brand}.{tld}{path}')

    for _ in range(1000):
        ip = (f'{random.randint(1,255)}.{random.randint(0,255)}'
              f'.{random.randint(0,255)}.{random.randint(1,255)}')
        path = random.choice(paths)
        urls.append(f'http://{ip}{path}')
        urls.append(f'https://{ip}{path}')

    obfuscated = [
        'https://paypa1.com','https://arnazon.com','https://g00gle.com',
        'https://app1e-id.com','https://netf1ix.com','https://lnstagram.com',
        'https://faceb00k.com','https://pay-pal.com',
        'https://amaz0n-secure.com','https://apple-id-verify.com',
        'https://microsoft-alert.com','https://secure-paypal.com',
        'https://amazon-security.com','https://paypal-login.com',
    ]
    for base in obfuscated:
        for path in paths[:6]:
            urls += [base + path] * 2

    df = pd.DataFrame({'url': urls, 'label': 1})
    df = df.drop_duplicates(subset=['url'])
    print(f"Generated {len(df)} synthetic phishing samples")
    return df


def get_guaranteed_legitimate_urls():
    """
    Brand subdomain + India govt URLs that must be in training.
    These are added AFTER sampling so they are never dropped.
    This is the key fix for accounts.google.com being flagged.
    """
    brand_urls = [
        # Google — subdomain_depth=1, trusted_tld=1
        'https://accounts.google.com/signin',
        'https://accounts.google.com/login',
        'https://accounts.google.com/ServiceLogin',
        'https://mail.google.com/mail',
        'https://maps.google.com/',
        'https://myaccount.google.com/',
        'https://support.google.com/accounts',
        'https://drive.google.com/drive',
        'https://docs.google.com/document',
        'https://calendar.google.com/',
        'https://meet.google.com/',
        # Amazon
        'https://signin.amazon.com/signin',
        'https://payments.amazon.com/',
        'https://seller.amazon.com/signin',
        'https://console.aws.amazon.com/console',
        # Microsoft
        'https://account.microsoft.com/account',
        'https://login.microsoftonline.com/',
        'https://login.live.com/login',
        'https://outlook.live.com/mail',
        'https://teams.microsoft.com/signin',
        # Apple
        'https://appleid.apple.com/sign-in',
        'https://id.apple.com/signin',
        'https://developer.apple.com/account',
        # PayPal
        'https://www.paypal.com/signin',
        'https://login.paypal.com/signin',
        'https://secure.paypal.com/home',
        # Others
        'https://www.facebook.com/login',
        'https://m.facebook.com/login',
        'https://business.facebook.com/login',
        'https://api.twitter.com/oauth',
        'https://mobile.twitter.com/login',
        'https://www.instagram.com/accounts/login',
        'https://app.slack.com/signin',
        'https://login.salesforce.com/',
        'https://signin.ebay.com/signin',
        'https://www.linkedin.com/login',
        'https://www.netflix.com/login',
        'https://github.com/login',
        'https://dashboard.stripe.com/login',
        'https://cloud.google.com/console',
        'https://hub.docker.com/login',
        # General subdomain patterns
        'https://mail.yahoo.com/',
        'https://mail.outlook.com/',
        'https://app.github.com/',
        'https://api.stripe.com/',
        'https://support.microsoft.com/',
        'https://help.twitter.com/',
        'https://docs.github.com/',
        'https://status.github.com/',
        'https://m.facebook.com/',
        'https://mobile.twitter.com/',
    ]

    india_urls = [
        'https://www.india.gov.in/',
        'https://www.incometax.gov.in/iec/foportal',
        'https://www.gst.gov.in/',
        'https://www.rbi.org.in/',
        'https://www.uidai.gov.in/',
        'https://resident.uidai.gov.in/verify',
        'https://myaadhaar.uidai.gov.in/',
        'https://digilocker.gov.in/signin',
        'https://www.irctc.co.in/',
        'https://www.irctc.co.in/nget/train-search',
        'https://vahan.parivahan.gov.in/',
        'https://exams.nta.ac.in/',
        'https://www.cbse.gov.in/',
        'https://results.cbse.nic.in/',
        'https://www.kerala.gov.in/',
        'https://www.karnataka.gov.in/',
        'https://www.onlinesbi.sbi/',
        'https://ssc.nic.in/',
        'https://www.upsc.gov.in/',
        'https://www.epfindia.gov.in/',
        'https://unifiedportal-mem.epfindia.gov.in/',
        'https://www.sebi.gov.in/',
        'https://www.passportindia.gov.in/',
        'https://www.mygov.in/',
        'https://www.npci.org.in/',
    ]

    all_urls = brand_urls + india_urls
    df = pd.DataFrame({'url': all_urls, 'label': 0})
    df = df.drop_duplicates(subset=['url'])
    print(f"Guaranteed legitimate URLs: {len(df)}")
    return df


def load_tranco(filepath):
    """Load top 25K Tranco domains with realistic URL variants."""
    import random
    random.seed(42)

    df = pd.read_csv(filepath, header=None, names=['rank', 'domain'])
    print(f"Tranco raw: {len(df)} rows")

    df = df.head(25000)
    df['domain'] = df['domain'].str.strip().str.lower()

    path_templates = [
        '', '/', '/home', '/about', '/contact', '/login', '/signup',
        '/search?q=laptop', '/search?q=shoes&page=2',
        '/products/electronics', '/category/books',
        '/user/profile', '/help/faq', '/news/today', '/shop/cart',
        '/account/settings', '/account/verify-email',
        '/secure/checkout', '/blog/2024/top-tips',
        '/dp/B09G9FPHY6/ref=sr_1_1?keywords=phone',
        '/watch?v=dQw4w9WgXcQ', '/en/support/article/12345',
        '/checkout?step=address', '/order/tracking?id=ABC123',
        '/confirm-email?token=abc123', '/reset-password?token=xyz789',
        '/api/v1/products?page=1&limit=20',
    ]

    prefixes = ['', 'www.', '']
    schemes  = ['https', 'https', 'https', 'http']

    tranco_urls = []
    for domain in df['domain']:
        for _ in range(2):
            prefix = random.choice(prefixes)
            scheme = random.choice(schemes)
            path   = random.choice(path_templates)
            tranco_urls.append(f'{scheme}://{prefix}{domain}{path}')

    result = pd.DataFrame({'url': tranco_urls})
    result = result.drop_duplicates()
    result['label'] = 0
    print(f"Tranco URLs generated: {len(result)} rows")
    return result


def is_valid_url(url):
    try:
        r = urlparse(url)
        return (
            r.scheme in ('http', 'https') and
            bool(r.netloc) and
            10 < len(url) < 2000
        )
    except:
        return False


def clean_and_merge(phishtank_path, tranco_path,
                    output_path='data/dataset.csv'):
    """
    Full pipeline using both PhishTank and Tranco datasets.
    Guaranteed URLs added AFTER sampling — never dropped.
    """
    print("=" * 50)
    print("STEP 1: Loading PhishTank")
    print("=" * 50)
    phish_df = load_phishtank(phishtank_path)
    phish_df = pd.concat(
        [phish_df, generate_phishing_samples()],
        ignore_index=True
    )
    print(f"Total phishing: {len(phish_df)}")

    print("\n" + "=" * 50)
    print("STEP 2: Loading Tranco")
    print("=" * 50)
    tranco_df = load_tranco(tranco_path)
    print(f"Total tranco legitimate: {len(tranco_df)}")

    print("\n" + "=" * 50)
    print("STEP 3: Cleaning and balancing")
    print("=" * 50)
    combined = pd.concat([phish_df, tranco_df], ignore_index=True)
    print(f"Combined raw: {len(combined)} rows")

    combined.dropna(subset=['url'], inplace=True)
    combined = combined[combined['url'].str.strip() != '']
    combined = combined[combined['url'].apply(is_valid_url)]
    print(f"After validation: {len(combined)} rows")

    before = len(combined)
    combined.drop_duplicates(subset=['url'], keep='first', inplace=True)
    print(f"After dedup: {len(combined)} rows (removed {before - len(combined)})")

    lc  = combined.groupby('url')['label'].nunique()
    bad = lc[lc > 1].index
    if len(bad):
        print(f"Removing {len(bad)} contradictory URLs")
        combined = combined[~combined['url'].isin(bad)]

    print(f"\nClass distribution:")
    print(combined['label'].value_counts())

    # Sample 50K each
    n = min(
        len(combined[combined['label'] == 1]),
        len(combined[combined['label'] == 0]),
        50000
    )
    phish_s = combined[combined['label'] == 1].sample(n=n, random_state=42)
    legit_s = combined[combined['label'] == 0].sample(n=n, random_state=42)

    # Add guaranteed legitimate URLs AFTER sampling
    # This ensures accounts.google.com etc. are ALWAYS in training
    guaranteed = get_guaranteed_legitimate_urls()

    final = pd.concat([phish_s, legit_s, guaranteed], ignore_index=True)
    final = final.drop_duplicates(subset=['url'])
    final = final.sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"\nFinal dataset: {len(final)} rows")
    print(final['label'].value_counts())

    final.to_csv(output_path, index=False)
    print(f"Saved to {output_path}")
    return final


if __name__ == '__main__':
    clean_and_merge('data/phishtank.csv', 'data/tranco.csv')