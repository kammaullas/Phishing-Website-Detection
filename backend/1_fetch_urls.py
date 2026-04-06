# backend/1_fetch_urls.py
"""
Fetch legitimate and phishing URLs for the training dataset.
Legitimate URLs: Large curated list of top websites  
Phishing URLs:  Active phishing database from GitHub
"""

import pandas as pd
import requests
import random

OUTPUT_FILE = '../data/raw_urls.csv'

# --- Large curated list of legitimate domains ---
LEGIT_DOMAINS = [
    # Tech Giants
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "netflix.com", "apple.com",
    "microsoft.com", "github.com", "reddit.com", "whatsapp.com", "zoom.us",
    "tiktok.com", "pinterest.com", "twitch.tv", "spotify.com", "discord.com",
    
    # News & Media
    "nytimes.com", "cnn.com", "bbc.com", "theguardian.com", "washingtonpost.com",
    "reuters.com", "bloomberg.com", "forbes.com", "wsj.com", "aljazeera.com",
    "nbcnews.com", "abcnews.go.com", "foxnews.com", "usatoday.com", "huffpost.com",
    "theatlantic.com", "wired.com", "techcrunch.com", "theverge.com", "arstechnica.com",
    
    # E-commerce & Services
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "etsy.com",
    "shopify.com", "aliexpress.com", "rakuten.com", "wayfair.com", "costco.com",
    "homedepot.com", "lowes.com", "ikea.com", "zappos.com", "macys.com",
    "nordstrom.com", "sephora.com", "nike.com", "adidas.com", "underarmour.com",
    
    # Technology & Developer
    "stackoverflow.com", "medium.com", "dev.to", "gitlab.com", "bitbucket.org",
    "npm.js.com", "pypi.org", "docker.com", "kubernetes.io", "aws.amazon.com",
    "azure.microsoft.com", "cloud.google.com", "digitalocean.com", "heroku.com",
    "vercel.com", "netlify.com", "cloudflare.com", "godaddy.com", "namecheap.com",
    "hostinger.com",
    
    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org", "mit.edu",
    "stanford.edu", "harvard.edu", "yale.edu", "ox.ac.uk", "cam.ac.uk",
    "berkeley.edu", "caltech.edu", "columbia.edu", "princeton.edu", "cornell.edu",
    "coursera.org", "duolingo.com", "quizlet.com", "chegg.com", "studycom.com",
    
    # Finance & Banking
    "paypal.com", "stripe.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citibank.com", "capitalone.com", "americanexpress.com", "visa.com", "mastercard.com",
    "venmo.com", "squareup.com", "robinhood.com", "coinbase.com", "binance.com",
    "fidelity.com", "schwab.com", "etrade.com", "tdameritrade.com", "sofi.com",
    
    # Entertainment
    "hulu.com", "disneyplus.com", "hbomax.com", "peacocktv.com", "paramountplus.com",
    "crunchyroll.com", "funimation.com", "imdb.com", "rottentomatoes.com", "metacritic.com",
    "steamcommunity.com", "epicgames.com", "ea.com", "ubisoft.com", "roblox.com",
    "minecraft.net", "playstation.com", "xbox.com", "nintendo.com", "ign.com",
    
    # Productivity & Business
    "slack.com", "notion.so", "trello.com", "asana.com", "monday.com",
    "dropbox.com", "box.com", "drive.google.com", "onedrive.live.com", "icloud.com",
    "salesforce.com", "hubspot.com", "mailchimp.com", "canva.com", "figma.com",
    "adobe.com", "atlassian.com", "jira.atlassian.com", "confluence.atlassian.com",
    "zendesk.com",
    
    # Travel & Food
    "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com", "hotels.com",
    "kayak.com", "skyscanner.com", "priceline.com", "vrbo.com", "trivago.com",
    "uber.com", "lyft.com", "doordash.com", "grubhub.com", "ubereats.com",
    "yelp.com", "opentable.com", "zomato.com", "swiggy.com", "instacart.com",
    
    # Health & Fitness
    "webmd.com", "mayoclinic.org", "healthline.com", "nih.gov", "cdc.gov",
    "who.int", "fitbit.com", "myfitnesspal.com", "strava.com", "peloton.com",
    "headspace.com", "calm.com", "noom.com", "23andme.com", "zocdoc.com",
    
    # Search & Portals
    "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com",
    "ask.com", "aol.com", "ecosia.org", "brave.com", "qwant.com",
    
    # Social & Community
    "tumblr.com", "quora.com", "snapchat.com", "telegram.org", "signal.org",
    "meetup.com", "nextdoor.com", "clubhouse.com", "mastodon.social", "threads.net",
    
    # Government & Organizations  
    "usa.gov", "gov.uk", "whitehouse.gov", "irs.gov", "ssa.gov",
    "nasa.gov", "fbi.gov", "state.gov", "un.org", "europa.eu",
    
    # Miscellaneous Popular
    "craigslist.org", "imgur.com", "archive.org", "wikimedia.org",  "britannica.com",
    "weather.com", "accuweather.com", "maps.google.com", "translate.google.com",
    "docs.google.com", "mail.google.com", "outlook.com", "protonmail.com",
    "tutanota.com", "fastmail.com", "zoho.com", "wix.com", "squarespace.com",
    "wordpress.com", "blogger.com",
]

# --- Step 1: Fetch/Generate Legitimate URLs ---
print("⬇️  Preparing Legitimate URLs (Class 0)...")
legit_urls = []

# First try to get Tranco list for diversity
try:
    tranco_df = pd.read_csv(
        "https://tranco-list.eu/top-1m.csv",
        names=['rank', 'domain'],
        nrows=2000
    )
    raw_domains = tranco_df['domain'].tolist()
    print(f"  ✅ Downloaded {len(raw_domains)} domains from Tranco list.")
except Exception as e:
    print(f"  ⚠️  Tranco unavailable: {e}")
    raw_domains = []

# Combine Tranco + our curated list
all_legit_domains = list(set(raw_domains + LEGIT_DOMAINS))
random.shuffle(all_legit_domains)

# Create realistic URL formats 
for domain in all_legit_domains:
    # Each domain gets multiple realistic URL variations
    formats = [
        f"https://www.{domain}",
        f"https://{domain}",
        f"https://www.{domain}/",
        f"https://{domain}/about",
        f"https://www.{domain}/contact",
        domain, # Bare domain
        f"www.{domain}", # www prefix only
        f"http://{domain}", # http prefix
        f"http://www.{domain}", # http + www prefix
    ]
    # Pick 2–4 random variations for diversity
    n_variations = random.randint(2, 4)
    legit_urls.extend(random.sample(formats, min(n_variations, len(formats))))

random.shuffle(legit_urls)
print(f"  ✅ Generated {len(legit_urls)} legitimate URL variations.")

# --- Step 2: Fetch Active Phishing URLs ---
print("\n⬇️  Fetching active Phishing URLs (Class 1)...")
phishing_urls = []
try:
    response = requests.get(
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
    )
    phishing_all = [url.strip() for url in response.text.splitlines() if url.strip()]
    # Sample up to the same count as legit URLs for perfect balance
    max_phish = min(len(legit_urls), len(phishing_all))
    phishing_urls = random.sample(phishing_all, max_phish)
    print(f"  ✅ Secured {len(phishing_urls)} active phishing URLs.")
except Exception as e:
    print(f"  ❌ Failed to fetch phishing list: {e}")
    exit()

# --- Step 3: Balance and Save ---
# Use the shorter list length for perfect balance
n = min(len(legit_urls), len(phishing_urls))
legit_urls = legit_urls[:n]
phishing_urls = phishing_urls[:n]

data = []
for legit, phish in zip(legit_urls, phishing_urls):
    data.append({"url": legit, "label": 0})
    data.append({"url": phish, "label": 1})

df = pd.DataFrame(data)
df.to_csv(OUTPUT_FILE, index=False)
print(f"\n🎉 Saved {len(df)} balanced URLs to {OUTPUT_FILE}")
print(f"   Legitimate: {len(df[df['label']==0])}")
print(f"   Phishing:   {len(df[df['label']==1])}")
print(f"   Unique legit domains: {len(all_legit_domains)}")