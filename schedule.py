import schedule
import time
from crawler import crawl_website

# List of websites to crawl
websites = [
    'https://example.com',
    'https://phishy-site.com',
    'https://another-site.net'
]

def run_crawler():
    for website in websites:
        print(f"Crawling: {website}")
        crawl_website(website)

# Schedule the task every 5 minutes
schedule.every(5).minutes.do(run_crawler)

# Keep running in the background
while True:
    schedule.run_pending()
    time.sleep(1)