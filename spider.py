import scrapy
from scrapy_playwright.page import PageMethod
import hashlib
from urllib.parse import urlparse, urlunparse
import random
import asyncio

class BankSpider(scrapy.Spider):
    name = 'bank_spider'
    
    with open('indian_banks.txt') as f:
        allowed_domains = [line.strip() for line in f if line.strip()]

    start_urls = [f"https://{domain}" for domain in allowed_domains]
    random.shuffle(start_urls)
    visited_urls = set()
    max_pages = 15  
    max_depth = 3

    phishing_keywords = [
        "verify your account", "password reset", "urgent login",
        "your account is locked", "update payment info", "unusual activity",
        "confirm bank details", "login issue", "reset your password",
        "security check", "account suspended", "click here to verify"
    ]

    def start_requests(self):
        for url in self.start_urls:
            yield scrapy.Request(
                url,
                callback=self.parse,
                meta={
                    'playwright': True,
                    'depth': 0,
                    'playwright_page_methods': [
                        PageMethod('wait_for_load_state', 'domcontentloaded'),
                        PageMethod('evaluate', 'window.scrollTo(0, document.body.scrollHeight)'),
                        PageMethod('wait_for_timeout', 2000)
                    ]
                }
            )

    def normalize_url(self, url):
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment='', query=''))

    def check_phishing(self, text):
        text_lower = text.lower()
        for keyword in self.phishing_keywords:
            if keyword in text_lower:
                return "1"
        return "0"

    async def parse(self, response):
        if len(self.visited_urls) >= self.max_pages:
            return
        
        normalized_url = self.normalize_url(response.url)
        url_hash = hashlib.sha256(normalized_url.encode()).hexdigest()

        if url_hash not in self.visited_urls:
            self.visited_urls.add(url_hash)

            title = response.css('title::text').get() or "No Title"
            content = response.body.decode('utf-8', errors='ignore')
            is_phishing = self.check_phishing(content)

            # ✅ Yield item to pipeline
            yield {
                'url': normalized_url,
                'title': title,
                'html': content,
                'content': content,
                'hash': url_hash,
                'is_phishing': is_phishing
            }

        if len(self.visited_urls) < self.max_pages:
            current_depth = response.meta.get('depth', 0)
            if current_depth < self.max_depth:
                links = response.css('a::attr(href)').getall()
                for link in links:
                    absolute_url = response.urljoin(link)
                    normalized_link = self.normalize_url(absolute_url)

                    if normalized_link.startswith(('http')) and normalized_link not in self.visited_urls:
                        domain = urlparse(normalized_link).netloc
                        if domain in self.allowed_domains:
                            self.logger.info(f"⏳ Waiting 5 seconds before crawling: {normalized_link}")

                            await asyncio.sleep(5)

                            yield scrapy.Request(
                                normalized_link,
                                callback=self.parse,
                                meta={
                                    'playwright': True,
                                    'depth': current_depth + 1,
                                    'playwright_page_methods': [
                                        PageMethod('wait_for_load_state', 'domcontentloaded'),
                                        PageMethod('evaluate', 'window.scrollTo(0, document.body.scrollHeight)'),
                                        PageMethod('wait_for_timeout', 2000)
                                    ]
                                }
                            )
