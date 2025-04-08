import mysql.connector
import requests

class PhishingDetectionPipeline:
    def __init__(self):
        self.conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Door#@mirror555",
            database="scrapy_db",
            charset='utf8mb4',
            autocommit=True
        )
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS bank_website (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url TEXT,
                title TEXT,
                html LONGTEXT,
                content LONGTEXT,
                hash VARCHAR(64) UNIQUE,
                is_phishing VARCHAR(10)
            )
        """)

    def process_item(self, item, spider):
        # ✅ Send to Flask API
        flask_api_url = "http://127.0.0.1:5000/extract_features"
        try:
            response = requests.post(flask_api_url, json=item, timeout=10)
            spider.logger.info(f"📡 Sent to Flask API: {response.status_code} - {response.text}")
        except requests.exceptions.RequestException as e:
            spider.logger.error(f"❌ Failed to send to Flask API: {e}")

        # ✅ Save to MySQL
        self.cursor.execute("""
            INSERT IGNORE INTO bank_website (url, title, html, content, hash, is_phishing)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            item['url'],
            item['title'],
            item['html'],
            item['content'],
            item['hash'],
            item['is_phishing']
        ))

        spider.logger.info(f"✅ Saved: {item['url']} | Status: {item['is_phishing']}")
        return item

    def close_spider(self, spider):
        self.cursor.close()
        self.conn.close()
