from flask import Flask, request, jsonify, render_template
import mysql.connector
import re
from features_extract import extract_url_features, extract_keyword_features, extract_content_features, extract_domain_features, extract_redirection_count, get_certificate_info

app = Flask(__name__)

# Database connection


# Function to clean text data
def clean_text(text):
    return re.sub(r'\s+', ' ', text).strip()  # Remove extra spaces/newlines

# Home Route
@app.route('/')
def home():
    return render_template('index.html')

# Feature Extraction API
@app.route('/index', methods=['POST'])
def index():
    try:
        data = request.get_json()
        url = data.get("url")

        # Extract features
        features = {
            "url_features": extract_url_features(url),
            "keyword_features": extract_keyword_features(url),
            "content_features": extract_content_features(url),
            "domain_features": extract_domain_features(url),
            "redirection_count": extract_redirection_count(url),
            "certificate_info": get_certificate_info(url)
        }

        return jsonify({"url": url, "features": features})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Crawled Data API
@app.route('/get_data', methods=['GET'])
def get_data():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT url, title, is_phishing FROM bank_website201 ORDER BY id DESC LIMIT 50
    """)
    records = cursor.fetchall()
    
    cursor.close()
    conn.close()

    # Clean each record before sending
    cleaned_data = []
    for record in records:
        cleaned_data.append({
            "url": record["url"],
            "title": clean_text(record["title"]),
            "is_phishing": record["is_phishing"]
        })

    return jsonify({
        "message": "Cleaned crawled data retrieved successfully",
        "data": cleaned_data
    })

if __name__ == '__main__':
    app.run(debug=True)

