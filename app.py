from flask import Flask, request, jsonify, render_template, send_file
import mysql.connector
import re
import io
from fpdf import FPDF
from features_extract import (
    extract_url_features,
    extract_keyword_features,
    extract_content_features,
    extract_domain_features,
    extract_redirection_count,
    get_certificate_info
)

app = Flask(__name__, static_folder='static', template_folder='templates')

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Door#@mirror555",
        database="scrapy_db",
        charset="utf8mb4"
    )

# Utility to clean text
def clean_text(text):
    return re.sub(r'\s+', ' ', text).strip()

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Feature Extraction API
@app.route('/index', methods=['POST'])
def index():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is missing."}), 400

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

# Get Crawled Data API
@app.route('/get_data', methods=['GET'])
def get_data():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT url, title, is_phishing FROM bank_website201
            ORDER BY id DESC LIMIT 50
        """)
        records = cursor.fetchall()

        cursor.close()
        conn.close()

        cleaned_data = [
            {
                "url": record["url"],
                "title": clean_text(record["title"]),
                "is_phishing": record["is_phishing"]
            }
            for record in records
        ]

        return jsonify({
            "message": "Cleaned crawled data retrieved successfully",
            "data": cleaned_data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Generate and Download PDF Report API
@app.route('/download_report', methods=['POST'])
def download_report():
    try:
        data = request.get_json()
        url = data.get("url")

        if not url:
            return jsonify({"error": "URL is missing."}), 400

        # Extract features
        features = {
            "url_features": extract_url_features(url),
            "keyword_features": extract_keyword_features(url),
            "content_features": extract_content_features(url),
            "domain_features": extract_domain_features(url),
            "redirection_count": extract_redirection_count(url),
            "certificate_info": get_certificate_info(url)
        }

        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        pdf.cell(0, 10, txt=f"Report for URL: {url}", ln=True, align="C")
        pdf.ln(10)

        for category, details in features.items():
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, category.replace("_", " ").title(), ln=True)
            pdf.set_font("Arial", size=11)
            if isinstance(details, dict):
                for key, value in details.items():
                    pdf.multi_cell(0, 8, f"{key}: {value}")
            else:
                pdf.multi_cell(0, 8, str(details))
            pdf.ln(5)

        # Corrected part
        pdf_bytes = pdf.output(dest='S').encode('latin1')
        pdf_buffer = io.BytesIO(pdf_bytes)
        pdf_buffer.seek(0)

        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name="url_report.pdf",
            mimetype='application/pdf'
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
if __name__ == '__main__':
    app.run(debug=True)