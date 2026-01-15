from flask import Flask, jsonify
import mysql.connector
import re

app = Flask(__name__)

# Database connection


# Function to clean text data
def clean_text(text):
    return re.sub(r'\s+', ' ', text).strip()  # Remove extra spaces/newlines

# API endpoint to get cleaned crawled data
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

