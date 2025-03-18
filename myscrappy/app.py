from flask import Flask, request, jsonify, render_template
from features_extract import extract_url_features, extract_keyword_features, extract_content_features, extract_domain_features, extract_redirection_count, get_certificate_info

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

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

if __name__ == '__main__':
    app.run(debug=True)
