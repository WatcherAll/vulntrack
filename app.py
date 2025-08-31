# This app uses CISA Api as a vulnerability tracker, so credits to them.
# We're still improving so please be gentle and kind with us. We plan to make a server.
import requests
import json
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

CISA_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    try:
        response = requests.get(CISA_API_URL)
        response.raise_for_status() 
        data = response.json()
        
        vulnerabilities = []
        for vulnerability in data.get('catalog', []):
            vulnerabilities.append({
                'name': vulnerability.get('cveID', 'N/A'),
                'affected': vulnerability.get('vendorProject', 'N/A') + ' ' + vulnerability.get('product', 'N/A'),
                'priority': 'Critical',
                'action': 'Patch by: ' + vulnerability.get('dateAdded', 'N/A'),
                'last_updated': vulnerability.get('dateAdded', 'N/A')
            })
            
        return jsonify(vulnerabilities)

    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
        
if __name__ == '__main__':
    app.run(debug=True)
