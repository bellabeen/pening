from flask import Flask, jsonify
import boto3
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

@app.route('/securityhub/nist-summary', methods=['GET'])
def nist_compliance_summary():
    # Require AWS_REGION to be set
    region = os.getenv('AWS_REGION')
    if not region:
        return jsonify({'error': 'Environment variable AWS_REGION is not set'}), 500

    client = boto3.client('securityhub', region_name=region)
    NIST_STANDARD_ID = "standards/nist-800-53/v/5.0.0"

    findings = []
    next_token = None

    while True:
        params = {
            'Filters': {
                'ComplianceAssociatedStandardsId': [
                    {'Value': NIST_STANDARD_ID, 'Comparison': 'EQUALS'}
                ],
                'RecordState': [
                    {'Value': 'ACTIVE', 'Comparison': 'EQUALS'}
                ]
            },
            'MaxResults': 100
        }

        if next_token:
            params['NextToken'] = next_token

        response = client.get_findings(**params)
        findings.extend(response['Findings'])

        next_token = response.get('NextToken')
        if not next_token:
            break

    # Count compliance statuses
    status_counts = {
        'PASSED': 0,
        'FAILED': 0,
        'UNKNOWN': 0
    }

    for f in findings:
        status = f.get('Compliance', {}).get('Status', 'UNKNOWN').upper()
        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts['UNKNOWN'] += 1

    result = {
        'total_findings': len(findings),
        'compliance_summary': status_counts
    }

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)