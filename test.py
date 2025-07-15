import boto3
import csv

# Initialize client
client = boto3.client('securityhub', region_name='ap-southeast-1')

# Standard ID for NIST 800-53 Rev. 5
NIST_STANDARD_ID = "standards/nist-800-53/v/5.0.0"

# Pagination
findings = []
next_token = None

print("🔍 Fetching Security Hub findings for NIST 800-53 Rev. 5...")

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

print(f"✅ Total findings fetched: {len(findings)}")

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

print("\n📊 Compliance Status Summary:")
for status, count in status_counts.items():
    print(f"{status:<7}: {count}")

# ➕ Export findings to CSV
csv_filename = "nist80053_findings.csv"
with open(csv_filename, mode='w', newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    # CSV header
    writer.writerow([
        'Title', 'Description', 'Severity', 'ComplianceStatus',
        'SecurityControlId', 'ResourceId', 'Remediation', 'Region'
    ])

    for f in findings:
        writer.writerow([
            f.get('Title', ''),
            f.get('Description', '').replace('\n', ' ').strip(),
            f.get('Severity', {}).get('Label', ''),
            f.get('Compliance', {}).get('Status', ''),
            f.get('Compliance', {}).get('SecurityControlId', ''),
            f.get('Resources', [{}])[0].get('Id', ''),
            f.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
            f.get('Region', '')
        ])

print(f"\n📄 Exported to {csv_filename}")
