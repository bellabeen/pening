import os
from flask import Blueprint, render_template, request, Response
from app.models import Finding
from app import db
import boto3
import csv
import io
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Define the Blueprint
securityhub_bp = Blueprint('securityhub', __name__)

@securityhub_bp.route('/')
def dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    findings = Finding.query.paginate(page=page, per_page=per_page)

    # Count statuses
    status_counts = {'PASSED': 0, 'FAILED': 0, 'UNKNOWN': 0}
    for f in Finding.query.all():
        status = f.compliance_status.upper() if f.compliance_status else 'UNKNOWN'
        if status in status_counts:
            status_counts[status] += 1
        else:
            status_counts['UNKNOWN'] += 1

    summary = {
        "total_findings": Finding.query.count(),
        "compliance_status": status_counts,
        "passed": status_counts["PASSED"],
        "failed": status_counts["FAILED"],
        "unknown": status_counts["UNKNOWN"]
    }

    return render_template(
        'dashboard.html',
        findings=findings,
        summary=summary
    )

def fetch_findings_from_aws():
    # Get region from environment variable
    region = os.getenv('AWS_REGION')
    if not region:
        raise RuntimeError("❌ Environment variable AWS_REGION is not set.")

    # Boto3 client
    client = boto3.client('securityhub', region_name=region)

    NIST_STANDARD_ID = "standards/nist-800-53/v/5.0.0"
    all_findings = []
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

        for f in response['Findings']:
            finding = Finding(
                title=f.get('Title', ''),
                description=f.get('Description', ''),
                severity=f.get('Severity', {}).get('Label', ''),
                compliance_status=f.get('Compliance', {}).get('Status', ''),
                security_control_id=f.get('Compliance', {}).get('SecurityControlId', ''),
                resource_id=f.get('Resources', [{}])[0].get('Id', ''),
                standard_id=NIST_STANDARD_ID
            )
            all_findings.append(finding)

        next_token = response.get('NextToken')
        if not next_token:
            break

    return all_findings

@securityhub_bp.route('/export')
def export_csv():
    standard = request.args.get('standard', 'nist-800-53')

    findings = Finding.query.filter_by(standard_id=standard).all()

    # Prepare CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Title', 'Description', 'Severity', 'Compliance Status', 'Control ID', 'Resource ID'])

    # Write data rows
    for f in findings:
        writer.writerow([
            f.title,
            f.description,
            f.severity,
            f.compliance_status,
            f.security_control_id,
            f.resource_id
        ])

    # Prepare HTTP response with CSV
    output.seek(0)
    return Response(
        output,
        mimetype='text/csv',
        headers={
            "Content-Disposition": f"attachment; filename={standard}_findings.csv"
        }
    )
