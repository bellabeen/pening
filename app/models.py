from app import db

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    severity = db.Column(db.String(50))
    compliance_status = db.Column(db.String(20))
    security_control_id = db.Column(db.String(100))
    resource_id = db.Column(db.String(255))

    # New field: stores standard ID like "nist-800-53", "cis-aws", etc.
    standard_id = db.Column(db.String(100))  # ✅ A