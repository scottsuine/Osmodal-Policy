class Policy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(20), nullable=False)
    date = db.Column(db.Date, nullable=False)
    url = db.Column(db.String(500), nullable=False)
    reference_number = db.Column(db.String(50), nullable=False)
    assignments = db.relationship('PolicyAssignment', backref='policy', lazy=True) 