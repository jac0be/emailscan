import datetime
from . import db
from sqlalchemy import select
import json
from ast import literal_eval

class Customer(db.Model):
    __tablename__ = 'customers'
    # customer ID
    id = db.Column(db.String(36), primary_key=True)
    # Email address as a string (user@domain)
    email = db.Column(db.String)
    
    def to_dict(self):
        return {
            'cid': self.id,
            'email' : self.email
        }
    def __repr__(self):
        return f'<Todo {self.id} {self.email}>'

class Email(db.Model):
    __tablename__ = 'emails'
    # Email ID, unique to all emails generated as UUIDv4 (36 charater string).
    # Passes a reference to the uuidv4 generator function, so it is called at runtime.
    id = db.Column(db.String(36), primary_key=True)

    # customer ID of the sender, foreign key (references Customer table)
    cid = db.Column(db.String(36), db.ForeignKey('customers.id'), nullable=False) # TODO: ADD FOREIGN KEY

    # MANDATORY Body query parameters
    metadata_ = db.Column(db.String, nullable=False)
    to = db.Column(db.String, nullable=False)
    from_ = db.Column(db.String, nullable=False)
    subject = db.Column(db.String, nullable=False)
    body = db.Column(db.String, nullable=False)

    # TODO: Should I change the default? Its called when stored
    created_at = db.Column(db.DateTime, nullable=False, 
                           default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow, 
                           onupdate=datetime.datetime.utcnow)
    
    domains = db.Column(db.String)
    
    status = db.Column(db.String)
    malicious = db.Column(db.Boolean)

    def to_dict(self):
        return {
            'id': self.id,
            'created_at': str(self.created_at.isoformat("T")) + "Z",
            'updated_at': str(self.updated_at.isoformat("T")) + "Z",
            'contents': {
                'to': self.to,
                'from': self.from_,
                'subject': self.subject
            },
            'status': self.status,
            'malicious': self.malicious,
            'domains':  literal_eval(self.domains),
            'metadata': {
                'spamhammer': self.metadata_
            }
        }
    
    def __repr__(self):
        return f'<Email {self.id} {self.from_}>'

# Domains table, we don't need it except for the domain report so whatever i guess
class Domains(db.Model):
    domain = db.Column(db.String, primary_key = True)
    email_id = db.Column(db.String, db.ForeignKey('emails.id'), primary_key = True)
    sender_id = db.Column(db.String, db.ForeignKey('customers.id'))
    to_address = db.Column(db.String)
    
    def __repr__(self):
        return f'<Domain {self.domain} {self.email_id}>'






