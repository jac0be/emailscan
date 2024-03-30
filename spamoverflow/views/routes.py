from flask import Blueprint, jsonify, request
import uuid
import re
from urllib.parse import urlparse
from spamoverflow.models import db
from spamoverflow.models.todo import Email, Customer, Domains
import subprocess
import json
from sqlalchemy import func
import datetime

api = Blueprint('api', __name__, url_prefix='/api/v1') 

@api.route('/health') 
def health():
    """Return a status of 'ok' if the server is running and listening to request"""
    return jsonify({"status": "ok"})

# Helper function to validate UUIDv4
def is_valid_uuid(uuid_str):
    try:
        uuid.UUID(uuid_str, version=4)
        return True
    except ValueError:
        return False

def is_valid_email(email_address):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email_address)

# Helper function to validate post request args
def is_valid_post_request(data):
    try :
        if not data:
            return False
        contents = data['contents']
        metadata = data['metadata']
        if not (contents and contents['to'] and contents['from'] and contents['subject'] and contents['body']):
            return False
        if not (metadata and metadata['spamhammer']):
            return False
        
        if not is_valid_email(contents['to']) or not is_valid_email(contents['from']):
            return False
    
        return True
    except:
        return False

# Helper function to scrape and store domains
def store_domains(email_id, body, from_, to):

    # Regular expression pattern to search urls
    url_pattern = re.compile(r'https?://\S+')

    # Find all urls
    urls = re.findall(url_pattern, body)

    # Store domains (set so unique only)

    domains = set()
    for url in urls:
        # Removes http?s and splits twice to remove subdomains
        domain = (re.sub(r'https?://', '', url).split('/')[0]).split('?')[0]
        if domain in domains:
            continue
        # Store in db to be used in domain report
        new_domain = Domains(
            domain= domain,
            email_id = email_id,
            sender_id = from_,
            to_address = to
        )
        db.session.add(new_domain)
        domains.add(domain)
    
    db.session.commit()

    return list(domains)

# Helper function to create a customer, if one does not exist
def create_customer(customer_id, email_address):
    
    existing_customer = Customer.query.get(customer_id)
    if existing_customer is not None:
        return
    else:
        new_customer = Customer(
            id = customer_id,
            email = email_address
        )
        db.session.add(new_customer)
        db.session.commit()

# Helper function to store a new email
# Also stores a customer if DNE.
def store_email(customer_id, metadata, contents):
    # Generate new uuidv4 for the email
    email_id = str(uuid.uuid4())
    # Create customer before creating email (foreign key)
    create_customer(customer_id, contents['from'])
    # Store domains found in email
    domains = store_domains(email_id, contents['body'], customer_id, contents['to'])

    input = {
        "id": email_id,
        "content": contents['body'],
        "metadata": metadata['spamhammer']
    }

    # Serialize input to json
    json_input = json.dumps(input)
    
    # Setup pipes and run commandline comand
    command = f"cat | spamoverflow/spamhammer-v1.0.0-linux-amd64 scan --input - --output -"
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True
    )

    # Send json input to the subprocess (ignore stderr)
    stdout, _ = process.communicate(json_input.encode())

    response = json.loads(stdout.decode())

    email = Email(
        id = email_id,
        cid = customer_id,
        metadata_ = str(metadata['spamhammer']),
        to = contents['to'],
        created_at = datetime.datetime.utcnow(),
        updated_at = datetime.datetime.utcnow(),
        from_ = contents['from'],
        subject = contents['subject'],
        body = contents['body'],
        status = 'scanned',
        domains = str(domains),
        malicious = response["malicious"]
    )

    db.session.add(email)
    db.session.commit()

    return email

# "POST" Submit a new email scan request
@api.route('/customers/<customer_id>/emails', methods=['POST'])
def create_email(customer_id):
    # Validate customer_id
    if not is_valid_uuid(customer_id):
        return jsonify({"error": "Invalid customer_id"}), 400
    # :TODO error 500
    try: 
        data = request.get_json()
        if not data or not is_valid_post_request(data):
            return jsonify({"error": "Request body is missing or not JSON"}), 400
        
        metadata = data['metadata']
        contents = data['contents']
        email = store_email(customer_id, metadata, contents)
        return json.dumps(email.to_dict(), indent=4), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 400

def is_valid_rfc3339(date_string):
    try:
        # Remove Z and replace with '+00:00' (copied from online)
        date_string = date_string.replace('Z', '+00:00')
        datetime.datetime.fromisoformat(date_string)
        return True
    except ValueError:
        return False

# "GET" All submitted emails for a given customer
@api.route('/customers/<customer_id>/emails', methods=['GET'])
def get_emails(customer_id):
    if not is_valid_uuid(customer_id):
            return jsonify({"error": "Invalid customer_id"}), 400
    
    # Get query args
    # We don't specifcy type or default as we do that in validation
    limit = request.args.get('limit')
    offset = request.args.get('offset')
    start = request.args.get('start')
    end = request.args.get('end')
    email_from = request.args.get('from')
    email_to = request.args.get('to')
    state = request.args.get('state')
    only_malicious = request.args.get('only_malicious')

    emails = None
    try:
        # Call helper function to fetch emails
        emails = fetch_emails(customer_id, limit, offset, start, end, email_from, email_to, state, only_malicious)
    except:
        return jsonify({"error": "Invalid query parameters"}), 400
    
    if emails == None:
        return jsonify({"error": "Invalid query parameters"}), 400
    # Return the fetched emails as JSON response
    return json.dumps(emails, indent=4), 200

# Helper function to fetch emails
def fetch_emails(customer_id, limit, offset, start, end, email_from, email_to, state, only_malicious):
    query = Email.query.filter_by(cid=customer_id)

    # Apply filters if provided
    # If filters provided but not valid, return None (will return 400 error see above)
    if start:
        if not is_valid_rfc3339(start):
            return None
        query = query.filter(Email.created_at >= datetime.datetime.fromisoformat(start.replace('Z', '+00:00')))
    if end:
        if not is_valid_rfc3339(end):
            return None
        query = query.filter(Email.created_at <= datetime.datetime.fromisoformat(end.replace('Z', '+00:00')))
    if email_from:
        if not is_valid_email(email_from):
            return None
        query = query.filter(Email.from_ == email_from)
    if email_to:
        if not is_valid_email(email_to):
            return None
        query = query.filter(Email.to == email_to)
    if state:
        if state not in ['pending', 'scanned', 'failed']:
            return None
        query = query.filter(Email.status == state)
    if only_malicious:
        if only_malicious.lower() not in ["true", "false"]:
            return None
        if only_malicious.lower() == "true":
            query = query.filter(Email.malicious == True)

    # Apply limit and offset
    # Apply int type conversion, if fails its invalid
    if limit:
        try:
            limit = int(limit)
            if limit <= 0 or limit > 1000:
                return None
        except:
            return None
    else:
        limit = 100
    if offset:
        try:
            offset = int(offset)
            if offset < 0:
                return None
        except:
            return None
    else:
        offset = 0

    query = query.limit(limit).offset(offset)

    # Execute final query and get all emails
    emails = query.all()

    return [email.to_dict() for email in emails]

# "GET" Information for a particular email
@api.route('/customers/<customer_id>/emails/<id>', methods=['GET'])
def get_email(customer_id, id):
    # Fetch the email information from the database
    if not is_valid_uuid(customer_id) or not is_valid_uuid(id):
        return jsonify({"error": "Invalid query parameters"}), 400
    
    email = None

    try:
        email = Email.query.filter_by(id=id, cid=customer_id).first()
    except:
        return jsonify({"error": "Invalid query parameters"}), 400
    
    if email is None:
        # If the email is not found, return 404 Not Found
        return jsonify({"404": "Email or Customer does not exist"}), 404

    return json.dumps(email.to_dict(), indent=4), 200

# "GET" REPORT: All senders of malicious emails (customer id is ignored)
@api.route('/customers/<customer_id>/reports/actors', methods=['GET'])
def get_malicious_actors(customer_id):
    # Query to group by sender email address and count the number of malicious emails
    # This is a complex query so call db directly.
    malicious_actors_query = db.session.query(
        Email.from_,
        func.count().label('count')
    ).filter(
        Email.malicious == True
    ).group_by(
        Email.from_
    ).all()
    
    malicious_actors = [
        {"id": actor[0], "count": actor[1]}
        for actor in malicious_actors_query
    ]

    # Generate current time
    generated_at = str(datetime.datetime.utcnow().isoformat("T")) + "Z"
    
    # Construct response
    response_data = {
        "generated_at": str(generated_at),
        "total": len(malicious_actors),
        "data": malicious_actors
    }
    
    return json.dumps(response_data, indent=4), 200

# "GET" REPORT: Domains that appeared in malicious emails, sent by the customer
@api.route('/customers/<customer_id>/reports/domains', methods=['GET'])
def get_malicious_domains(customer_id):
    # Fetch malicious domains for the given customer
    malicious_domains = fetch_malicious_domains(customer_id)
    
    # Generate current time
    generated_at = str(datetime.datetime.utcnow().isoformat("T")) + "Z"

    # Construct response
    response = {
        "generated_at": str(generated_at),
        "total": len(malicious_domains),
        "data": malicious_domains
    }
    
    return json.dumps(response, indent=4), 200

# Helper function to fetch malicious domains
def fetch_malicious_domains(customer_id):
    # Query to get malicious domains
    # Again complex query so use db
    malicious_domains_query = db.session.query(
        Domains.domain,
        func.count().label('count')
    ).join(
        Email,
        Email.id == Domains.email_id
    ).filter(
        Domains.sender_id == customer_id,
        Email.malicious == True,
        Email.domains != None
    ).group_by(
        Domains.domain
    ).all()

    # Construct the list of malicious domains and counts
    malicious_domains = [
        {
            "id": domain[0], 
            "count": domain[1]}
        for domain in malicious_domains_query
    ]
    
    return malicious_domains

# "GET" REPORT: Users who have received malicious emails, sent by the customer_id
@api.route('/customers/<string:customer_id>/reports/recipients', methods=['GET'])
def get_malicious_recipients(customer_id):
    recipients_query = db.session.query(
        Email.to,
        func.count().label('count')
    ).filter(
        Email.cid == customer_id,
        Email.malicious == True
    ).group_by(
        Email.to
    ).all()

    malicious_recipients = [
        {
            "id": recipient[0],
            "count": recipient[1]
        } for recipient in recipients_query
    ]

    # Generate current time
    generated_at = str(datetime.datetime.utcnow().isoformat("T")) + "Z"

    # Construct response
    response = {
        "generated_at": str(generated_at),
        "total": len(malicious_recipients),
        "data": malicious_recipients
    }

    return json.dumps(response, indent=4), 200




    