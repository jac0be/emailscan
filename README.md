# EmailScan

## Version: 1.1.0

SpamOverflow is an API service designed to scan malicious emails and provide comprehensive reports on malicious actors, their targets, and link domains utilized in these emails.

## Usage
The api is available for use at [http://emailscan.wilma.monster/api/v1](http://emailscan.wilma.monster/api/v1). See below for a list of endpoints and their respective functionalities.

## Email Service

### GET /customers/{customer_id}/emails

List all submitted emails for a given customer.

Returns a list of all emails submitted for the given customer id with optional filters applied. The limit and offset parameters are used for paging through the results.

All other parameters are used to filter the results and are applied before the limit and offset parameters.

#### Curl Request Example

curl -X GET
-H "Accept: application/json"
"http://emailscan.wilma.monster/api/v1/customers/{customer_id}/emails?limit=20&offset=0&start=2024-02-21T13:10:05Z&end=2024-02-21T14:10:05Z&from=no-reply@uq.edu.au&to=support@uq.edu.au&state=scanned&only_malicious=true"

#### Path Parameters

- `customer_id*`: String - The customer identifier (UUIDv4).

#### Query Parameters

- `limit`: Integer - Returns only this many results (0 < limit <= 1000). Default is 100.
- `offset`: Integer - Skip this many results before returning (0 <= offset). Default is 0.
- `start`: Date (date-time) - Only return emails submitted from this date (RFC3339 format).
- `end`: Date (date-time) - Only return emails submitted before this date (RFC3339 format).
- `from`: String (email) - Only return emails submitted from this email address.
- `to`: String (email) - Only return emails submitted to this email address.
- `state`: String - Only return emails with this state ('pending', 'scanned', 'failed').
- `only_malicious`: Boolean - Only return emails flagged as malicious.

#### Responses

- Status Code: 200 - List of all emails with applied filters.

### GET /customers/{customer_id}/emails/{id}

Get information for a particular email.

Returns a representation of an email for a customer with the status of the scan and its result.

#### Curl Request Example

curl -X GET
-H "Accept: application/json"
"http://emailscan.wilma.monster/api/v1/customers/{customer_id}/emails/{id}"

#### Path Parameters

- `customer_id*`: String - The customer identifier (UUIDv4).
- `id*`: String - The email identifier returned during creation.

#### Responses

- Status Code: 200 - Information about the requested email message.

### POST /customers/{customer_id}/emails

Post a new email scan request.

If the customer account does not exist, it will be created.

#### Curl Request Example

curl -X POST \
 -H "Accept: application/json" \
 -H "Content-Type: application/json" \
 "http://emailscan.wilma.monster/api/v1/customers/{customer_id}/emails" \
 -d '{
  "metadata" : {
    "spamhammer" : "1|14"
  },
  "contents" : {
    "subject" : "Important information about your account.",
    "from" : "support@uq.edu.au",
    "to" : "no-reply@uq.edu.au",
    "body" : "Dear customer,\nWe have noticed some suspicious activity on your account. Please click [here](https://scam-check.uq.edu.au?userId=uqehugh3) to reset your password."
  }
}'

#### Path Parameters

- `customer_id*`: String - The customer identifier (UUIDv4).

#### Body Parameters

- `metadata`: Object - Metadata for the email.
- `contents`: Object - The contents of the email.

#### Responses

- Status Code: 201 - The Email scan request has been successfully created.

### GET /customers/{customer_id}/reports/actors

Get malicious senders of emails.

Returns a list of all senders/actors identified as sending at least one malicious email.

#### Curl Request Example

curl -X GET
-H "Accept: application/json"
"http://emailscan.wilma.monster/api/v1/customers/{customer_id}/reports/actors"

#### Path Parameters

- `customer_id*`: String - The customer identifier (UUIDv4).

#### Responses

- Status Code: 200 - List of all senders/actors identified as sending at least one malicious email.

### GET /customers/{customer_id}/reports/domains

Get the domains that appeared in malicious emails.

Returns a report consisting of the link domains found in malicious emails for the given customer.

#### Curl Request Example

curl -X GET
-H "Accept: application/json"
"http://emailscan.wilma.monster/api/v1/customers/{customer_id}/reports/domains"

#### Path Parameters

- `customer_id*`: String - The customer identifier (UUIDv4).

#### Responses

- Status Code: 200 - A report consisting of the link domains found in malicious emails.

### GET /customers/{customer_id}/reports/recipients

Get users who have received malicious emails.

Returns a list of all recipients who have received at least one malicious email.

#### Curl Request Example

curl -X GET
-H "Accept: application/json"
"http://emailscan.wilma.monster/api/v1/customers/{customer_id}/reports/recipients"

#### Path Parameters

- `customer_id*`: String - The customer identifier (UUIDv4).

#### Responses

- Status Code: 200 - List of all recipients who have received malicious email.

### GET /health

Query the health of the service.

The health endpoint is useful for determining whether an instance is still healthy.

#### Curl Request Example

curl -X GET
"http://emailscan.wilma.monster/api/v1/health"

#### Responses

- Status Code: 200 - Service is healthy.
- Status Code: 500 - Service is not healthy.
- Status Code: 503 - Service is not healthy.
