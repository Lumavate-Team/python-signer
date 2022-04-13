"""URL signing/checking functionality"""
# pylint: disable=too-many-arguments,too-many-locals
from random import randint
import urllib.parse
import hashlib
import json
import time
import hmac
import base64

try:
  from flask import request
except: # pylint: disable=bare-except
  pass

class Signer:
  """All behavior required to assign signatures to urls based on public/private keys"""
  def __init__(self, public_key, private_key):
    self.public_key = public_key
    self.private_key = None

    if callable(private_key):
      try:
        self.private_key = private_key(public_key)
      except: # pylint: disable=bare-except
        self.private_key = None

    else:
      self.private_key = private_key

  def get_signed_url(self, method, url, body, headers):
    """Calculate the signature and return the signed url"""
    return self.get_signature(method, url, body, headers)['s-url']

  def get_signing_errors(self, method, url, body, headers):
    """Calculate the signature and compare to the given signature, returning errors if needed"""
    parsed_url = urllib.parse.urlparse(url)
    parsed_query = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
    signature = self.get_signature( \
        method,
        url,
        body,
        headers,
        forced_time=parsed_query.get('s-time', [0])[0],
        forced_nonce=parsed_query.get('s-nonce', [-1])[0])

    signing_errors = []

    if signature.get('s-signature') is None:
      signing_errors.append('Missing signature')

    if signature.get('s-key') is None:
      signing_errors.append('Missing Public Key')

    if self.private_key is None:
      signing_errors.append('Invalid Public Key')

    if signature.get('s-time') is None:
      signing_errors.append('Missing signing timestamp')

    if 's-hash' in parsed_query and signature.get('s-hash') != parsed_query.get('s-hash')[0]:
      signing_errors.append('Hash does not match')

    try:
      signed_time = int(signature.get('s-time'))
      now = int(time.time())
      if abs(now - signed_time) > 300:
        signing_errors.append('Signing timestamp too old')
    except Exception: # pylint: disable=broad-except
      signing_errors.append('Invalid signing timestamp')

    if signature.get('s-nonce') is None:
      signing_errors.append('Missing nonce')

    if parsed_query.get('s-signature', ['missing'])[0] != signature.get('s-signature'):
      signing_errors.append('Signature does not match')

    return signing_errors

  def get_request_signing_errors(self):
    """Check if the current request (in context) has been properly signed"""
    forward_host = next((value for (key, value) in request.headers if key.lower() == 'x-forwarded-host'), None)
    derived_url = request.url.replace(request.host, forward_host) if forward_host else request.url
    
    return self.get_signing_errors(
        request.method.lower(),
        derived_url,
        request.get_data(),
        request.headers)

  def get_signature(self, method, url, body, headers, forced_time=None, forced_nonce=None):
    """Calculate a request signature based on given context"""
    # pylint: disable=too-many-branches,unused-argument
    hasher = hashlib.md5()

    if isinstance(body, (bytes, bytearray)):
      hasher.update(body)
    elif isinstance(body, dict):
      hasher.update(json.dumps(body).encode('utf-8'))
    elif body is None:
      hasher.update(''.encode('utf-8'))
    else:
      hasher.update(body.encode('utf-8'))

    body_md5 = hasher.hexdigest()

    parsed_url = urllib.parse.urlparse(url)
    parsed_query = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)

    # For the sake of checking a signature, remove these calculated
    # parameters from the existing query string
    for parm in ['s-key', 's-time', 's-hash', 's-signature', 's-nonce']:
      if parm in parsed_query:
        del parsed_query[parm]

    additional_query = {
        's-key': self.public_key,
        's-time': str(int(time.time())),
        's-hash': body_md5,
        's-nonce': randint(0, 1000000000),
    }

    # For the sake of checking a signature, allow the time & none value to be
    # passed directly in rather than calculated
    if forced_time is not None:
      additional_query['s-time'] = forced_time

    if forced_nonce is not None:
      additional_query['s-nonce'] = forced_nonce

    full_parms = {}
    for parm in parsed_query:
      full_parms[parm] = ','.join(parsed_query[parm])

    for parm in additional_query:
      full_parms[parm] = additional_query[parm]

    query_string = []
    for parm in sorted(full_parms.keys()):
      query_string.append('{}={}'.format(parm, full_parms[parm]))

    key = '{}\n{}\n{}\n{}'.format( \
        method.lower(),
        parsed_url.path.lower(),
        '&'.join(query_string),
        additional_query['s-nonce'])

    del additional_query['s-hash']

    signature = base64.b64encode(
        hmac.new(
            str(self.private_key).encode('utf-8'),
            msg=key.encode('utf-8'),
            digestmod=hashlib.sha256).digest()
        ).decode("utf-8")

    additional_query['s-signature'] = signature

    additional_query_string = '&'.join(
        [k + '=' + urllib.parse.quote_plus(str(additional_query[k])) for k in additional_query])

    if '?' in url:
      signed_url = url + '&' + additional_query_string
    else:
      signed_url = url + '?' + additional_query_string

    additional_query['s-url'] = signed_url
    additional_query['s-hash'] = body_md5
    return additional_query
