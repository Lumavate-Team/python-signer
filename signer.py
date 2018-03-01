from random import randint
import urllib.parse
import hashlib
import json
import time
import hmac
import sys
import base64

try:
  from flask import request
except:
  pass

class Signer:
  def __init__(self, public_key, private_key):
    self.public_key = public_key
    self.private_key = None

    if callable(private_key):
      try:
        self.private_key = private_key(public_key)
      except:
        self.private_key = None

    else:
      self.private_key = private_key

  def get_signed_url(self, method, url, body, headers):
    return self.get_signature(method, url, body, headers)['s-url']

  def get_signing_errors(self, method, url, body, headers):
    parsed_url = urllib.parse.urlparse(url)
    parsed_query = urllib.parse.parse_qs(parsed_url.query)
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
    except Exception as e:
      signing_errors.append('Invalid signing timestamp')

    if signature.get('s-nonce') is None:
      signing_errors.append('Missing nonce')
      # TODO - check if the nonce value has changed.  Use redis & cache
      # for 5 minutes to verify.  Key should be public key + nonce

    if parsed_query.get('s-signature', ['missing'])[0] != signature.get('s-signature'):
      signing_errors.append('Signature does not match')

    return signing_errors

  def get_request_signing_errors(self):
    return self.get_signing_errors(request.method.lower(), request.url, request.get_data(), request.headers)

  def get_signature(self, method, url, body, headers, forced_time=None, forced_nonce=None):
    md = hashlib.md5()

    if isinstance(body, (bytes, bytearray)):
      md.update(body)
    elif isinstance(body, dict):
      md.update(json.dumps(body).encode('utf-8'))
    elif body is None:
      md.update(''.encode('utf-8'))
    else:
      md.update(body.encode('utf-8'))

    body_md5 = md.hexdigest()

    parsed_url = urllib.parse.urlparse(url)
    parsed_query = urllib.parse.parse_qs(parsed_url.query)

    # For the sake of checking a signature, remove these calculated
    # parameters from the existing query string
    for p in ['s-key', 's-time', 's-hash', 's-signature', 's-nonce']:
      if p in parsed_query:
        del parsed_query[p]

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
    for p in parsed_query:
      full_parms[p] = ','.join(parsed_query[p])

    for p in additional_query:
      full_parms[p] = additional_query[p]

    qs = []
    for p in sorted(full_parms.keys()):
      qs.append('{}={}'.format(p, full_parms[p]))

    key = '{}\n{}\n{}\n{}'.format( \
        method.lower(),
        parsed_url.path.lower(),
        '&'.join(qs),
        additional_query['s-nonce'])

    del additional_query['s-hash']

    signature = base64.b64encode(hmac.new(str(self.private_key).encode('utf-8'), msg=key.encode('utf-8'), digestmod=hashlib.sha256).digest()).decode("utf-8")

    additional_query['s-signature'] = signature

    additional_query_string = '&'.join([k + '=' + urllib.parse.quote_plus(str(additional_query[k])) for k in additional_query])
    if '?' in url:
      signed_url = url + '&' + additional_query_string
    else:
      signed_url = url + '?' + additional_query_string

    additional_query['s-url'] = signed_url
    additional_query['s-hash'] = body_md5
    return additional_query

