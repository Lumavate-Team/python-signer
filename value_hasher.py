import json
from hashlib import blake2b
from hmac import compare_digest

class ValueHasher:
  AUTH_SIZE = 16

  def __init__(self, private_key):
    self.private_key = private_key

  def sign(self, value):
    h = blake2b(digest_size=self.AUTH_SIZE, key=self.private_key.encode('utf-8'))

    if isinstance(value, (bytes, bytearray)):
      h.update(value)
    elif isinstance(value, dict):
      h.update(json.dumps(value).encode('utf-8'))
    elif value is None:
      h.update(''.encode('utf-8'))
    else:
      h.update(value.encode('utf-8'))

    return h.hexdigest() #.encode('utf-8')

  def verify(self, value, signature):
    good_signature = self.sign(value)
    return compare_digest(good_signature, signature)
