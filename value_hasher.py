from hashlib import blake2b
from hmac import compare_digest

class ValueHasher:
  AUTH_SIZE = 16

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

  def sign(self, value):
    h = blake2b(digest_size=self.AUTH_SIZE, key=self.private_key)

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
