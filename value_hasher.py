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
      sorted_value = self.__get_sorted_dict(value)
      encoded_value = json.dumps(sorted_value).encode('utf-8')
      h.update(encoded_value)
    elif value is None:
      h.update(''.encode('utf-8'))
    else:
      h.update(value.encode('utf-8'))

    return h.hexdigest() #.encode('utf-8')

  def verify(self, value, signature):
    good_signature = self.sign(value).encode('utf-8')
    return compare_digest(good_signature, signature)

  def __get_sorted_dict(self, value):
    result = {}
    for k, v in sorted(value.items()):
      if isinstance(v, dict):
        result[k] = self.__get_sorted_dict(v)
      else:
        result[k] = v
    return result
