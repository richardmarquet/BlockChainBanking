import hashlib as hasher
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Block:
  def __init__(self, index, timestamp, data, prev_hash):
   private_key = rsa.generate_private_key(
	public_exponent=65537,
	key_size=2048,
	backend=default_backend()
   )
   public_key = private_key.public_key()
   data = data.encode()
   enc = public_key.encrypt(
	data,
	padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
		)
   )
	
   self.index = index
   self.timestamp = timestamp
   self.data = enc
   self.prev_hash = prev_hash
   self.hash = self.hash_block()
   self.public_key = public_key
   self.private_key = private_key

  def hash_block(self):
    sha = hasher.sha256()
    strHash = str(self.index) + str(self.timestamp) + str(self.data) + str(self.prev_hash)
    sha.update(strHash.encode())
    return sha.hexdigest()
	
  def decrypt_data(self, private_key):
    print(self.data)
    ogm = private_key.decrypt(
        self.data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ogm
	
  
  def writeToFile(self):
    with open('test.txt', 'w') as f:
      arr = []
      for a in self.data:
        arr.append(a)
        f.write(str(a))
      print("YOOOOOOOO\n")
      print(bytes(arr))
	
  def __str__(self):
    return "Index: " + str(self.index) + "\n" + "Timestamp: " + str(self.timestamp) + "\n"+ "Data: " + str(self.data) + "\n"+ "Prev Hash: " + str(self.prev_hash) + "\n" + "Hash: " + str(self.hash) + "\nPublic Key: " + str(self.public_key) + "\nReal MSG: " + str(self.decrypt_data(self.private_key))	+ "\n\n" 
