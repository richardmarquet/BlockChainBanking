import hashlib as hasher
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

class Block:
  def __init__(self, index, timestamp, data, prev_hash, stamp="", old=False, public_pem="", private_pem="", hash=""):
    if not old:
      private_key = RSA.generate(1024)
      public_key = private_key.publickey()
   
      private_pem = private_key.export_key().decode()
      public_pem = public_key.export_key().decode()
   
      cipher = PKCS1_OAEP.new(key=public_key)
      enc = cipher.encrypt(data)
      self.data = enc
	
    self.index = index
    self.timestamp = timestamp
    if old:
      self.data = data
    self.prev_hash = prev_hash
    if not old or hash == "":
      self.hash = self.hash_block()
    else:
      self.hash = hash
    self.public_key = public_pem
    self.private_key = private_pem
    self.stamp = stamp

  def hash_block(self):
    sha = hasher.sha256()
    strHash = str(self.index) + str(self.timestamp) + str(self.data) + str(self.prev_hash)
    sha.update(strHash.encode())
    return sha.hexdigest()
	
  def bytesToList(self):
    arr = []
    for a in self.data:
      arr.append(a)
    return arr
	  
  def listToBytes(self, arr):
    return bytes(arr)
	
  def decrypt_data(self, private_key):
    pr_key = RSA.import_key(self.private_key)
    decrypt = PKCS1_OAEP.new(key=pr_key)
    print(self.data)
    decrypted_message = decrypt.decrypt(self.listToBytes(self.data))
    return decrypted_message
	
  def __str__(self):
    return "Index: " + str(self.index) + "\n" + "Timestamp: " + str(self.timestamp) + "\n"+ "Data: " + str(self.data) + "\n"+ "Prev Hash: " + str(self.prev_hash) + "\n" + "Hash: " + str(self.hash) + "\nPublic Key: " + str(self.public_key) + "\nReal MSG: " + str(self.decrypt_data(self.private_key))	+ "\n\n" 
