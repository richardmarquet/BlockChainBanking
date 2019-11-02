
class User:
   def __init__(self, username, password, public_key):
     self.username = username
	 self.password = password
	 self.public_key = public_key
	 
   def __str__(self):
     return "Username: " + self.username