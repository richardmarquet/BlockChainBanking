import datetime as date
from Block import Block

def create_gen_block():
    return Block(0, date.datetime.now(), "Genesis Block", "0")
	
blockchain = [create_gen_block()]
previous_block = blockchain[0]

num_of_blocks = 1

def next_block(last_block):
  this_index = last_block.index + 1
  this_timestamp = date.datetime.now()
  this_data = "Hey! I'm block " + str(this_index)
  this_hash = last_block.hash
  return Block(this_index, this_timestamp, this_data, this_hash)
  
def append_block():
  global previous_block
  block = next_block(previous_block)
  blockchain.append(block)
  previous_block = block
  print("Block #" + str(block.index) + " has been successfully added!")
  
def print_block_chain():
  for block in blockchain:
    print(block)
	
def getBlockData(hash):
	for block in blockchain:
	  if block.hash == hash:
	    return str(block.decrypt_data(block.private_key))
 
def proof_of_work(last_proof):
  incrementor = last_proof + 1
  
  while not (incrementor % 9 == 0 and incrementor % last_proof == 0):
    incrementor += 1
  
  return incrementor
  
def mine():
   last_block = blockchain[len(blockchain) - 1]
   last_proof = last_block.data['proof_of_work']
   
   proof = proof_of_work(last_proof)
   