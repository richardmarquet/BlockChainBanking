from flask import Flask
from flask import send_file
from flask import request
from flask import render_template
#import genesis as blockchain
import datetime as date
import requests as req
from Block import Block
import json
import codecs

app = Flask(__name__)

this_nodes_transx = []
miner_addr = "q3nf394hjg-random-miner-address-34nf3i4nflkn3oi"

def create_gen_block():
    return Block(0, date.datetime.now(), "Genesis Block", "0")

blockchain = [create_gen_block()]
previous_block = blockchain[0]
#List of other blockchain ips
other_blockchains = ['192.168.1.77','192.168.1.64']

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
  return block

def print_block_chain():
  for block in blockchain:
    print(block)

def put_blockchain_in_json():
  blockList = []
  for block in blockchain:
    #format_data(codecs.decode(block.data, 'unicode_escape'))
    jblock = {
	   "index" : block.index,
	   "data" : str(block.data),
	   "timestamp" : str(block.timestamp),
	   "hash" : str(block.hash)
	}
    blockList.append(jblock)
  y = json.dumps(blockList)
  return y

def put_block_in_json(block):
  jblock = {
    "index" : block.index,
	"data" : str(block.data),
	"timestamp" : str(block.timestamp),
	"hash" : str(block.hash)
  }
  return jblock

def getBlockWithHash(hash):
  for block in blockchain:
	  if block.hash == hash:
	    return block

def getBlockDataWithHash(hash):
  block = getBlockWithHash(hash)
  return str(block.decrypt_data(block.private_key))

def proof_of_work(last_proof):
  incrementor = last_proof + 1

  while not (incrementor % 9 == 0 and incrementor % last_proof == 0):
    incrementor += 1

  return incrementor

def get_blockchains():
  blist = {}
  blist['blockchainIps'] = []
  for ip in other_blockchains:
    blist['blockchainIps'].append({
	  'ip' : ip
	})
  return json.dumps(blist)

def parse_json_ip_blockchains(jfile):
  data = json.loads(jfile)
  for bchains in data['blockchainIps']:
    print('IP: ' + bchains['ip'])


def call_blockchain_with_ip(ip, port, loc):
  url = ip + ":" + port + "/" + loc
  r = req.get(url)
  return r.json()

def get_blockchain_with_ip(ip, port):
  return call_blockchain_with_ip(ip, port, 'viewBlockchain')

def format_data(data):
  print("\nTHE FORMATED DATA -> ")
  t = codecs.encode(data)
  print(t)

#implement
def compare_blockchains(bchain1, bchain2):
  return ""

def sendFile(ip, port):
  with open('test.txt', 'rb') as f:
    r = req.post("http://192.168.1.64:8080/test", files={'test.txt' : f})
    print(r.text)

#ends here

@app.route('/addBlock', methods=['GET', 'POST'])
def addBlock():
  block = append_block()
  return put_block_in_json(block)

@app.route('/getBlockChains')
def getBlockchainIPS():
  parse_json_ip_blockchains(get_blockchains())
  return get_blockchains()

@app.route('/test', methods=["POST"])
def test():
  if request.method == "POST":
    f = request.files['test.txt']
    print(f.read())
    return "test"


@app.route('/getBlockInfo/<hash>')
def getBlockInfo(hash):
  return put_block_in_json(getBlockWithHash(hash))

@app.route('/getBlockData/<hash>')
def getBlockData(hash):
  s = getBlockDataWithHash(hash)
  return s

@app.route("/getBlockchain")
def giveBlockchain():
  return put_blockchain_in_json()

@app.route("/viewBlockchain")
def iter():
  sendFile('192.168.1.64','8080')
  blockchain[0].writeToFile()
  print_block_chain()
  return put_blockchain_in_json()
  #return "success!"

@app.route('/transx', methods=['POST'])
def transaction():
  if request.method == 'POST':
    new_transx = request.get_json()
    this_nodes_transx.append(new_transx)
    print("From: ", new_transx['from'])
    print("To: ", new_transx['to'])
    print("Amount: ", new_transx['amount'])
    return "Transaction submission successful!"

@app.route('/mine', methods=['GET'])
def mine():
   last_block = blockchain[len(blockchain) - 1]
   last_proof = last_block.data["proof_of_work"]

   proof = proof_of_work(last_proof)
   this_nodes_transx.append({"from" : "network", "to" : miner_addr, "amount": 1})
   new_block_data = {"proof_of_work" : proof, "transactions" : list(this_nodes_transx)}

   nexw_block_index = last_block.index + 1
   new_block_timestamp = date.datetime.now()
   last_block_hash = last_block.hash

   this_nodes_transx = []
   mined_block = Block(
     new_block_index,
	 new_block_timestamp,
	 new_block_data,
	 last_block_hash
   )
   blockchain.append(mined_block)
   return json.dumps({
      "index": new_block_index,
      "timestamp": str(new_block_timestamp),
      "data": new_block_data,
      "hash": last_block_hash
   }) + "\n"

#change depending on network and computer!
#port should be good tho
app.run(host='10.250.52.183', port=8080)
