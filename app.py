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
import hashlib

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

import random

import socket

app = Flask(__name__)

this_nodes_transx = []
miner_addr = "q3nf394hjg-random-miner-address-34nf3i4nflkn3oi"
#
users = []

#local_address = socket.gethostbyname(socket.gethostname())
#local_address = '10.250.85.46'
#print(local_address)

#myip = 'http://' + local_address + ':8080'

other_blockchains = ['http://10.250.14.33:8080', 'http://10.250.19.148:8080']
#change this
myip = 'http://10.250.85.46:8080'

#user data fabrication

def genUsers(numUsers):
  url = "http://ncrqe-qe.apigee.net/digitalbanking/db-accounts/v1/accounts/rf5ao6Qclwsth9OfOvUb-EeV1m2BfmTzUEALGLQ3ehU"

  querystring = {"hostUserId":"HACKATHONUSER100"}

  payload = ""
  headers = {
    'Authorization': "Bearer ME0CnxAeYAmWUNjQglBYyBVCPuHK",
    'transactionId': "fdd1542a-bcfd-439b-a6a1-5a064023b0ce",
    'Accept': "application/json",
    'cache-control': "no-cache",
    'Postman-Token': "6bc750cc-046f-4605-9e63-38249e5d0b00"
  }

  response = req.request("GET", url, data=payload, headers=headers, params=querystring)
  #print(response.text)
  baseJson = json.loads(response.text)
  print(baseJson['id'])

  for i in range(numUsers):
    baseJson['id'] = str(hashlib.sha224(str(random.randrange(0,10000000)).encode()).hexdigest())
	
    private_key = RSA.generate(1024)
    public_key = private_key.publickey()
   
    private_pem = private_key.export_key().decode()
    public_pem = public_key.export_key().decode()
	
    baseJson['pubkey'] = public_pem
    baseJson['privkey'] = private_pem
    baseJson['stamp'] = ""
	
    users.append(json.dumps(baseJson))

  for u in users:
    b = json.loads(u)
    #print(u)
    print(b['id'])
    print(b['pubkey'])
    print(b['privkey'])
    
	
def bytesToList(data):
  arr = []
  for a in data:
    arr.append(a)
  return arr

  
#for ajax stuff
@app.route('/createTransaction', methods=["POST"])
def transactionSR():
  if request.method == "POST":
    sender = findUserById(request.form['senderAccountID'])
    recv = findUserById(request.form['recipientAccountID'])
    transAmount = request.form['transactionAmount']
	
    public_pem = recv['pubkey']
    pk = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(key=pk)
    enc = cipher.encrypt(transAmount.encode())
    #enc = bytesToList(enc)	
    sendTransaction("", recv['pubkey'], recv['privkey'], enc, date.datetime.now(), sender['stamp'])
	
    return ":D"

#end of user data fabrication
def findUserById(id):
  for u in users:
    u = json.loads(u)
    if u['id'] == id:
      return u
#user stuff

  

#this will create the transaction by sending a post request of the info required to make a block
#it will then go an create a block using a post call!
def sendTransaction(hash, pub, priv, data, timestamp, stamp="", ip=myip):
  block = {
    'hash' : str(hash),
	'public_key' : str(pub),
	'private_key' : str(priv),
	'data' : bytesToList(data),
	'timestamp' : str(timestamp),
	'stamp' : str(stamp)
  }
  r = req.post(ip+'/addBlock', json=block)
  #print(r)
  #return json.dumps(r.text)
  
def decrypt(priv, data):
  pr_key = RSA.import_key(priv)
  decrypt = PKCS1_OAEP.new(key=pr_key)
  decrypted_message = decrypt.decrypt(bytes(data))
  
#end of user stuff

def convert_json_to_block(jb):
  block = Block(jb['index'],jb['timestamp'],jb['data'],jb['prev_hash'],"",True,jb['public_key'],jb['private_key'], jb['hash'])
  return block

def convert_json_to_blockchain(jbc):
  b = []
  jbc = json.loads(jbc)
  for jblock in jbc:
    b.append(convert_json_to_block(jblock))
  return b

def create_gen_block():
  if myip == 'http://10.250.85.46:8080':
    genUsers(10)
    return Block(0, date.datetime.now(), b'Genesis Block', "0")
  else:
    r = req.get('http://10.250.85.46:8080/getBlockchain')
    bchain = convert_json_to_blockchain(r.text)
    blockchain = bchain
    r = req.get('http://10.250.85.46:8080/getUsers')
    jfile = json.loads(r.text)
    for u in jfile:
      users.append(u)
    return blockchain[0]

blockchain = [create_gen_block()]
previous_block = blockchain[0]
#List of other blockchain ips


num_of_blocks = 1

def next_block(last_block, data, stamp="", old=False, public_pem="", private_pem="", hash=""):
  this_index = last_block.index + 1
  this_timestamp = date.datetime.now()
  #this_data = b"Hey! I'm block " + str.encode(str(this_index))
  this_hash = last_block.hash
  return Block(this_index, this_timestamp, data, this_hash, stamp, old, public_pem, private_pem, hash)
  
def append_block(data, stamp="", old=False, public_pem="", private_pem="", hash=""):
  global previous_block
  block = next_block(previous_block, data, stamp, old, public_pem, private_pem, hash)
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
    jblock = put_block_in_json(block)
    blockList.append(jblock)
  #print("LIST SIZE : " + str(blockList.size()))
  y = json.dumps(blockList)
  #print("JSON")
  #print(y)
  return y

def put_block_in_json(block):
  jblock = {
    "index" : block.index,
	"data" : block.bytesToList(),
	"timestamp" : str(block.timestamp),
	"public_key" : str(block.public_key),
	"private_key" : str(block.private_key),
	"prev_hash" : str(block.prev_hash),
	"hash" : str(block.hash),
	"msg" : str(block.decrypt_data(block.private_key))
  }
  return jblock

def getBlockWithHash(hash):
  for block in blockchain:
	  if block.hash == hash:
	    return block

def getBlockDataWithHash(hash):
  block = getBlockWithHash(hash)
  return str(block.decrypt_data(block.private_key))

def get_blockchains():
  #return json.dumps(other_blockchains)
  blist = {}
  blist['blockchainIps'] = []
  for ip in other_blockchains:
    blist['blockchainIps'].append({
	  'ip' : ip
	})
  return blist

#IP FILE OKAY  
def parse_json_ip_blockchains(jfile):
  #data = json.dumps(jfile)
  #return data
  print(jfile)
  data = json.dumps(jfile)

  for bchains in data:
    print("IP" + str(bchains))
	
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

def sendBlock(url,block):
  jblock = put_block_in_json(block)
  try:
    r = req.post(url+"/recvBlock",json=jblock)
  except req.exceptions.RequestException as e:
    print("error!")

def ip_json_to_list(jip):
  jip = json.loads(jip)
  arr = []
  for ip in jip:
    arr.append(ip)
  return arr
#ends here

def updateIps():
  print("OLD BLOCKCHAIN IP")
  print(other_blockchains)
  for ip in other_blockchains:
    try:
      r = req.get(ip + "/getBlockChains")
      print("the response")
      print(r)
      t = json.loads(r.text)
      print(t)
      #resp = ip_json_to_list(r.text)
      for i in range(len(t)):
        if t['blockchainIps'][i]['ip'] not in other_blockchains and t['blockchainIps'][i]['ip'] != myip:
          other_blockchains.append(t[i]['ip'])
    except req.exceptions.Timeout:
      print("timeout!")
    except req.exceptions.ConnectionError:
      print("error!")
    except req.exceptions.RequestException as e:
      print("error!")
  print("NEWWWWW")
  print(other_blockchains)
  
#Routes start here

@app.route('/addBlock', methods=['GET', 'POST'])
def addBlock():
  #you now need to get user data!!! send it in a json file
  #you will need: Hash, public key, private key, enc, timestamp, stamp
  #do error checking first. Check to see if blockchain is up to date/not corrupted

  if request.method == "POST":
    jblock = request.json
    print("jblock")
    print(jblock)
    #updateIps()
    blocks = []
    for ip in other_blockchains:
      if ip != myip:
        try:  
          r = req.get(ip + "/getLastBlock")
          resp = json.loads(r.text)
          b = convert_json_to_block(resp)
          blocks.append(b)
          print(b)
        except req.exceptions.RequestException as e:
          print("error!")
  
    count = 0
    for block in blocks:
      if block.hash != previous_block.hash:
        count += 1
    if count > 1:
      print("error detected. . .")
      print("correcting error. . .")
      for ip in other_blockchains:
        if ip != myip:
          r = req.get(ip + "/getBlockchain")
          bchain = convert_json_to_blockchain(r.text)
          blockchain = bchain
          break
    elif count == 1:
      print("error detected. . .")
      print("correcting error. . .")
	  #set new blockchain at the other blockchain
    else:
      print("no errors detected. . .")
      print("will append normally!")
  
  block = append_block(jblock['data'], jblock['stamp'], True, jblock['public_key'], jblock['private_key'], jblock['hash'])
  #send this block to every other blockchain
  for ip in other_blockchains:
    sendBlock(ip, block)
  return put_block_in_json(block)

@app.route('/getBlockChains')
def getBlockchainIPS():
  parse_json_ip_blockchains(other_blockchains)
  return get_blockchains()

@app.route('/recvBlock', methods=["POST"])
def recvBlock():
  jblock = request.json
  block = convert_json_to_block(jblock)
  print(jblock)
  blockchain.append(block)
  return jblock

@app.route('/recvBlockchain', methods=["POST"])
def recvBlockchain():
  jblockchain = request.json
  blockchain = convert_json_to_blockchain(jblockchain)
  print(blockchain[0])
  return "hm"

@app.route('/sendBlockchain')
def sendBlockchain():
  jbc = put_blockchain_in_json()
  try:
    r = req.post("http://10.250.19.148:8080/recvBlockchain", json=jbc)
  except req.exceptions.RequestException as e:
    print("error!")
  return "done"

@app.route('/getLastBlock')
def getLastBlock():
  return put_block_in_json(blockchain[len(blockchain)-1])

@app.route('/ncrtest')
def ncrtest():
  url = "http://ncrqe-qe.apigee.net/digitalbanking/db-accounts/v1/accounts"

  querystring = {"hostUserId":"HACKATHONUSER001"}

  payload = ""
  headers = {
    'Authorization': "Bearer ME0CnxAeYAmWUNjQglBYyBVCPuHK",
    'transactionId': "9e28bbea-d77d-4dd4-a4e1-c54ed3ec7738",
    'Accept': "application/json",
    'cache-control': "no-cache",
    'Postman-Token': "ee337072-530e-407b-bb50-c1c1f894a7c6"
  }

  response = req.request("GET", url, data=payload, headers=headers, params=querystring)

  return(response.text)

@app.route('/ncrtest2')
def genUserData():
  genUsers(10)
  return "YAY!"

@app.route('/sendBlock')
def sendBlockToIp():
  sendBlock("http://10.250.19.148:8080/recvBlock", blockchain[0])
  return "YOOOO"

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
  
@app.route("/getUsers")
def giveUsers():
  return json.dumps(users)

@app.route("/viewBlockchain")
def iter():
  #print_block_chain()
  #hash, pub, priv, data, timestamp, ip=myip
  data = b"jason"
  private_key = RSA.generate(1024)
  public_key = private_key.publickey()
   
  private_pem = private_key.export_key().decode()
  public_pem = public_key.export_key().decode()
   
  cipher = PKCS1_OAEP.new(key=public_key)
  enc = cipher.encrypt(data)
  enc = bytesToList(enc)
  
  sendTransaction(hash="", pub=public_pem, priv=private_pem, data=enc, timestamp=date.datetime.now())
  return put_blockchain_in_json()

@app.route('/ui/<senderAccountID>')
def ui(senderAccountID=None):
   return render_template('ui.html', senderAccountID=senderAccountID)

@app.route('/newPage')
def newPage():
   return render_template('newPage.html')

#change depending on network and computer!
#port should be good tho
app.run(host='10.250.85.46', port=8080)
