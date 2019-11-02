from app import app
from flask import render_template
import genesis as blockchain

@app.route('/addChain')
def addChain():
  blockchain.append_block()
  return "success!"
  
@app.route("/viewBlockchain")
def iter():
  blockchain.print_block_chain()
  return "success!"
