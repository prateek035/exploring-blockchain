import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse


class BlockChain:

    def __init__(self):

        self.chain = []
        self.transactions = []
        #Genesis Block
        self.create_block(proof = 1, previous_hash = '0') 
        self.nodes = set()


    def create_block(self, proof, previous_hash):

        # add key with data field if you want.
        # proof of work is called nonce
        block = {
            'index' : len(self.chain) + 1, 
            'timestamp' : str(datetime.datetime.now()),
            'proof' : proof,
            'previous_hash' : previous_hash,
            'transactios' : self.transactions
        }
        self.transactions = []
        self.chain.append(block)
        return block

    
    def get_previous_block(self):

        return self.chain[-1]

    # Proof is work is hard to find but easy to verify.
    def proof_of_work(self, previous_proof):
        
        new_proof = 1
        #Check with the target.
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        
        return new_proof


    #  @Return : CryptoGraphic hash of the entire block.

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    
    def is_chain_valid(self, chain):
        
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            current_block = chain[block_index]
            if current_block['previous_hash'] != self.hash(previous_block):
                return False

            # Check if proof of each block is valid.
            previous_proof = previous_block['proof']
            current_proof = current_block['proof']
            hash_operation = hashlib.sha256(str(current_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            
            previous_block = current_block
            block_index += 1

        return True


    def add_transaction(self, sender, reciever, amount):
        self.transactions.append({
            'sender' : sender,
            'reciever' : reciever,
            'amount' : amount
        })

        # Upcoming block will be added after the last index of current chain
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    
    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)

        for node in network:
            response = requests.get(f'http://{node}/get-chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        
        if longest_chain:
            self.chain = longest_chain
            return True





app = Flask(__name__)

# creating an address for the node on Port 5000
node_address = str(uuid4()).replace('-', '')


blockChain = BlockChain()

@app.route('/mine-block', methods = ['GET'])
def mine_block():
    
    previous_block = blockChain.get_previous_block()
    previous_proof = previous_block['proof']

    proof = blockChain.proof_of_work(previous_proof)
    previous_hash = blockChain.hash(previous_block)

    blockChain.add_transaction(sender = node_address, reciever = 'User2', amount = 3)

    block = blockChain.create_block(proof, previous_hash)
    response = {
        'messgae' : 'Woohoo, Successfully mined a block !!!',
        'index' : block['index'],
        'timestamp' : block['timestamp'],
        'proof' : block['proof'],
        'previous_hash' : block['previous_hash'],
        'transactions' : block['transactios']
    }

    return jsonify(response), 200

@app.route('/get-chain', methods = ['GET'])
def get_chain():
    
    response = {
        'chain' : blockChain.chain,
        'length' : len(blockChain.chain)
    }

    return jsonify(response), 200

@app.route('/add-transaction', methods = ['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'reciever', 'amount']
    if not all (key in json for key in transaction_keys):
        return "Some element of transaction are missing", 400
    index = blockChain.add_transaction(json['sender'], json['reciever'], json['amount'])
    response = {'message' : f'This transaction will be added to Block {index}'}
    return jsonify(response), 201


@app.route('/connect-node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockChain.add_node(node)
    response = {
        'message' : f'All the nodes are connected, The TeekCoin BlockChain now contains the following nodes : ', 
        'total_nodes' : list(blockChain.nodes)
    }
    return jsonify(response), 201


@app.route('/replace-chain', methods = ['GET'])
def replace_chain():
    is_chain_replaced = blockChain.replace_chain()
    if is_chain_replaced:
        response = {
            'message' : 'Chain was replaced by longer one.',
            'chain' : blockChain.chain
        }
    else:
        response = {
            'message' : 'All good, Chain was the largest one.',
            'chain' : blockChain.chain
        }
    return jsonify(response), 200




app.run(host = '0.0.0.0', port = 5002)