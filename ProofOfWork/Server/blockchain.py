from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS



MINING_SENDER = "MINER 1"
MINING_REWARD = 1
MINING_DIFFICULTY = 2


class Blockchain:

    def __init__(self):
        
        # Initialising arrays
        self.transactions = []
        self.chain = []
        self.nodes = set()

        # Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        # Create genesis block (frist block in the blockchain)
        self.create_block(0, '00')


    # Add a new node to the nodes' list
    def register_node(self, node_url):
        
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)

        # Localising network address (www.xxxxxx.com:port/xxxx.html)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        # If it's a path accept it too 
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)

        # Else invalid node_url
        else:
            raise ValueError('Invalid URL')


    # If signature verified, add transaction to transactions array
    def submit_transaction(self, sender_public, receiver_public, value, signature):

        # Filling transaction data
        transaction = OrderedDict({'sender_public': sender_public, 
                                    'receiver_public': receiver_public,
                                    'value': value})

        # Adding transaction and returning length of the chain
        if sender_public == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1

        # Manages transactions from wallet to another wallet
        else:
            # Verifying signature
            transaction_verification = self.verify_transaction_signature(sender_public, signature, transaction)

            # Adding transaction and returning length of the chain
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            
            # If verifying failed, don't add anything
            else:
                return False


    # Check signature (it must correspond to the the transaction signed by the publick key)
    def verify_transaction_signature(self, sender_public, signature, transaction):

        # Getting binary data (string) from hexadecimal format and using as key
        public_key = RSA.importKey(binascii.unhexlify(sender_public))
        # Signer storage the signing scheme
        verifier = PKCS1_v1_5.new(public_key)
        # Produces the 160 bit digest of a message (transaction data or our dictionary)
        h = SHA.new(str(transaction).encode('utf8'))
        # Verifying the signature from the generated public key signature scheme and the original sender signature scheme (both must match)
        return verifier.verify(h, binascii.unhexlify(signature))

        
    # Adding block of transactions to the blockchain
    def create_block(self, nonce, previous_hash):

        # Filling the block data
        block = {'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': self.transactions,
                'nonce': nonce,
                'previous_hash': previous_hash}

        # Reset the current list of transactions
        self.transactions = []

        # Append and return block
        self.chain.append(block)
        return block


    # Creating a SHA-256 hash of block
    def hash(self, block):

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        # Hexadecimal string of the hashed block
        return hashlib.sha256(block_string).hexdigest()


    # Proof of work algorithm
    def proof_of_work(self):

        # Getting last block
        last_block = self.chain[-1]
        # Getting hash of the last block
        last_hash = self.hash(last_block)

        # A nonce is an arbitrary number that can only be used once
        nonce = 0

        # Iterate until finding the matching nonce number
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        # Return matching nonce
        return nonce


    # Check if a hash value satisfies the mining conditions
    def valid_proof(self, transactions, last_hash, nonce, difficulty = MINING_DIFFICULTY):

        # Encode: Return an encoded version of the string as a bytes object. Default encoding is 'utf-8'
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode()
        # Hexadecimal string of the hashed guess
        guess_hash = hashlib.sha256(guess).hexdigest()
        # Checking if first 'difficulty' characters in string are 0, the more 0 characters the more the complexity
        # The '*'' symbol means 'and' operator
        return guess_hash[:difficulty] == '0' * difficulty


    # Resolve conflicts between blockchain's nodes by replacing our chain with the longest one in the network.
    def resolve_conflicts(self):

        # Getting node
        neighbours = self.nodes
        # Initialising variable
        new_chain = None

        # We are only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node + '/chain')
            # Get response from that url ( node )
            response = requests.get('http://' + node + '/chain')

            # If everything ok
            if response.status_code == 200:
                # Getting length and chain
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    # If longer and validated then update max_length and new_chain
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
        	# Return transactions to the pool
        	is_returned = self.return_transactions_to_pool(new_chain)
        	# The chain becomes the new chain
        	self.chain = new_chain
        	return True

        # Return false in case that no conflict was found
        return False


	# Returning transactions to the pool, the new_chain input is for future improvements
    def return_transactions_to_pool(self, new_chain):
    	length = len(self.chain)
    	# We need to return transactions from the latest block in the self.chain not the new_chain
    	block = self.chain[length - 1]

    	# If the block is the same  as the block previous to the latest in our new_chain, there's no conflict. Just a new block was added
    	# Validating by nonce, for improvement it's necesary validate by hash
    	if block['nonce'] == new_chain[length - 1]['nonce']:
    		return False

    	# Removing mining reward transaction
    	transactions = block['transactions'][:-1]
    	# Adding transactions to the pool
    	for transaction in transactions: 
    		self.transactions.append(transaction)
    	return True


	# Check if a blockchain is valid
    def valid_chain(self, chain):
        
        # Initialising genesis block (the last one just for the first iteration)
        last_block = chain[0]
        # Initialising index in 1 (excluding genesis block)
        current_index = 1

        # Iterate thorugh every block in te chain
        while current_index < len(chain):

            # Current block
            block = chain[current_index]
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            # Delete the reward transaction (otherwise the hash will be different)
            transactions = block['transactions'][:-1]
            # Id names of other transaction elements
            transaction_elements = ['sender_public', 'receiver_public', 'value']
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            # Validating proof of work
            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                return False

            # Upadting index and previous block
            last_block = block
            current_index += 1
        # Return true if there was no anomalies
        return True


# Instantiate the Node
app = Flask(__name__)
CORS(app)


# Instantiate the Blockchain
blockchain = Blockchain()


# Index route
@app.route('/')
def index():
    return render_template('./index.html')


# Configure route
@app.route('/configure')
def configure():
    return render_template('./configure.html')


# Transactions route
@app.route('/transactions/new', methods=['POST'])
def new_transaction():

    # Getting form
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_public', 'receiver_public', 'amount', 'signature']
    if not all(k in values for k in required):
        # Returning error if values missing
        return 'Missing values', 400

    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(values['sender_public'], values['receiver_public'], values['amount'], values['signature'])

    # Validate transaction and return message
    if transaction_result == False:
        # If invalid or error
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        # Succesful transaction
        response = {'message': 'Transaction will be added to Block '+ str(transaction_result)}
        return jsonify(response), 201


# Get transactions route
@app.route('/transactions/get', methods=['GET'])

def get_transactions():
    # Get transactions from transactions pool
    transactions = blockchain.transactions
    # Return transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


# Chain route
@app.route('/chain', methods=['GET'])
def full_chain():
    # Return the chain and its length
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


# Mine route
@app.route('/mine', methods=['GET'])

def mine():
    # Validate if there are no transactions to add
    if not blockchain.transactions:
        print("There's no transactions to mine")
        return "Error: Please supply transactions to mine in order to create a new block", 400
    
    # We run the proof of work algorithm to get the next proof...
    # Getting the last block
    last_block = blockchain.chain[-1]
    # Finding the nonce (executing proof of work)
    nonce = blockchain.proof_of_work()

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(sender_public=MINING_SENDER, receiver_public=blockchain.node_id, value=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    # Create and return response
    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


# Register nodes route
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    # Getting values from form
    values = request.form
    # Removing space character and separate values with ',' character
    nodes = values.get('nodes').replace(" ", "").split(',')

    # If there's no nodes, it throws an error
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    # Register new nodes
    for node in nodes:
        blockchain.register_node(node)

    # Return the nodes
    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


# Solving problems through consensus
@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    # Asking and replacing chain if conflict exists
    replaced = blockchain.resolve_conflicts()

    # If chain was replaced fill the message and return the new chain
    if replaced:
        response = {
            'message': 'The chain was replaced',
            'new_chain': blockchain.chain
        }
    # Else keep the chain
    else:
        response = {
            'message': 'The chain is authoritative',
            'chain': blockchain.chain
        }

    # Return response
    return jsonify(response), 200


# Nodes route
@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    # Getting the nodes in the block chain
    nodes = list(blockchain.nodes)
    # Return the nodes
    response = {'nodes': nodes}
    return jsonify(response), 200


# If executing from console, using port 5000 as default and 127.0.0.1 as host address
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    # The user can specify another port with the console commnads -p or --port
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)

