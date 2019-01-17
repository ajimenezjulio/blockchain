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
import pprint

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS



MINING_SENDER = "MINER 1"
MINING_REWARD = 1
MINING_DIFFICULTY = 2

PUBLIC_KEYS = ["30819f300d06092a864886f70d010101050003818d0030818902818100d8982d41166cd0e4e651c28ed552e01a6ad726eb18b254b711033f70a6a11f16aa029ee28ec336442e6ae30d7c9fc1a845d0e422a455fc52b2a3b155b5523f0fa9c778f7abc7752b63a5423a827bbc7388151fca845fd3c727c7d67d5e4d590b7af8de3e07aabb950b805a7c8382f2904a2fa68e8fad55c8a0f57b3ec0b33a750203010001", "30819f300d06092a864886f70d010101050003818d0030818902818100a9c31ef7ff9ef6eb37f4fd22487565d5bb3c187caf75dd7b3b06e07f4d91a880ed17fa8c80f265b6e76ae2a87def528b7c4fa9229cfce16344b916655d0ffd8e5f3852bb0dc23a26c97793a714338891292dcaab4a3d90f312550600d2bf62b43b9057117959d257285601aa957e7b7e51e95c5250bddbea2d0cf3c592f2af830203010001", "30819f300d06092a864886f70d010101050003818d0030818902818100cae6def2221351b560b432b2601a2e43dcc49803f4423ca78d22cd3ca1783b73c137ca7f5a1ebf7e4423f542ee5426659e9379da0e265ced91da459027a94b9949efb4f1194544be1fc2b3548f94f65e530317db698850593b8a61310de42eeaf0e484d07eaca9d6f235e8550f3801a7a0e2f8e7b04451b0faf5bd012908f8050203010001", "30819f300d06092a864886f70d010101050003818d0030818902818100b64ebfe6463c284b01b4afaac8ebd7c9071a9ad18bd26cadc79229759fe2ca15a5f36b35f1dcd9387277127d405fd6de532c570ece44490ca3a4741a37e79d0c4d17557a7dae2b72358b21fb8a200f7f580924194f5282091ba666b7a23510790724bcbd8a4de8fd8d752329689d0d03d9cfcec6cb59d8b13be81efc9b309e990203010001"]
PRIVATE_KEYS = ["3082025b02010002818100d8982d41166cd0e4e651c28ed552e01a6ad726eb18b254b711033f70a6a11f16aa029ee28ec336442e6ae30d7c9fc1a845d0e422a455fc52b2a3b155b5523f0fa9c778f7abc7752b63a5423a827bbc7388151fca845fd3c727c7d67d5e4d590b7af8de3e07aabb950b805a7c8382f2904a2fa68e8fad55c8a0f57b3ec0b33a7502030100010281800fb7db70e1c3bbd520b1c640bf526859026fe2af24f7ac162cf1e364b572f3e29d2bdb83ed80552bd582843fb24f95aa3486d8477b4d92261e38aae1e16aba90b235bf58f5fffd9432673083f05603da5bdd1c339a8560ff87938cc41e1679455d7c3d9e9c8f44ff15e10757dcb618da2e2ff661d90216122ffe3566afd73801024100e0463c7e39912b7cb6fd544dc42f6238ca2fc1a2ad707e9934cc72c4d50011cc38f5a27e1b8ff2475423135045d64ea79a4496b1dcfc2808f02668866f746b81024100f73bd2d40491d0e2907bd9847d2b9d99b518d29928e9f9d726464c4531884e938284ae5ad37558c95cede6057b93cbb9cd4cc7da25ab6a3c3e0768944b5458f50240555102c435dc0ec203cebd1a544e7e3c025646803f2073588ee853a4a32ec29680f89897069f2cd88b9e48439a3d9b7050d454cb56b8a9f6347d37f8244012810240012b6145eb779d1b553fa0b9c5b5cd1b0b064108c46ec6e5c3a2957dc64c34c2f1dd1ace072e08eb7aeb0d297d7a277e8b800f79f2afaae2fa1022e880aab7790240790f78d57e65f211fff15f74ed2cd9901d0f77bb22587d9a8ae652fad8f2347c0ff695a17e2e774e1a4680523e1e7c717986bc01dc15bb4c39667bcfad3625ab", "3082025c02010002818100a9c31ef7ff9ef6eb37f4fd22487565d5bb3c187caf75dd7b3b06e07f4d91a880ed17fa8c80f265b6e76ae2a87def528b7c4fa9229cfce16344b916655d0ffd8e5f3852bb0dc23a26c97793a714338891292dcaab4a3d90f312550600d2bf62b43b9057117959d257285601aa957e7b7e51e95c5250bddbea2d0cf3c592f2af8302030100010281804d5e2bc302b0c3ffb764e3e8b7f529101b60ec18072f445d612d652b1f82feb4a359864a7a89fe693956b12df1171d1b8cf01139412acedd9af86f888abd3ae4e5e1fd540b186d4cb920c85c06e3eb53584fb8803475e2e0128bb2c01d6599558cfccf581808ea1806745f7c09cb047283517605dc0375bc4bea40d9ae6419c1024100ceb0acf210df62d370701d2f969cfee6f2c148f2ab076d63e7aedb216503f1cbbad1c367ccd6945e0d61b9ddd5b9018f3ca1ac63209a210b55b860aa2b4cdd09024100d2431eca755b4ff6360bdf67596268242a1fb40447644a8608ea58fc91a5b73b7c2a16d38a49d505689abf72b5384f2257098d84d2308989a17b7b0a44efd72b024100c8645b09467a8ea2593d19ceedc3c10fc104cce91a10d56a2b52487a9429c2e0b77c706bcf19ac3793d9d00ed80bcb0b48c9a70d64aa8aa726b0e0679c1ba5a102400aff7fc8cf42ab781173a587de610b5978ea979bf1b00945e1898086158839815f094490641760911bdb9c4fffb2a65101847a668c2805c9b12ca84eed342e690240690f4b5d06e996aff2ab0d9785c9de76a576e7c0179ed69ef5aa177c3be32a027bdc94f8ff95a6064a86766afff1ebcce632249353b9899d08362e03aecaf9f4", "3082025e02010002818100cae6def2221351b560b432b2601a2e43dcc49803f4423ca78d22cd3ca1783b73c137ca7f5a1ebf7e4423f542ee5426659e9379da0e265ced91da459027a94b9949efb4f1194544be1fc2b3548f94f65e530317db698850593b8a61310de42eeaf0e484d07eaca9d6f235e8550f3801a7a0e2f8e7b04451b0faf5bd012908f8050203010001028181008f4127c16edb9301eb4feec74fe0cc2f6fac81e3b0ce1f42f0fbd449ed7b1506aa31b8cfe791f403b31a6c2ca0565b71bddf43d5f7cd9028cfa47b1ec751d92412e6715915fb5b174bf2d944b084cc0f0c3f9c3d6219326b8809d65ea345eb21e6ddfd0f8bc4dab6d73a4be026b6654569fe02509328d59f5f2b6f7ef26b5e55024100cf07e7061bad14b4646b136f2fb5eecc6fd849ba62913ec8651ec2101dd2aa94104a9d7f42f3e6d37b4f3360c3e1f754185d66d895179e23ba33cbe6f950bb57024100fae4f2baa50c45d2665ad7e7c1343650dc5a5825573d81d193ea8de7299d9e08ab0e9bf01a7f01093252d5fb475ae8bd220cb9acc5b013206ed5970a4669aa0302400313acfd4c400044c6114952a7b4de7daf53d994a98e5b0e836237a421ad55d7a97e5264e7cbd42c6472c2e2b7468e7473803fdd0c2a33b1783cf8d4cff3c135024100e3c96bab136052201537d32021a472cff54fbd09a1ec40e9f35e9819510a3e49e66c2c1dd1208fe336a2488e8c19388746dbc0d3e0e3dc69acd714fb8a3432db024100b8f61ac96ce336bf44a7b96f1e73bd76a3f85ac255b95da04975393362fc13edde70c6fec0e93a55e5107eac2977764ae712c7e95ec39250e64a4395878a7849", "3082025c02010002818100b64ebfe6463c284b01b4afaac8ebd7c9071a9ad18bd26cadc79229759fe2ca15a5f36b35f1dcd9387277127d405fd6de532c570ece44490ca3a4741a37e79d0c4d17557a7dae2b72358b21fb8a200f7f580924194f5282091ba666b7a23510790724bcbd8a4de8fd8d752329689d0d03d9cfcec6cb59d8b13be81efc9b309e9902030100010281810080bf6ea0a65b57ad59000ccb54e7d1d5a391b36267176d2ef0f1151c7f94bf58b88106e6eaef27ecc851b51a057b69984b2ed6309b94f7edd8278ce2f3363bdec1bd953c2050ba7182612b51eddc3ac6eb7f4d77ca2ded3f19999aab103c7f0a0140ae7749b8b6919b67a5a7c0775f8b283e6b5607bce694ffa8d80ae8dd23b1024100d020e4462c365a7a363798623548cc3b5f7914a2044b2717e4ec96d009013ca843fc82d9d295bf41875727dfdf21a3c5fb5794a117989786c0b3d5b3fe9b4955024100e03d767a29bd01db8bc1005a5fda433e1866269a397801b0da8cda679b762c28274ba6404f07d3beadd3ae490e1e896f8ff92d955d8a67d01b185dd11820b035024049b98d032a802a76a623f56fbc6e48223404a1016f41ebdc33f476cbc494d296cc56734793a805f2c16d672b8f4fcc42c270d8ae63bc62d89204620bfb81a86d0240676f32754b4769d1f1770748a8aa2f16377ef71370aad06cd982db43ab4c2936245a1ac7d32c93198368ff1da7aba24d99a5a0c7232cb29225cd6989078e1c79024019c19ff29b930725cedd7a0425d861c42eb1db2bef412dd9231aca73801423e819281f7adbf9ca252cb3055bc06da5ffc6180332143bbd83af14cb14590d039c"]
NODE_ID = 0

def get_id(node_id):
    global NODE_ID
    NODE_ID = node_id
    blockchain.node_id = node_id

class Blockchain:

    def __init__(self):
        # Initialising arrays
        self.transactions = []
        self.signatures = []
        self.chain = []
        self.nodes = set()

        # Generate random number to be used as node_id
        # self.node_id = str(uuid4()).replace('-', '')
        # The id for proof of authority must be static
        self.node_id = NODE_ID
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
            # transaction_verification = self.verify_transaction_signature(sender_public, signature, transaction)
            # In PoA the signature verification must be made in proof_of_authority
            transaction_verification = True
            # Adding transaction and returning length of the chain
            if transaction_verification:
                self.transactions.append(transaction)
                self.signatures.append(signature)
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

        # Reset the current list of transactions and signatures
        self.transactions = []
        self.signatures = []

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

            # Get transactions
            transactions = block['transactions']

            # Id names of other transaction elements
            transaction_elements = ['sender_public', 'receiver_public', 'value']
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            # Validating proof of work
            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
                # Change this
                return True

            # Upadting index and previous block
            last_block = block
            current_index += 1
        # Return true if there was no anomalies
        return True

    # Proof of authority
    def proof_of_authority(self, last_block):
        # Get the actual number of blocks
        num_blocks = len(self.chain)

        transaction = self.transactions[0]
        sender_public = transaction['sender_public']
        signature = self.signatures[0]
        # Check if the signature is valid
        is_valid = self.verify_transaction_signature(sender_public, signature, transaction)

        if not is_valid:
            return 'unknown signature'

        station = int(transaction['value'][transaction['value'].find("Id_Station:") + 11:])
        if station != self.node_id + 1:
            if self.node_id == 999: return True
            return 'wrong station'
        return True 


    def sign_transaction(self, transaction):

        # Getting binary data (string) from hexadecimal format and using as key
        private_key = RSA.importKey(binascii.unhexlify(PRIVATE_KEYS[self.node_id]))
        # Signer storage the signing scheme
        signer = PKCS1_v1_5.new(private_key)
        # Produces the 160 bit digest of a message (transaction data or our dictionary)
        h = SHA.new(str(transaction).encode('utf8'))
        # Hexadecimal representation of the signed transaction
        return binascii.hexlify(signer.sign(h)).decode('ascii')


    def print_obj(self, obj):
        print("***********************************************************************************")
        pprint.pprint(obj)
        print("***********************************************************************************")



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


# Get transactions route
@app.route('/create/block', methods=['POST'])

def create_initial_block():
    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hash(last_block)
    nonce = 0
    block = blockchain.create_block(nonce, previous_hash)
    blockchain.print_obj(block)
    return jsonify(block), 200


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
    #nonce = blockchain.proof_of_work()
    proof_answer = blockchain.proof_of_authority(last_block)
    blockchain.print_obj(proof_answer)

    nonce = 0
    # We must receive a reward for finding the proof.
    #blockchain.submit_transaction(sender_public=MINING_SENDER, receiver_public=blockchain.node_id, value=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)

    # Replacing chain for the biggest one before creating a new block
    blockchain.resolve_conflicts()
    block = blockchain.create_block(nonce, previous_hash)

    # The normal behaviour of the function
    status_web_code = 200
    is_last_validator = False
    
    # Asking if its the last station
    if(blockchain.node_id == 999):
        status_web_code = 700
        is_last_validator = True 

    # Change Id_Station to the Id of the next station
    transaction = block['transactions'][0]
    station = int(transaction['value'][transaction['value'].find("Id_Station:") + 11:])
    # Replace value in transaction
    replace_str = transaction['value'] [0 : transaction['value'].find("Id_Station:")]

    if proof_answer != 'wrong station':
        transaction['value'] = replace_str + "Id_Station: " + str(station + 1)

    if not is_last_validator:
        # Adding the request to generate a new transaction in the next node/station  
        next_node_port = 5000 + blockchain.node_id + 1
        next_node = "127.0.0.1:" + str(next_node_port)

        trx_to_send = OrderedDict({'sender_public': PUBLIC_KEYS[blockchain.node_id], 
                                    'receiver_public': PUBLIC_KEYS[blockchain.node_id + 1],
                                    'value': transaction['value']})
        print
        signature = blockchain.sign_transaction(trx_to_send)
        data = {
            'sender_public': trx_to_send['sender_public'],
            'receiver_public': trx_to_send['receiver_public'],
            'amount': trx_to_send['value'], 
            'signature':signature
        }
        # If is the wrong station broadcast to the right one
        if proof_answer == 'wrong station':
            next_node_port = 5000 + station - 1
            next_node = "127.0.0.1:" + str(next_node_port)

        if proof_answer != 'unknown signature':
            response_new_tr = requests.post('http://' + next_node + '/transactions/new', data)

    
    # Handling proof_answer
    if proof_answer == 'unknown signature':
        response = {
        'message': "Unknown signature, invalid product/material",
        }
        status_web_code = 666
        replace_str = transaction['value'] [0 : transaction['value'].find("Id_Station:")]
        transaction['value'] = replace_str + "Id_Station: 666"
    
    elif proof_answer == 'wrong station':
        response = {
        'message': "Wrong station, product/material returns to the right station",
        }
        status_web_code = 409
    
    else:
        response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
        }

    block['transactions'] = [transaction]
    # Create and return response
    
    blockchain.print_obj(block)
    return jsonify(response), status_web_code


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
    parser.add_argument('-id', '--id', default=0, type=int, help='Validator id')
    args = parser.parse_args()
    port = args.port
    node_id = args.id
    get_id(node_id)
    app.run(host='127.0.0.1', port=port)

