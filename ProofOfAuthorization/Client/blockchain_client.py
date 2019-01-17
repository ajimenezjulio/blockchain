
from collections import OrderedDict
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import requests
from flask import Flask, jsonify, request, render_template


class Transaction:

	# Constructor
    def __init__(self, sender_public, sender_private, receiver_public, value):
        
        # Initialising variables
        self.sender_public = sender_public
        self.sender_private = sender_private
        self.receiver_public = receiver_public
        self.value = value

    # Getter
    def __getattr__(self, attr):
        return self.data[attr]

    # Creating dictionary with the transaction's data excluding sender private key
    def to_dict(self):
        return OrderedDict({'sender_public': self.sender_public,
                            'receiver_public': self.receiver_public,
                            'value': self.value})

    # Signing method using RSA algorithm and data including sender private key
    def sign_transaction(self):

    	# Getting binary data (string) from hexadecimal format and using as key
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private))
        # Signer storage the signing scheme
        signer = PKCS1_v1_5.new(private_key)
        # Produces the 160 bit digest of a message (transaction data or our dictionary)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        # Hexadecimal representation of the signed transaction
        return binascii.hexlify(signer.sign(h)).decode('ascii')


# Using Flask for web app
app = Flask(__name__)

# Route to index page
@app.route('/')
def index():
	return render_template('./index.html')

# Route to create new transaction page
@app.route('/create/transaction')
def make_transaction():
    return render_template('./create_transaction.html')

# Route to view the transactions history 
@app.route('/view/history')
def view_transaction():
    return render_template('./history.html')

# Generating the privte and public key
@app.route('/new/wallet', methods=['GET'])
def new_wallet():
    # Generating random object
	random_gen = Crypto.Random.new().read
    # Generating private key of size 1024 (the size must be a multiple of 256)
	private_key = RSA.generate(1024, random_gen)
    # Generating public key from private key (there is a bond between both)
	public_key = private_key.publickey()
    # Filling the response in hexadecimal format('DER'. Binary encoding, always unencrypted.)
	response = {
		'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
		'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii')
	}
    # Return the response and the status OK (OK = 200 in http code)
	return jsonify(response), 200

# Generating a new transaction using port 8080 for communication
@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
	
    # Requesting the data filled by the user in the webpage
	sender_public = request.form['sender_public']
	sender_private = request.form['sender_private']
	receiver_public = request.form['receiver_public']
	value = request.form['amount']

    # Filling the new transaction object with the info
	transaction = Transaction(sender_public, sender_private, receiver_public, value)

    # Filling the response with the transaction info and the signature file/object
	response = {'transaction': transaction.to_dict(), 'signature': transaction.sign_transaction()}

    # Return the response and the status OK (OK = 200 in http code)
	return jsonify(response), 200


# If executing from console, using port 8080 as default and 127.0.0.1 as host address
if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    # The user can specify another port with the console commnads -p or --port
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)