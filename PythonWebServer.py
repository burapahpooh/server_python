from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import json
import binascii

hostName = "localhost"
serverPort = 5174

# E2E ----------------------------
import hashlib
from binascii import hexlify # For debug output

# If a secure random number generator is unavailable, exit with an error.
try:
	import ssl
	random_function = ssl.RAND_bytes
	random_provider = "Python SSL"
except (AttributeError, ImportError):
	import OpenSSL
	random_function = OpenSSL.rand.bytes
	random_provider = "OpenSSL"

class DiffieHellman(object):
	"""
	A reference implementation of the Diffie-Hellman protocol.
	By default, this class uses the 6144-bit MODP Group (Group 17) from RFC 3526.
	This prime is sufficient to generate an AES 256 key when used with
	a 540+ bit exponent.
	"""

	def __init__(self, generator=2, group=17, keyLength=540):
		"""
		Generate the public and private keys.
		"""
		min_keyLength = 180
		default_keyLength = 540

		default_generator = 2
		valid_generators = [ 2, 3, 5, 7 ]

		# Sanity check fors generator and keyLength
		if(generator not in valid_generators):
			print("Error: Invalid generator. Using default.")
			self.generator = default_generator
		else:
			self.generator = generator

		if(keyLength < min_keyLength):
			print("Error: keyLength is too small. Setting to minimum.")
			self.keyLength = min_keyLength
		else:
			self.keyLength = keyLength

		self.prime = self.getPrime(group)

		self.privateKey = self.genPrivateKey(keyLength)
		self.publicKey = self.genPublicKey()

	def getPrime(self, group=17):
		"""
		Given a group number, return a prime.
		"""
		default_group = 17

		primes = {
		5:  0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
		14: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
		15: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
		16: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
		17:
		0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
		18:
		0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF
		}

		if group in primes.keys():
			return primes[group]
		else:
			print("Error: No prime with group %i. Using default." % group)
			return primes[default_group]

	def genRandom(self, bits):
		"""
		Generate a random number with the specified number of bits
		"""
		_rand = 0
		_bytes = bits // 8 + 8

		while(_rand.bit_length() < bits):
			try:
				# Python 3
				_rand = int.from_bytes(random_function(_bytes), byteorder='big')
			except:
				# Python 2
				_rand = int(OpenSSL.rand.bytes(_bytes).encode('hex'), 16)

		return _rand

	def genPrivateKey(self, bits):
		"""
		Generate a private key using a secure random number generator.
		"""
		return self.genRandom(bits)

	def genPublicKey(self):
		"""
		Generate a public key X with g**x % p.
		"""
		return pow(self.generator, self.privateKey, self.prime)

	def checkPublicKey(self, otherKey):
		"""
		Check the other party's public key to make sure it's valid.
		Since a safe prime is used, verify that the Legendre symbol == 1
		"""
		if(otherKey > 2 and otherKey < self.prime - 1):
			if(pow(otherKey, (self.prime - 1)//2, self.prime) == 1):
				return True
		return False

	def genSecret(self, privateKey, otherKey):
		"""
		Check to make sure the public key is valid, then combine it with the
		private key to generate a shared secret.
		"""
		if(self.checkPublicKey(otherKey) == True):
			sharedSecret = pow(otherKey, privateKey, self.prime)
			return sharedSecret
		else:
			raise Exception("Invalid public key.")

	def genKey(self, otherKey):
		"""
		Derive the shared secret, then hash it to obtain the shared key.
		"""
		self.sharedSecret = self.genSecret(self.privateKey, otherKey)

		# Convert the shared secret (int) to an array of bytes in network order
		# Otherwise hashlib can't hash it.
		try:
			_sharedSecretBytes = self.sharedSecret.to_bytes(
				self.sharedSecret.bit_length() // 8 + 1, byteorder="big")
		except AttributeError:
			_sharedSecretBytes = str(self.sharedSecret)

		s = hashlib.sha256()
		s.update(bytes(_sharedSecretBytes))
		self.key = s.digest()

	def createSharedKey(self, privateKey, otherKey):
		"""
		Derive the shared secret, then hash it to obtain the shared key.
		"""
		self.sharedSecret = self.genSecret(privateKey, otherKey)

		# Convert the shared secret (int) to an array of bytes in network order
		# Otherwise hashlib can't hash it.
		try:
			_sharedSecretBytes = self.sharedSecret.to_bytes(
				self.sharedSecret.bit_length() // 8 + 1, byteorder="big")
		except AttributeError:
			_sharedSecretBytes = str(self.sharedSecret)

		s = hashlib.sha256()
		s.update(bytes(_sharedSecretBytes))
		self.key = s.digest()

	def getKey(self):
		"""
		Return the shared secret key
		"""
		return self.key

	def showParams(self):
		"""
		Show the parameters of the Diffie Hellman agreement.
		"""
		print("Parameters:")
		print("Prime[{0}]: {1}".format(self.prime.bit_length(), self.prime))
		print("Generator[{0}]: {1}\n".format(self.generator.bit_length(),
			self.generator))
		print("Private key[{0}]: {1}\n".format(self.privateKey.bit_length(),
			self.privateKey))
		print("Public key[{0}]: {1}".format(self.publicKey.bit_length(),
			self.publicKey))

	def showResults(self):
		"""
		Show the results of a Diffie-Hellman exchange.
		"""
		print("Results:")
		print("Shared secret[{0}]: {1}".format(self.sharedSecret.bit_length(),
			self.sharedSecret))
		print("Shared key[{0}]: {1}".format(len(self.key), hexlify(self.key)))
		


# Model ----------------------------
import tensorflow as tf
from keras.preprocessing.text import Tokenizer
from keras.preprocessing.sequence import pad_sequences
import pickle


# Translator
from deep_translator import GoogleTranslator

MAX_NB_WORDS = 50000

MAX_SEQUENCE_LENGTH = 300

EMBEDDING_DIM = 100

with open('tokenizer.pickle', 'rb') as handle:
    tokenizer = pickle.load(handle)

loaded_model = tf.keras.models.load_model('classification_model_earlystop.keras')

import numpy as np
labels=['$access control and management',
       '$artificial intelligence security', '$cloud security',
       '$coding and application security',
       '$credential and password security', '$cyber attack',
       '$cyber security updated', '$cyber threat',
       '$cybercrime and cyberwarfare likelihood', '$data security',
       '$email security', '$encryption and cryptography security',
       '$endpoint and device security',
       '$enterprise and widearea security',
       '$exploitation and hacking likelihood',
       '$framework and infrastructure security',
       '$github and version control security', '$malware likelihood',
       '$mobile security', '$network security',
       '$operating system security', '$penetration testing',
       '$phishing likelihood', '$ransomware likelihood',
       '$risk assessment and risk management',
       '$security operation center', '$training guides',
       '$vulnerability likelihood', '$website security',
       '$zero-day likelihood', 'unknown']
# Model ----------------------------

def pad_text(plaintext):
    block_size = 16
    padding_length = block_size - (len(plaintext) % block_size)
    return plaintext + bytes([padding_length] * padding_length)

def encrypt(key, plaintext):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad_text(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext[AES.block_size:])
    return unpad(decrypted_data,AES.block_size)

import pymongo
client = pymongo.MongoClient('mongodb+srv://SeChatUsername:SeChatLover%23123@cbs-01.1swurq8.mongodb.net/')
SeChat = client['SeChat']
UserData = SeChat['UserData']
ConversationData = SeChat['ConversationData']

from bson import json_util

def parse_json(data):
    return json.loads(json_util.dumps(data))

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/encrypt_decrypt":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = json.loads(post_data)
            out=""
            if parsed_data['shared_key']!=None and parsed_data['shared_key'].strip() != '' and parsed_data['mode']!=None and parsed_data['mode'].strip() != '' and parsed_data['message']!=None and parsed_data['message'].strip() != '':
                a = parsed_data["shared_key"].encode()
                shared_key = binascii.unhexlify(a)
                mode = parsed_data["mode"]
                message = parsed_data["message"].encode()
                if mode=="decrypt":
                   message = binascii.a2b_hex(message)
                   decrypted = decrypt(shared_key, message)
                   out = decrypted.decode()
                elif mode=="encrypt":
                   encrypted = encrypt(shared_key, message)	
                   out = encrypted.hex()		   
                else:
                   out="someting wrong"
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()

                response = {"output":out}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"code":404}).encode())

        elif self.path == "/get_sharedKey":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = json.loads(post_data)
            if parsed_data['user_id']!=None and parsed_data['user_id'].strip() != '' and parsed_data['shared_user_id']!=None and parsed_data['shared_user_id'].strip() != '':
                user_id = parsed_data["user_id"].encode()
                shared_user_id = parsed_data["shared_user_id"].encode()
                userA_private = UserData.find({"user_id":{"$eq":int(user_id)}})[0]['private_key']
                userB_public = UserData.find({"user_id":{"$eq":int(shared_user_id)}})[0]['public_key']
                a = DiffieHellman()
                a.createSharedKey(int(userA_private),int(userB_public))
                

                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()

                response = {"shared_key":a.key.hex()}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"code":404}).encode())

        elif self.path == "/model":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = json.loads(post_data)
            
            if parsed_data['message']!=None and parsed_data['message'].strip() != '':
                message = parsed_data["message"]
                message = GoogleTranslator(source='th', target='en').translate(message)

                seq = tokenizer.texts_to_sequences([message])
                padded = pad_sequences(seq, maxlen=MAX_SEQUENCE_LENGTH)
                pred = loaded_model.predict(padded)
                

                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()

                response = {"message":message,
                            "label":labels[np.argmax(pred)]}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"code":404}).encode())

        elif self.path == "/login":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            parsed_data = json.loads(post_data)
            if parsed_data['username']!=None and parsed_data['username'].strip() != '' and parsed_data['password']!=None and parsed_data['password'].strip() != '':
                username = parsed_data["username"]
                password = parsed_data["password"]
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                byte_password = bytes(password, 'utf-8')
                hash_password = SHA256.new(data=byte_password).hexdigest()
                user_login_query = { "user_username": { "$eq": username },"user_password": { "$eq": hash_password } }
                userQuery = UserData.find(user_login_query)
                query_data=[]
                if(userQuery!=None):
                    query_data = [parse_json(x) for x in userQuery]
                else:
                    query_data=["NO USER"]
                response = {"data":query_data}
                self.wfile.write(json.dumps(response).encode())
            else:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"code":404}).encode())
		
        # elif self.path == "/database":
        #     content_length = int(self.headers['Content-Length'])
        #     post_data = self.rfile.read(content_length).decode('utf-8')
        #     parsed_data = json.loads(post_data)
        #     if parsed_data['query']!=None and parsed_data['query'].strip() != '':
        #         query = parsed_data["query"]
        #         self.send_response(200)
        #         self.send_header("Content-type", "application/json")
        #         self.end_headers()
        #         myquery = json.loads(query)
        #         userQuery = UserData.find(myquery)
        #         query_data=[]
        #         if(userQuery!=None):
        #             query_data = [parse_json(x) for x in userQuery]
        #         else:
        #             query_data=[]
        #         response = {"query":query,
		# 					"data":query_data}
        #         self.wfile.write(json.dumps(response).encode())
        #     else:
        #         self.send_response(400)
        #         self.send_header("Content-type", "application/json")
        #         self.end_headers()
        #         self.wfile.write(json.dumps({"code":404}).encode())
        else:
            self.send_response(400)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"code":404}).encode())	


def main():
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server running...")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
    webServer.server_close()
    print("Server stopped.")

if __name__ == "__main__":
    main()
