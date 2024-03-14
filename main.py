import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# say the database
database = {}

# client
class Client:
    def __init__(self, Username):
        self.Username = Username
        self.Address = f"{Username}@example.com"
        self.PrivateKey = self.generate_private_key()
        self.PublicKey = self.PrivateKey.public_key()
        self.save_keys_to_files()

    def generate_private_key(self):
        # generate key pair
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def save_keys_to_files(self):
        # save key pair
        private_key_pem = self.PrivateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(f'{self.Username}_private_key.pem', 'wb') as f:
            f.write(private_key_pem)

        public_key_pem = self.PublicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(f'{self.Username}_public_key.pem', 'wb') as f:
            f.write(public_key_pem)

    def send_register_request(self, server):
        # send register request to server
        server.register(self.Username, self.PublicKey)

    def decrypt_and_respond_challenge(self, encrypted_number):
        # re-encrypt
        original_number = self.PrivateKey.decrypt(
            encrypted_number,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        modified_number = int.from_bytes(original_number, 'big') - 1
        encrypted_response = self.PublicKey.encrypt(
            modified_number.to_bytes((modified_number.bit_length() + 7) // 8, byteorder='big'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_response

    def send_login_request(self, server):
        # send login request to server
        message = self.Address.encode()
        signature = self.PrivateKey.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        server.Login(self.Username, self.Address, signature)

    def request_user_info(self, server, username_to_find):
        # find user
        signature = self.PrivateKey.sign(
            username_to_find.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return server.FindUser(username_to_find, signature)

# server
class Server:
    def register(self, Username, PublicKey):
        # register user
        if Username in database:
            return 'UsernameTaken'
        # send encryption
        challenge_number = os.urandom(16)
        encrypted_challenge = PublicKey.encrypt(
            challenge_number,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_challenge

    def VerifyChallengeResponse(self, Username, PublicKey, encrypted_response):
        # response encryption
        try:
            decrypted_response = PublicKey.decrypt(
                encrypted_response,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            # add to database if correct
            database[Username] = {
                'PublicKey': PublicKey,
                'Address': f"{Username}@example.com"
            }
            return 'Success'
        except Exception as e:
            return 'ChallengeIncorrect'

    def Login(self, Username, Address, Signature):
        # use log in
        if Username not in database:
            return 'InvalidUsername'
        user_info = database[Username]
        PublicKey = user_info['PublicKey']
        try:
            PublicKey.verify(
                Signature,
                Address.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # update user IP address if success
            user_info['Address'] = Address
            return 'Success'
        except:
            return 'Invalid'

    def FindUser(self, UsernameToFind, Signature):
        # find user
        if UsernameToFind not in database:
            return 'InvalidUsername'
        user_info = database[UsernameToFind]
        PublicKey = user_info['PublicKey']
        try:
            PublicKey.verify(
                Signature,
                UsernameToFind.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return user_info['Address']
        except:
            return 'Invalid'


# test examples
if __name__ == '__main__':
    server = Server()

    alice = Client("A")
    challenge_from_server = alice.send_signup_request(server)
    response_to_challenge = alice.decrypt_and_respond_challenge(challenge_from_server)
    print(server.VerifyChallengeResponse("A", alice.PublicKey, response_to_challenge))
    print(alice.send_login_request(server))
    print(alice.request_user_info(server, "B"))
