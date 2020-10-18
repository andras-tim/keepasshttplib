import base64

import keyring

from .encrypter import Encrypter
from .httpclient import HttpClient


class Keepasshttplib:
    """Encrypting and decrypting strings using AES"""

    def get_credentials(self, url):
        key = self.get_key_from_keyring()
        if key is None:
            key = Encrypter.generate_key()
        connection_id = self.get_id_from_keyring()
        is_associated = False
        if connection_id is not None:
            is_associated = self.test_associate(key, connection_id)

        if not is_associated:
            print('running test associate')
            connection_id = self.associate(key)
            keyring.set_password("keepasshttplib", "connection_id", connection_id)
            keyring.set_password("keepasshttplib", "private_key", base64.b64encode(key).decode())
            is_associated = True

        if is_associated:
            return self.get_credentials_from_client(key, url, connection_id)
        else:
            return None

    def get_key_from_keyring(self):
        """getting key from Keyring"""
        private_key = keyring.get_password("keepasshttplib", "private_key")

        if private_key is not None:
            return base64.b64decode(private_key)
        else:
            return None

    def get_id_from_keyring(self):
        """getting identification from keyring"""
        return keyring.get_password("keepasshttplib", "connection_id")

    def test_associate(self, key, connection_id):
        """testing if associated"""
        enc = Encrypter(key)
        (base64_private_key, nonce, verifier) = enc.get_verifier()

        return HttpClient.test_associate(nonce, verifier, connection_id)

    def associate(self, key):
        """if associate"""
        enc = Encrypter(key)
        (base64_private_key, nonce, verifier) = enc.get_verifier()

        return HttpClient.associate(base64_private_key, nonce, verifier)

    def get_credentials_from_client(self, key, url, connection_id):
        """getting credentials from client"""
        enc = Encrypter(key)
        (base64_private_key, nonce, verifier) = enc.get_verifier()
        encrypted_url = enc.encrypt(url, base64.b64decode(nonce))
        (logins, nonce) = HttpClient.get_logins(connection_id, nonce, verifier, encrypted_url)
        number_of_logins = len(logins)
        if number_of_logins == 0:
            return None

        encrypted_username = logins[0]['Login']
        encrypted_password = logins[0]['Password']

        return (enc.decrypt(encrypted_username, base64.b64decode(nonce)),
                enc.decrypt(encrypted_password, base64.b64decode(nonce)))
