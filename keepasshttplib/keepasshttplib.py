import base64
from typing import Dict, Optional

import keyring

from .encrypter import Encrypter
from .httpclient import HttpClient

Credential = Dict[str, str]


class Keepasshttplib:
    """Encrypting and decrypting strings using AES"""

    def __init__(self, keyring_id: Optional[str] = None):
        self.keyring_service_name = "keepasshttplib"
        if keyring_id:
            self.keyring_service_name += "-{}".format(keyring_id)

    def get_credentials(self, url: str) -> Optional[Credential]:
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
            keyring.set_password(self.keyring_service_name, "connection_id", connection_id)
            keyring.set_password(self.keyring_service_name, "private_key", base64.b64encode(key).decode())
            is_associated = True

        if is_associated:
            return self.get_credentials_from_client(key, url, connection_id)
        else:
            return None

    def get_key_from_keyring(self):
        """getting key from Keyring"""
        private_key = keyring.get_password(self.keyring_service_name, "private_key")

        if private_key is not None:
            return base64.b64decode(private_key)
        else:
            return None

    def get_id_from_keyring(self):
        """getting identification from keyring"""
        return keyring.get_password(self.keyring_service_name, "connection_id")

    def test_associate(self, key, connection_id):
        """testing if associated"""
        enc = Encrypter(key)
        base64_private_key, nonce, verifier = enc.get_verifier()

        return HttpClient.test_associate(nonce, verifier, connection_id)

    def associate(self, key):
        """if associate"""
        enc = Encrypter(key)
        base64_private_key, nonce, verifier = enc.get_verifier()

        return HttpClient.associate(base64_private_key, nonce, verifier)

    def get_credentials_from_client(self, key, url, connection_id) -> Credential:
        """getting credentials from client"""
        enc = Encrypter(key)
        base64_private_key, nonce, verifier = enc.get_verifier()
        encrypted_url = enc.encrypt(url, base64.b64decode(nonce))
        encrypted_credentials, nonce = HttpClient.get_logins(connection_id, nonce, verifier, encrypted_url)
        iv = base64.b64decode(nonce)

        return {
            enc.decrypt(encrypted_credential['Login'], iv): enc.decrypt(encrypted_credential['Password'], iv)
            for encrypted_credential in encrypted_credentials
        }
