"""HTTP Client for KeepassHttp"""
import json

import requests
from requests import HTTPError


class HttpClient:
    URL = 'http://localhost:19455'

    @classmethod
    def associate(cls, key, nonce, verifier):
        """Associate a client with KeepassHttp."""
        payload = {
            'RequestType': 'associate',
            'Key': key,
            'Nonce': nonce,
            'Verifier': verifier
        }
        r = requests.post(cls.URL, data=json.dumps(payload))
        data = r.json()

        error = data.get('Error')
        if error:
            raise HTTPError(error)
        r.raise_for_status()

        return data['Id']

    @classmethod
    def test_associate(cls, nonce, verifier, connection_id):
        """Test if client is Associated with KeepassHttp."""
        payload = {
            'Nonce': nonce,
            'Verifier': verifier,
            'RequestType': 'test-associate',
            'TriggerUnlock': 'false',
            'Id': connection_id
        }
        r = requests.post(cls.URL, data=json.dumps(payload))
        data = r.json()

        error = data.get('Error')
        if error:
            raise HTTPError(error)
        r.raise_for_status()

        return data['Success']

    @classmethod
    def get_logins(cls, connection_id, nonce, verifier, url):
        """getting logins through url"""
        payload = {
            'RequestType': 'get-logins',
            'SortSelection': 'true',
            'TriggerUnlock': 'false',
            'Id': connection_id,
            'Nonce': nonce,
            'Verifier': verifier,
            'Url': url,
            'SubmitUrl': url
        }
        r = requests.post(cls.URL, data=json.dumps(payload))
        data = r.json()

        error = data.get('Error')
        if error:
            raise HTTPError(error)
        r.raise_for_status()

        return data['Entries'], data['Nonce']
