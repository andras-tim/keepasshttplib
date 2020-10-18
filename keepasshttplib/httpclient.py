"""HTTP Client for KeepassHttp"""
import json

import requests

URL = 'http://localhost:19455'


def associate(key, nonce, verifier):
    """Associate a client with KeepassHttp."""
    payload = {
        'RequestType': 'associate',
        'Key': key,
        'Nonce': nonce,
        'Verifier': verifier
    }
    r = requests.post(URL, data=json.dumps(payload))

    return r.json()['Id']


def test_associate(nonce, verifier, connection_id):
    """Test if client is Associated with KeepassHttp."""
    payload = {
        'Nonce': nonce,
        'Verifier': verifier,
        'RequestType': 'test-associate',
        'TriggerUnlock': 'false',
        'Id': connection_id
    }
    r = requests.post(URL, data=json.dumps(payload))

    return r.json()['Success']


def get_logins(connection_id, nonce, verifier, url):
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
    r = requests.post(URL, data=json.dumps(payload))

    return r.json()['Entries'], r.json()['Nonce']
