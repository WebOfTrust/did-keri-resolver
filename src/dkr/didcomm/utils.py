from keri.core import eventing, coring

from didcomm.common.types import DID, VerificationMethodType, VerificationMaterial, VerificationMaterialFormat
from didcomm.common.resolvers import SecretsResolver
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.secrets.secrets_resolver_demo import  Secret


from typing import Optional, List
import pysodium
import base64
import json


'''
Proof of concept of DIDComm packing and unpacking with did:keri
- Use SICPA didcomm-python library
- Authcryypt message
- AID is Ed25519 and derive X25519 keys from same private
- Transferable AID but with no next key that makes it non transferable (no key rotations)
'''


def createKeriDid():
    salt = coring.Salter()
    signerEd25519 = salt.signer(transferable=True, temp=True)

    X25519_pubkey = pysodium.crypto_sign_pk_to_box_pk(signerEd25519.verfer.raw)
    X25519_pubkey_qb64 = ('C'+base64.b64encode(X25519_pubkey).decode('utf-8'))[:-1]

    serder = eventing.incept(
        keys=[signerEd25519.verfer.qb64], 
        data=[
                {"e":X25519_pubkey_qb64},
                {"se": "https://example.coom/"}
            ], 
        code=coring.MtrDex.Blake3_256 # code is for self-addressing
    )

    did = 'did:keri:'+serder.ked['i']
    kelb64 = base64.urlsafe_b64encode(bytes(json.dumps(serder.ked), 'utf-8')).decode('utf-8')
    long_did = did+'?kel='+kelb64

    return {
        'did': did,
        'long_did': long_did,
        'signer': signerEd25519
    }

def validateLongDid(long_did):
    # TODO make URL parsing safer
    did = long_did.split('?')[0]
    kelb64 = long_did.split('=')[1]+"=="
    kel_decoded = json.loads(base64.urlsafe_b64decode(kelb64))
    prefixer = coring.Prefixer(ked=kel_decoded)
    return prefixer.qb64b.decode("utf-8") == did.split(':')[2]

class SecretsResolverInMemory(SecretsResolver):
    def __init__(self, store: dict):
        self._store = store

    async def get_key(self, kid: str) -> Optional[Secret]:
        
        did = kid.split('#')[0]
        signer = self._store[did]['signer']
        X25519_pubkey = pysodium.crypto_sign_pk_to_box_pk(signer.verfer.raw)
        X25519_pubkey_b64 = base64.b64encode(X25519_pubkey).decode('utf-8')
        X25519_prikey = pysodium.crypto_sign_sk_to_box_sk(signer.raw + signer.verfer.raw)
        X25519_prikey_b64 = base64.b64encode(X25519_prikey).decode('utf-8')

        secret = Secret(
                kid= kid,
                type= VerificationMethodType.JSON_WEB_KEY_2020,
                verification_material= VerificationMaterial(
                    format=VerificationMaterialFormat.JWK,
                    value= json.dumps(
                        {
                            'kty': 'OKP',
                            'crv': 'X25519',
                            'd': X25519_prikey_b64,
                            'x': X25519_pubkey_b64,
                            'kid': kid
                        }
                    )
                )
        )        
        return secret

    async def get_keys(self, kids: List[str]) -> List[str]:
        return kids


class DidKeriResolver(DIDResolver):
    def __init__(self, store: dict):
        self._store = store
    async def resolve(self, did: DID) -> DIDDoc:
        short_did = did.split('?')[0]
        if len(did.split('=')) > 1:  
            kelb64 = did.split('=')[1]+"=="
            ked = json.loads(base64.urlsafe_b64decode(kelb64))
            self._store[short_did]['ked'] = ked
        else:
            ked = self._store[short_did]['ked']

        return DIDDoc(
            did=did,
            key_agreement_kids = [short_did+'#key-1'],
            authentication_kids = [],
            verification_methods = [
                VerificationMethod(
                    id = short_did+'#key-1',
                    type = VerificationMethodType.JSON_WEB_KEY_2020,
                    controller = did,
                    verification_material = VerificationMaterial(
                        format = VerificationMaterialFormat.JWK,
                        value = json.dumps({
                                    'kty': 'OKP',
                                    'crv': 'X25519',
                                    'x': ked['a'][0]['e'][1:]
                                })
                    )
                )
            ],
             didcomm_services = []
        )