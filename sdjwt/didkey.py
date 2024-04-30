import json
import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwk
from multiformats import multibase, multicodec


class DIDKey:
    def __init__(self, seed):
        self.private_key = None
        self.public_key = None
        self._create_keypair(seed=seed)

    def _create_keypair(self, seed):
        curve = ec.SECP256R1()
        private_key = ec.derive_private_key(
            int.from_bytes(seed, "big"), curve, default_backend()
        )
        public_key = private_key.public_key()
        private_key_jwk = jwk.JWK.from_pem(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        public_key_jwk = jwk.JWK.from_pem(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        self.private_key = private_key_jwk
        self.public_key = public_key_jwk

    def generate(self) -> typing.Tuple[str, str]:
        if not self.public_key:
            raise Exception("Keypair must be created before generating the DID")
        # Convert jwk to json with whitespace eliminated
        jwk_json = json.dumps(
            self.public_key.export(as_dict=True), separators=(",", ":")
        )
        # multicodec wrap the utf-8 encoded bytes
        # with jwk_jcs-pub (0xeb51) codec identifier
        jwk_multicodec = multicodec.wrap("jwk_jcs-pub", jwk_json.encode("utf-8"))
        # multibase base58-btc encode the jwk_multicodec bytes
        method_specific_id = multibase.encode(jwk_multicodec, "base58btc")
        # prefix the method specific id with 'did:key:'
        did = f"did:key:{method_specific_id}"
        return did, method_specific_id

    @staticmethod
    def method_specific_identifier_to_jwk(method_specific_identifier: str) -> jwk.JWK:
        decoded = multibase.decode(method_specific_identifier)
        _, raw_data = multicodec.unwrap(decoded)
        jwk_str = raw_data.decode("utf-8")
        jwk_dict = json.loads(jwk_str)
        return jwk.JWK(**jwk_dict)
