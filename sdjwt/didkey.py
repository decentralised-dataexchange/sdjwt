import json
import typing
import base58

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwcrypto import jwk


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
        # UTF-8 encode the json string
        jwk_json_utf8 = jwk_json.encode("utf-8")

        # Manually add the multicodec prefix for jwk_jcs-pub (0xeb51)
        # Using varint encoding: \xd1\xd6\x03
        jwk_multicodec = b"\xd1\xd6\x03" + jwk_json_utf8

        # base58btc encode the data
        encoded_data = base58.b58encode(jwk_multicodec).decode()

        # Add the 'z' prefix for multibase and create the full DID
        method_specific_id = "z" + encoded_data

        # prefix the method specific id with 'did:key:'
        did = f"did:key:{method_specific_id}"

        return did, method_specific_id

    @staticmethod
    def method_specific_identifier_to_jwk(
        method_specific_identifier: str,
    ) -> jwk.JWK:
        # Remove the 'z' multibase prefix
        if not method_specific_identifier.startswith("z"):
            raise ValueError("Method specific identifier must start with 'z'")
        encoded_data = method_specific_identifier[1:]

        # Decode base58btc
        decoded = base58.b58decode(encoded_data)

        # Remove the multicodec prefix (0xeb51 for jwk_jcs-pub)
        # 0xeb51 in decimal is 60241, which takes 2 bytes
        if len(decoded) < 2:
            raise ValueError("Invalid multicodec format")

        if decoded[:3] != b"\xd1\xd6\x03":
            raise ValueError("Expected jwk_jcs-pub codec (0xeb51), got something else")

        raw_data = decoded[3:]

        # Decode the UTF-8 encoded JWK
        try:
            jwk_str = raw_data.decode("utf-8")
            jwk_dict = json.loads(jwk_str)
            return jwk.JWK(**jwk_dict)
        except UnicodeDecodeError:
            raise ValueError("Invalid UTF-8 encoding in JWK data")
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON format in JWK data")
