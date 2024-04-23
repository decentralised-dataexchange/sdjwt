import unittest
from unittest import IsolatedAsyncioTestCase
from sdjwt.sdjwt import (
    generate_did_key_from_seed,
    create_w3c_vc_jwt,
    get_current_datetime_in_epoch_seconds_and_iso8601_format,
    create_flat_sd_jwt,
    create_w3c_vc_sd_jwt,
)
import jwt
import json
from sdjwt.didkey import DIDKey


def create_w3c_vc_jwt_for_passport(didkey: DIDKey):
    credential_id = "urn:did:abc"
    credential_type = ["Passport"]
    credential_context = ["https://www.w3.org/2018/credentials/v1"]
    credential_schema = [
        {
            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
            "type": "FullJsonSchemaValidator2021",
        }
    ]
    credential_subject = {"id": "did:key:datawallet_did", "name": "Jane Doe", "age": 22}

    kid = "did:key:issuer_did#issuer_did"
    jti = credential_id
    iss = "did:key:issuer_did"
    sub = "did:key:datawallet_did"
    to_be_issued_credential = create_w3c_vc_jwt(
        credential_id=credential_id,
        credential_type=credential_type,
        credential_context=credential_context,
        credential_subject=credential_subject,
        credential_status=None,
        terms_of_use=None,
        credential_schema=credential_schema,
        kid=kid,
        jti=jti,
        iss=iss,
        sub=sub,
        key=didkey.private_key,
        credential_issuer=didkey.generate()[0],
    )

    return to_be_issued_credential


def create_flat_sd_jwt_for_passport(didkey: DIDKey):
    credential_id = "urn:did:abc"
    kid = "did:key:issuer_did#issuer_did"
    jti = credential_id
    iss = "did:key:issuer_did"
    sub = "did:key:datawallet_did"

    expiry_in_seconds = 3600
    issuance_epoch, issuance_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format()
    )
    expiration_epoch, expiration_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format(expiry_in_seconds)
    )

    passport_claims = {
        "name": "Jane Doe",
        "address": "Kochi",
        "age": 22,
        "country": "IN",
    }

    sd_jwt = create_flat_sd_jwt(
        jti=jti,
        sub=sub,
        iss=iss,
        kid=kid,
        key=didkey.private_key,
        iat=issuance_epoch,
        exp=expiration_epoch,
        credential_subject=passport_claims,
    )
    return sd_jwt


def create_w3c_vc_sd_jwt_for_passport(didkey: DIDKey):
    credential_id = "urn:did:abc"
    credential_type = ["Passport"]
    credential_context = ["https://www.w3.org/2018/credentials/v1"]
    credential_schema = [
        {
            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
            "type": "FullJsonSchemaValidator2021",
        }
    ]
    credential_subject = {
        "name": "Jane Doe",
        "address": "Kochi",
        "age": 22,
        "country": "IN",
    }

    kid = "did:key:issuer_did#issuer_did"
    jti = credential_id
    iss = "did:key:issuer_did"
    sub = "did:key:datawallet_did"
    to_be_issued_credential = create_w3c_vc_sd_jwt(
        credential_id=credential_id,
        credential_type=credential_type,
        credential_context=credential_context,
        credential_subject=credential_subject,
        credential_status=None,
        terms_of_use=None,
        credential_schema=credential_schema,
        kid=kid,
        jti=jti,
        iss=iss,
        sub=sub,
        key=didkey.private_key,
        credential_issuer=didkey.generate()[0],
    )

    return to_be_issued_credential


class TestSDJWT(IsolatedAsyncioTestCase):
    async def test_create_w3c_vc_jwt_for_passport(self):
        crypto_seed = "helloworld"
        key_did = await generate_did_key_from_seed(crypto_seed)
        key_did.generate()
        vc = create_w3c_vc_jwt_for_passport(didkey=key_did)

        condition1 = len(vc) > 0
        self.assert_(condition1, "VC is empty")
        condition2 = len(vc.split(".")) == 3
        self.assert_(
            condition2, "VC doesn't contain one of header/claims/signature or all"
        )

    async def test_create_flat_sd_jwt_for_passport(self):

        crypto_seed = "helloworld"
        key_did = await generate_did_key_from_seed(crypto_seed)
        key_did.generate()
        sd_jwt = create_flat_sd_jwt_for_passport(didkey=key_did)

        condition1 = len(sd_jwt) > 0
        self.assert_(condition1, "SD-JWT is empty")
        condition2 = len(sd_jwt.split(".")) == 3
        self.assert_(
            condition2, "SD-JWT doesn't contain one of header/claims/signature or all"
        )
        condition3 = len(sd_jwt.split("~")) == 5
        self.assert_(condition3, "SD-JWT doesn't contain all of the disclosures")

        _, claims, _ = sd_jwt.split(".")
        decoded_claims = jwt.utils.base64url_decode(claims.encode()).decode("utf-8")
        decoded_claims = json.loads(decoded_claims)

        self.assertIn("_sd", decoded_claims, "SD-JWT doesn't contain `_sd`")
        condition6 = len(decoded_claims["_sd"]) == 4
        self.assert_(condition6, "VC doesn't contain all of the digest of disclosures")

    async def test_create_w3c_vc_sd_jwt_for_passport(self):

        crypto_seed = "helloworld"
        key_did = await generate_did_key_from_seed(crypto_seed)
        key_did.generate()
        vc = create_w3c_vc_sd_jwt_for_passport(didkey=key_did)

        condition1 = len(vc) > 0
        self.assert_(condition1, "VC is empty")
        condition2 = len(vc.split(".")) == 3
        self.assert_(
            condition2, "VC doesn't contain one of header/claims/signature or all"
        )
        condition3 = len(vc.split("~")) == 5
        self.assert_(condition3, "VC doesn't contain all of the disclosures")

        _, claims, _ = vc.split(".")
        decoded_claims = jwt.utils.base64url_decode(claims.encode()).decode("utf-8")
        decoded_claims = json.loads(decoded_claims)

        condition4 = decoded_claims["vc"]["type"][0] == "Passport"
        self.assert_(condition4, "VC doesn't contain type as `Passport`")
        self.assertIn(
            "_sd",
            decoded_claims["vc"]["credentialSubject"],
            "VC doesn't contain `_sd` in credentialSubject",
        )
        condition6 = len(decoded_claims["vc"]["credentialSubject"]["_sd"]) == 4
        self.assert_(condition6, "VC doesn't contain all of the digest of disclosures")


if __name__ == "__main__":
    unittest.main()
