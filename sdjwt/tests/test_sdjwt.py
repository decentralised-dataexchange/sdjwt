import unittest
from unittest import IsolatedAsyncioTestCase
from sdjwt.sdjwt import (
    generate_did_key_from_seed,
    create_w3c_vc_jwt,
    get_current_datetime_in_epoch_seconds_and_iso8601_format,
    create_flat_sd_jwt,
    create_w3c_vc_sd_jwt,
    get_all_disclosures_with_sd_from_token,
    decode_credential_sd_to_credential_subject,
    create_disclosure_mapping_from_credential_definition,
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
    (
        issuance_epoch,
        issuance_8601,
    ) = get_current_datetime_in_epoch_seconds_and_iso8601_format()
    (
        expiration_epoch,
        expiration_8601,
    ) = get_current_datetime_in_epoch_seconds_and_iso8601_format(expiry_in_seconds)

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

    async def test_decode_credential_sd_to_credential_subject(self):
        # Case 1
        token_1 = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticUhZTU12UU5VRnBVeGtKRTlTd051djNRcFhQZ1BlYmljS1FjOGQ0RDFvdHNNc2d0YVhCTndKNHpZOFNRUFpiY0FIeGJHd2trYk50bUh5ZnVUZGs4bkNxVlNlcGVXWGhoM1NqcnUyWDVmVEhucGdyOEZUeXczZTFXamJ4UUhoc0c5MiN6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxSFlNTXZRTlVGcFV4a0pFOVN3TnV2M1FwWFBnUGViaWNLUWM4ZDREMW90c01zZ3RhWEJOd0o0elk4U1FQWmJjQUh4Ykd3a2tiTnRtSHlmdVRkazhuQ3FWU2VwZVdYaGgzU2pydTJYNWZUSG5wZ3I4RlR5dzNlMVdqYnhRSGhzRzkyIiwidHlwIjoiSldUIn0.eyJleHAiOjE3MTU3NzA4MjIsImlhdCI6MTcxNTc2NzIyMiwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxSFlNTXZRTlVGcFV4a0pFOVN3TnV2M1FwWFBnUGViaWNLUWM4ZDREMW90c01zZ3RhWEJOd0o0elk4U1FQWmJjQUh4Ykd3a2tiTnRtSHlmdVRkazhuQ3FWU2VwZVdYaGgzU2pydTJYNWZUSG5wZ3I4RlR5dzNlMVdqYnhRSGhzRzkyIiwianRpIjoidXJuOmRpZDpiOTMyODU5NC0wNmNlLTRjNjYtYWNkYS1jZmY0ZjUxMDZjNjciLCJuYmYiOjE3MTU3NjcyMjIsInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtib3dvMU1ZcENKd05memZGZ2dYdVd4ZFBBZEFXaGtwOVhza1UyY2lyN3IyMUF4cU4yVE12TVRVUzFGbWFOV0xtMmVzYThGTHdaMzVpNW1SelV5Z0RRZFpSUzFnQzQyQW05RG95aDY4SHAxS3NhcDllOXh6ZWJEWUZoaExnWFRrc2duRyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOlt7ImlkIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS90cnVzdGVkLXNjaGVtYXMtcmVnaXN0cnkvdjIvc2NoZW1hcy96M01nVUZVa2I3MjJ1cTR4M2R2NXlBSm1uTm16REZlSzVVQzh4ODNRb2VMSk0iLCJ0eXBlIjoiRnVsbEpzb25TY2hlbWFWYWxpZGF0b3IyMDIxIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiTlZVbGFhaklSZEhDbGdyamtvMUZ5MWJNRDNqWEs5Mk9ZMEdUYU9SNFNYOCIsImlwUm5sNjNQVjlUVlhhRlhZSVg5UDZWVWswUXlMOF9tNnp1dEdUSG5zdGciXSwiaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYm93bzFNWXBDSndOZnpmRmdnWHVXeGRQQWRBV2hrcDlYc2tVMmNpcjdyMjFBeHFOMlRNdk1UVVMxRm1hTldMbTJlc2E4Rkx3WjM1aTVtUnpVeWdEUWRaUlMxZ0M0MkFtOURveWg2OEhwMUtzYXA5ZTl4emViRFlGaGhMZ1hUa3NnbkcifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI0LTA1LTE1VDExOjAwOjIyWiIsImlkIjoidXJuOmRpZDpiOTMyODU5NC0wNmNlLTRjNjYtYWNkYS1jZmY0ZjUxMDZjNjciLCJpc3N1YW5jZURhdGUiOiIyMDI0LTA1LTE1VDEwOjAwOjIyWiIsImlzc3VlZCI6IjIwMjQtMDUtMTVUMTA6MDA6MjJaIiwiaXNzdWVyIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxSFlNTXZRTlVGcFV4a0pFOVN3TnV2M1FwWFBnUGViaWNLUWM4ZDREMW90c01zZ3RhWEJOd0o0elk4U1FQWmJjQUh4Ykd3a2tiTnRtSHlmdVRkazhuQ3FWU2VwZVdYaGgzU2pydTJYNWZUSG5wZ3I4RlR5dzNlMVdqYnhRSGhzRzkyIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdHRlc3RhdGlvbiIsIlBvcnRhYmxlRG9jdW1lbnRBMVNkSnd0Il0sInZhbGlkRnJvbSI6IjIwMjQtMDUtMTVUMTA6MDA6MjJaIn19.BhWlU4zlkZUeLmScFTzhToXmP2ASNwWLlcXAXpMskIakRICDr-mN96CtwWOsihC52hZ7bDUnksFKr4z77E5Ccw~WyI3ODA1YmZkMjA0MWYwYzczNmYxYzk0ZDE5MWUyYmQ5NzY2ZjFkMTFiNGI2NDNkYTkxNjVjZDM3NjBiNDk5Mjg5IiwiaWRlbnRpZmllciIsIjEyMzQwMC03ODk5Il0~WyIwNzEzMDRiMWU5OWEyMDRmZGMzMzUyMmQ5OTEyNTcyNjkwOWMxMTgzZjFlMTM4N2UyNWE1NzMwM2RhMzgyNmIxIiwibGVnYWxOYW1lIiwiQnlnZyBBQiJd"
        sd_credential_subject_1 = {
            "_sd": [
                "NVUlaajIRdHClgrjko1Fy1bMD3jXK92OY0GTaOR4SX8",
                "ipRnl63PV9TVXaFXYIX9P6VUk0QyL8_m6zutGTHnstg",
            ],
            "id": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbowo1MYpCJwNfzfFggXuWxdPAdAWhkp9XskU2cir7r21AxqN2TMvMTUS1FmaNWLm2esa8FLwZ35i5mRzUygDQdZRS1gC42Am9Doyh68Hp1Ksap9e9xzebDYFhhLgXTksgnG",
        }
        expected_credential_subject_1 = {
            "id": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbowo1MYpCJwNfzfFggXuWxdPAdAWhkp9XskU2cir7r21AxqN2TMvMTUS1FmaNWLm2esa8FLwZ35i5mRzUygDQdZRS1gC42Am9Doyh68Hp1Ksap9e9xzebDYFhhLgXTksgnG",
            "identifier": "123400-7899",
            "legalName": "Bygg AB",
        }
        # Case 2
        token_2 = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticUhZTU12UU5VRnBVeGtKRTlTd051djNRcFhQZ1BlYmljS1FjOGQ0RDFvdHNNc2d0YVhCTndKNHpZOFNRUFpiY0FIeGJHd2trYk50bUh5ZnVUZGs4bkNxVlNlcGVXWGhoM1NqcnUyWDVmVEhucGdyOEZUeXczZTFXamJ4UUhoc0c5MiN6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxSFlNTXZRTlVGcFV4a0pFOVN3TnV2M1FwWFBnUGViaWNLUWM4ZDREMW90c01zZ3RhWEJOd0o0elk4U1FQWmJjQUh4Ykd3a2tiTnRtSHlmdVRkazhuQ3FWU2VwZVdYaGgzU2pydTJYNWZUSG5wZ3I4RlR5dzNlMVdqYnhRSGhzRzkyIiwidHlwIjoiSldUIn0.eyJleHAiOjE3MTU3NzA3MzQsImlhdCI6MTcxNTc2NzEzNCwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxSFlNTXZRTlVGcFV4a0pFOVN3TnV2M1FwWFBnUGViaWNLUWM4ZDREMW90c01zZ3RhWEJOd0o0elk4U1FQWmJjQUh4Ykd3a2tiTnRtSHlmdVRkazhuQ3FWU2VwZVdYaGgzU2pydTJYNWZUSG5wZ3I4RlR5dzNlMVdqYnhRSGhzRzkyIiwianRpIjoidXJuOmRpZDo5ZWMxNjg0ZS05YjVhLTQzY2EtODAxNy0zNmJmMmJhMGRhOGQiLCJuYmYiOjE3MTU3NjcxMzQsInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtib3dvMU1ZcENKd05memZGZ2dYdVd4ZFBBZEFXaGtwOVhza1UyY2lyN3IyMUF4cU4yVE12TVRVUzFGbWFOV0xtMmVzYThGTHdaMzVpNW1SelV5Z0RRZFpSUzFnQzQyQW05RG95aDY4SHAxS3NhcDllOXh6ZWJEWUZoaExnWFRrc2duRyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOlt7ImlkIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS90cnVzdGVkLXNjaGVtYXMtcmVnaXN0cnkvdjIvc2NoZW1hcy96M01nVUZVa2I3MjJ1cTR4M2R2NXlBSm1uTm16REZlSzVVQzh4ODNRb2VMSk0iLCJ0eXBlIjoiRnVsbEpzb25TY2hlbWFWYWxpZGF0b3IyMDIxIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiYlprNmR5ay1OZzU3UUhmT0ZsNkRYV3hUZVNHWHJiUWtIZzg2OGktTEpRVSIsImZ3ekV6WDd4bmUyTGNiemJseWlDTnJwOC1TdHlkUk5uV1BIajA3Ym5XZ1EiLCJQS2NCeG1GM1ZhRlR5Nl80X2ZJTWdrNW5nQ0tUUGFjRDZlbVVOUEppdk9NIiwid2NHMHViSVhXOWRkTWFPZlVQNGVVMnk5UUpFZkgyejlGa3RHWHo2UGxubyIsIjdhaW5MMUpmVTBmNHNHdVY2emVac0tfY1Y5ZnlnajJoS0tPb01oUXFuOFkiXSwiaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYm93bzFNWXBDSndOZnpmRmdnWHVXeGRQQWRBV2hrcDlYc2tVMmNpcjdyMjFBeHFOMlRNdk1UVVMxRm1hTldMbTJlc2E4Rkx3WjM1aTVtUnpVeWdEUWRaUlMxZ0M0MkFtOURveWg2OEhwMUtzYXA5ZTl4emViRFlGaGhMZ1hUa3NnbkciLCJzZWN0aW9uMSI6eyJfc2QiOlsiOE1tcEtCcFBxbXVNSkRuTXdtV29BQ1JsbnM3T0dDX3l6a3NPZmN1ZW53MCJdLCJmb3JlbmFtZXMiOiJDaGFybG90dGUiLCJuYXRpb25hbGl0aWVzIjpbIlNFIl0sInBlcnNvbmFsSWRlbnRpZmljYXRpb25OdW1iZXIiOiIxOTY4MTIyOS0xNDEyIiwicGxhY2VCaXJ0aCI6eyJjb3VudHJ5Q29kZSI6IlNFIiwicmVnaW9uIjoiU3RvY2tob2xtIiwidG93biI6IlN0b2NraG9sbSJ9LCJzZXgiOiJGZW1hbGUiLCJzdGF0ZU9mUmVzaWRlbmNlQWRkcmVzcyI6eyJjb3VudHJ5Q29kZSI6IlNFIiwicG9zdENvZGUiOiI0MTggNzgiLCJzdHJlZXRObyI6Ikd1bm5hciBFbmdlbGxhdXMgdmFnIDgsIDkxIDFCIiwidG93biI6IlN0b2NraG9sbSJ9LCJzdGF0ZU9mU3RheUFkZHJlc3MiOnsiY291bnRyeUNvZGUiOiJTRSIsInBvc3RDb2RlIjoiNDE4IDc4Iiwic3RyZWV0Tm8iOiJHdW5uYXIgRW5nZWxsYXVzIHZhZyA4LCA5MSAxQiIsInRvd24iOiJTdG9ja2hvbG0ifSwic3VybmFtZSI6IkFuZGVyc29uIiwic3VybmFtZUF0QmlydGgiOiJBbmRlcnNvbiJ9fSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI0LTA1LTE1VDEwOjU4OjU0WiIsImlkIjoidXJuOmRpZDo5ZWMxNjg0ZS05YjVhLTQzY2EtODAxNy0zNmJmMmJhMGRhOGQiLCJpc3N1YW5jZURhdGUiOiIyMDI0LTA1LTE1VDA5OjU4OjU0WiIsImlzc3VlZCI6IjIwMjQtMDUtMTVUMDk6NTg6NTRaIiwiaXNzdWVyIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxSFlNTXZRTlVGcFV4a0pFOVN3TnV2M1FwWFBnUGViaWNLUWM4ZDREMW90c01zZ3RhWEJOd0o0elk4U1FQWmJjQUh4Ykd3a2tiTnRtSHlmdVRkazhuQ3FWU2VwZVdYaGgzU2pydTJYNWZUSG5wZ3I4RlR5dzNlMVdqYnhRSGhzRzkyIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdHRlc3RhdGlvbiIsIlBvcnRhYmxlRG9jdW1lbnRBMVNkSnd0Il0sInZhbGlkRnJvbSI6IjIwMjQtMDUtMTVUMDk6NTg6NTRaIn19.bMYH7dxGOe3y4JYz4WKxelRjfH4Sk9T7EowJ2eHj7w3iAiCIBOXqQDHH6hjQpnhezF-uQouPpS5Y2fk6bacCHA~WyIwZDU1ODEyYWM1MDViN2Y4Yzk3ZGM3ZjQyNWY5ZWJkMzA4NjAyNjhmZWNiZjU5ZjFmMTBlMTQ2ZDFkODZiZDg0IiwiZGF0ZUJpcnRoIiwiMTk2OC0xMi0yOSJd~WyJhYmNjMmI2NTRmZGNlMzBhZjgwNjhlZjcwZWRlMDNkZTNlMTA3NzE2YzE1ZWUyNGQwOWEyY2E4ZTc4ZDE0ZmM2Iiwic2VjdGlvbjQiLHsiZW1wbG95ZWUiOmZhbHNlLCJlbXBsb3llclNlbGZFbXBsb3llZEFjdGl2aXR5Q29kZXMiOlsiMTg4OTExMzI0NCJdLCJuYW1lQnVzaW5lc3NOYW1lIjoiVm9sdm8iLCJyZWdpc3RlcmVkQWRkcmVzcyI6eyJjb3VudHJ5Q29kZSI6IlNFIiwicG9zdENvZGUiOiI0MTggNzgiLCJzdHJlZXRObyI6Ikd1bm5hciBFbmdlbGxhdXMgdnUwMGU0ZyA4LCAxNjQgQSIsInRvd24iOiJHb3RlYm9yZyJ9LCJzZWxmRW1wbG95ZWRBY3Rpdml0eSI6dHJ1ZX1d~WyI5N2ZlNTI4MDlkYjUxYWQyNjAxYzY4NDExMTU1YWFjZTZmNWI1M2VjNGJiYmMwYzlmNjk3OGJjODI0NDM1YTQxIiwic2VjdGlvbjMiLHsiY2l2aWxBbmRFbXBsb3llZFNlbGZFbXBsb3llZCI6ZmFsc2UsImNpdmlsU2VydmFudCI6ZmFsc2UsImNvbnRyYWN0U3RhZmYiOmZhbHNlLCJlbXBsb3llZEFuZFNlbGZFbXBsb3llZCI6ZmFsc2UsImVtcGxveWVkVHdvT3JNb3JlU3RhdGVzIjpmYWxzZSwiZXhjZXB0aW9uIjpmYWxzZSwiZXhjZXB0aW9uRGVzY3JpcHRpb24iOiIiLCJmbGlnaHRDcmV3TWVtYmVyIjpmYWxzZSwibWFyaW5lciI6ZmFsc2UsInBvc3RlZEVtcGxveWVkUGVyc29uIjpmYWxzZSwicG9zdGVkU2VsZkVtcGxveWVkUGVyc29uIjp0cnVlLCJzZWxmRW1wbG95ZWRUd29Pck1vcmVTdGF0ZXMiOmZhbHNlLCJ3b3JraW5nSW5TdGF0ZVVuZGVyMjEiOmZhbHNlfV0~WyI4YWJhYjBmMzVlYzAwOTEwMWNkZWRkZDllYmZlNzgwODVkYzI2Nzg3MmNhM2RjZTljMTNlZDJlYjIwNjAzZDVjIiwic2VjdGlvbjIiLHsiY2VydGlmaWNhdGVGb3JEdXJhdGlvbkFjdGl2aXR5Ijp0cnVlLCJkZXRlcm1pbmF0aW9uUHJvdmlzaW9uYWwiOmZhbHNlLCJlbmRpbmdEYXRlIjoiMjAyNC0wNy0wMyIsIm1lbWJlclN0YXRlV2hpY2hMZWdpc2xhdGlvbkFwcGxpZXMiOiJJVCIsInN0YXJ0aW5nRGF0ZSI6IjIwMjMtMDktMjEiLCJ0cmFuc2l0aW9uUnVsZXNBcHBseUFzRUM4ODMyMDA0IjpmYWxzZX1d~WyI3M2RjNmE2MGY5ZGMwMzgyNjJmZTE5MGM2ODE1YThhZTlhZGU0ZmU5YzFjY2JlMzIzNGY0NjJlMTRmZTgzZGQzIiwic2VjdGlvbjUiLHsibm9GaXhlZEFkZHJlc3MiOmZhbHNlLCJ3b3JrUGxhY2VBZGRyZXNzZXMiOlt7ImFkZHJlc3MiOnsiY291bnRyeUNvZGUiOiJJVCIsInBvc3RDb2RlIjoiMzQxMzIiLCJzdHJlZXRObyI6IlBpYXp6YSBEdWNhIGRlZ2xpIEFicnV6emkgMiwgNDQwIiwidG93biI6IlRyaWVzdGUifSwic2Vxbm8iOjF9XSwid29ya1BsYWNlTmFtZXMiOlt7ImNvbXBhbnlOYW1lVmVzc2VsTmFtZSI6IkFzc2ljdXJhemlvbmkgR2VuZXJhbGkgUy5wLkEiLCJzZXFubyI6MX1dfV0~WyI2OWQxN2E2ZjgzNDg2YjlhM2EwMmM0MTYyNThkNmZhMjUyOTcwZjE5Y2M4NTNjNDEyZDA4NjBkMTQ0ZDcxOTZmIiwic2VjdGlvbjYiLHsiYWRkcmVzcyI6eyJjb3VudHJ5Q29kZSI6IkJFIiwicG9zdENvZGUiOiIxMDAwIiwic3RyZWV0Tm8iOiJNYWluIFN0cmVldCAxIiwidG93biI6IkJydXNzZWxzIn0sImRhdGUiOiIyMDIzLTA5LTA3IiwiZW1haWwiOiJpbmZvQG5zc2ktYmUuZXUiLCJpbnN0aXR1dGlvbklEIjoiTlNTSS1CRS0wMSIsIm5hbWUiOiJOYXRpb25hbCBTb2NpYWwgU2VjdXJpdHkgT2ZmaWNlIiwib2ZmaWNlRmF4Tm8iOiIwODAwIDk4NzY1Iiwib2ZmaWNlUGhvbmVObyI6IjA4MDAgMTIzNDUiLCJzaWduYXR1cmUiOiJPZmZpY2lhbCBzaWduYXR1cmUifV0"
        sd_credential_subject_2 = {
            "_sd": [
                "bZk6dyk-Ng57QHfOFl6DXWxTeSGXrbQkHg868i-LJQU",
                "fwzEzX7xne2LcbzblyiCNrp8-StydRNnWPHj07bnWgQ",
                "PKcBxmF3VaFTy6_4_fIMgk5ngCKTPacD6emUNPJivOM",
                "wcG0ubIXW9ddMaOfUP4eU2y9QJEfH2z9FktGXz6Plno",
                "7ainL1JfU0f4sGuV6zeZsK_cV9fygj2hKKOoMhQqn8Y",
            ],
            "id": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbowo1MYpCJwNfzfFggXuWxdPAdAWhkp9XskU2cir7r21AxqN2TMvMTUS1FmaNWLm2esa8FLwZ35i5mRzUygDQdZRS1gC42Am9Doyh68Hp1Ksap9e9xzebDYFhhLgXTksgnG",
            "section1": {
                "_sd": ["8MmpKBpPqmuMJDnMwmWoACRlns7OGC_yzksOfcuenw0"],
                "forenames": "Charlotte",
                "nationalities": ["SE"],
                "personalIdentificationNumber": "19681229-1412",
                "placeBirth": {
                    "countryCode": "SE",
                    "region": "Stockholm",
                    "town": "Stockholm",
                },
                "sex": "Female",
                "stateOfResidenceAddress": {
                    "countryCode": "SE",
                    "postCode": "418 78",
                    "streetNo": "Gunnar Engellaus vag 8, 91 1B",
                    "town": "Stockholm",
                },
                "stateOfStayAddress": {
                    "countryCode": "SE",
                    "postCode": "418 78",
                    "streetNo": "Gunnar Engellaus vag 8, 91 1B",
                    "town": "Stockholm",
                },
                "surname": "Anderson",
                "surnameAtBirth": "Anderson",
            },
        }
        expected_credential_subject_2 = {
            "id": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbowo1MYpCJwNfzfFggXuWxdPAdAWhkp9XskU2cir7r21AxqN2TMvMTUS1FmaNWLm2esa8FLwZ35i5mRzUygDQdZRS1gC42Am9Doyh68Hp1Ksap9e9xzebDYFhhLgXTksgnG",
            "section1": {
                "forenames": "Charlotte",
                "nationalities": ["SE"],
                "personalIdentificationNumber": "19681229-1412",
                "placeBirth": {
                    "countryCode": "SE",
                    "region": "Stockholm",
                    "town": "Stockholm",
                },
                "sex": "Female",
                "stateOfResidenceAddress": {
                    "countryCode": "SE",
                    "postCode": "418 78",
                    "streetNo": "Gunnar Engellaus vag 8, 91 1B",
                    "town": "Stockholm",
                },
                "stateOfStayAddress": {
                    "countryCode": "SE",
                    "postCode": "418 78",
                    "streetNo": "Gunnar Engellaus vag 8, 91 1B",
                    "town": "Stockholm",
                },
                "surname": "Anderson",
                "surnameAtBirth": "Anderson",
                "dateBirth": "1968-12-29",
            },
            "section4": {
                "employee": False,
                "employerSelfEmployedActivityCodes": ["1889113244"],
                "nameBusinessName": "Volvo",
                "registeredAddress": {
                    "countryCode": "SE",
                    "postCode": "418 78",
                    "streetNo": "Gunnar Engellaus vu00e4g 8, 164 A",
                    "town": "Goteborg",
                },
                "selfEmployedActivity": True,
            },
            "section3": {
                "civilAndEmployedSelfEmployed": False,
                "civilServant": False,
                "contractStaff": False,
                "employedAndSelfEmployed": False,
                "employedTwoOrMoreStates": False,
                "exception": False,
                "exceptionDescription": "",
                "flightCrewMember": False,
                "mariner": False,
                "postedEmployedPerson": False,
                "postedSelfEmployedPerson": False,
                "selfEmployedTwoOrMoreStates": False,
                "workingInStateUnder21": False,
            },
            "section2": {
                "certificateForDurationActivity": True,
                "determinationProvisional": False,
                "endingDate": "2024-07-03",
                "memberStateWhichLegislationApplies": "IT",
                "startingDate": "2023-09-21",
                "transitionRulesApplyAsEC8832004": False,
            },
            "section5": {
                "noFixedAddress": False,
                "workPlaceAddresses": [
                    {
                        "address": {
                            "countryCode": "IT",
                            "postCode": "34132",
                            "streetNo": "Piazza Duca degli Abruzzi 2, 440",
                            "town": "Trieste",
                        },
                        "seqno": 1,
                    }
                ],
                "workPlaceNames": [
                    {
                        "companyNameVesselName": "Assicurazioni Generali S.p.A",
                        "seqno": 1,
                    }
                ],
            },
            "section6": {
                "address": {
                    "countryCode": "BE",
                    "postCode": "1000",
                    "streetNo": "Main Street 1",
                    "town": "Brussels",
                },
                "date": "2023-09-07",
                "email": "info@nssi-be.eu",
                "institutionID": "NSSI-BE-01",
                "name": "National Social Security Office",
                "officeFaxNo": "0800 98765",
                "officePhoneNo": "0800 12345",
                "signature": "Official signature",
            },
        }
        # Test for case 1
        disclosure_mapping = get_all_disclosures_with_sd_from_token(token=token_1)
        credential_subject_1 = decode_credential_sd_to_credential_subject(
            disclosure_mapping=disclosure_mapping,
            credential_subject=sd_credential_subject_1,
        )
        condition_1 = (
            credential_subject_1["identifier"]
            == expected_credential_subject_1["identifier"]
        )
        self.assert_(
            condition_1,
            "Expected credential subject attribute `identifier` doesn't match with result",
        )
        condition_2 = (
            credential_subject_1["legalName"]
            == expected_credential_subject_1["legalName"]
        )
        self.assert_(
            condition_2,
            "Expected credential subject attribute `legalName` doesn't match with result",
        )

        # Test for case 2
        disclosure_mapping = get_all_disclosures_with_sd_from_token(token=token_2)
        credential_subject_2 = decode_credential_sd_to_credential_subject(
            disclosure_mapping=disclosure_mapping,
            credential_subject=sd_credential_subject_2,
        )
        condition_1 = (
            credential_subject_2["section1"]["dateBirth"]
            == expected_credential_subject_2["section1"]["dateBirth"]
        )
        self.assert_(
            condition_1,
            "Expected credential subject attribute `dateBirth` doesn't match with result",
        )
        condition_2 = (
            credential_subject_2["section6"]
            == expected_credential_subject_2["section6"]
        )
        self.assert_(
            condition_2,
            "Expected credential subject attribute `section6` doesn't match with result",
        )

    async def test_create_disclosure_mapping_from_credential_definition(self):
        # Case 1
        credential_definition_1 = {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "object",
                    "limitDisclosure": False,
                    "properties": {
                        "id": {
                            "type": "object",
                            "limitDisclosure": True,
                            "properties": {
                                "legalName": {
                                    "type": "string",
                                    "limitDisclosure": False,
                                },
                            },
                        }
                    },
                },
                "legalName": {"type": "string", "limitDisclosure": False},
                "legalAddress": {"type": "string", "limitDisclosure": True},
            },
            "required": ["identifier", "legalName", "legalAddress"],
            "additionalProperties": False,
        }
        expected_disclosure_mapping_1 = {
            "credentialSubject": {
                "identifier": {"id": {"limitDisclosure": True}},
                "legalAddress": {"limitDisclosure": True},
            }
        }

        # Case 2

        credential_definition_2 = {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "object",
                    "limitDisclosure": True,
                    "properties": {
                        "id": {
                            "type": "object",
                            "limitDisclosure": True,
                            "properties": {
                                "legalName": {
                                    "type": "string",
                                    "limitDisclosure": False,
                                },
                            },
                        }
                    },
                },
                "legalName": {"type": "string", "limitDisclosure": True},
                "legalAddress": {"type": "string", "limitDisclosure": False},
            },
            "required": ["identifier", "legalName", "legalAddress"],
            "additionalProperties": False,
        }
        expected_disclosure_mapping_2 = {
            "credentialSubject": {
                "identifier": {"limitDisclosure": True},
                "legalName": {"limitDisclosure": True},
            }
        }

        # Tescase for case 1
        disclosure_mapping_1 = create_disclosure_mapping_from_credential_definition(
            credential_definition_1
        )

        condition_1 = (
            disclosure_mapping_1["credentialSubject"]["identifier"]["id"][
                "limitDisclosure"
            ]
            == expected_disclosure_mapping_1["credentialSubject"]["identifier"]["id"][
                "limitDisclosure"
            ]
        )
        self.assert_(
            condition_1,
            "Expected desclosure mapping for id field doesn't match",
        )
        condition_2 = (
            disclosure_mapping_1["credentialSubject"]["legalAddress"]
            == expected_disclosure_mapping_1["credentialSubject"]["legalAddress"]
        )
        self.assert_(
            condition_2,
            "Expected desclosure mapping for legalAddress field doesn't match",
        )

        # Tescase for case 2
        disclosure_mapping_2 = create_disclosure_mapping_from_credential_definition(
            credential_definition_2
        )

        condition_1 = (
            disclosure_mapping_2["credentialSubject"]["identifier"]
            == expected_disclosure_mapping_2["credentialSubject"]["identifier"]
        )
        self.assert_(
            condition_1,
            "Expected desclosure mapping for identifier field doesn't match",
        )
        condition_2 = (
            disclosure_mapping_2["credentialSubject"]["legalName"]
            == expected_disclosure_mapping_2["credentialSubject"]["legalName"]
        )
        self.assert_(
            condition_2,
            "Expected desclosure mapping for legalName field doesn't match",
        )


if __name__ == "__main__":
    unittest.main()
