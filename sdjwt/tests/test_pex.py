import unittest
import json
from unittest import IsolatedAsyncioTestCase
from sdjwt.pex import (
    match_credentials,
    MatchedCredential,
    MatchedField,
    MatchedPath,
    extract_disclosure_values,
)


class TestPEX(IsolatedAsyncioTestCase):
    async def test_match_credentials(self):
        input_descriptor = json.dumps(
            {
                "id": "ef91319b-81a5-4f71-a602-de3eacccb543",
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": [
                        {"path": ["$.credentialSubject.identifier"]},
                        {"path": ["$.credentialSubject.legalName"]},
                    ],
                },
            }
        )
        credentials = [
            json.dumps(
                {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "credentialSchema": [
                        {
                            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                            "type": "FullJsonSchemaValidator2021",
                        }
                    ],
                    "credentialSubject": {
                        "id": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnhVe3bugMJPbfkv9GcRq5ogEKVHwnudNt4jMaTMzAgQgM5Pd61nbJ3vGzjn5dqo4C9X1FTZ6RY1rv3dPg6ux6auTrWtBWtUby2KJ3BKfJmKtwAynWLNr8EqRnuz2nFPZbS",
                        "identifier": "123400-7899",
                        "legalName": "Bygg AB",
                    },
                    "expirationDate": "2024-06-07T07:07:40Z",
                    "id": "urn:did:eb2ac148-4f07-492f-aaea-b75a2acc0f98",
                    "issuanceDate": "2024-06-07T06:07:40Z",
                    "issued": "2024-06-07T06:07:40Z",
                    "issuer": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnhVe3bugMJPbfkv9GcRq5ogEKVHwnudNt4jMaTMzAgQgM5Pd61nbJ3vGzjn5dqo4C9X1FTZ6RY1rv3dPg6ux6auTrWtBWtUby2KJ3BKfJmKtwAynWLNr8EqRnuz2nFPZbS",
                    "type": ["VerifiableLegalPersonalIdentificationData"],
                    "validFrom": "2024-06-07T06:07:40Z",
                }
            ),
            json.dumps(
                {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "credentialSchema": [
                        {
                            "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                            "type": "FullJsonSchemaValidator2021",
                        }
                    ],
                    "credentialSubject": {
                        "id": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnhVe3bugMJPbfkv9GcRq5ogEKVHwnudNt4jMaTMzAgQgM5Pd61nbJ3vGzjn5dqo4C9X1FTZ6RY1rv3dPg6ux6auTrWtBWtUby2KJ3BKfJmKtwAynWLNr8EqRnuz2nFPZbS",
                        "activity": "Construction Industry",
                        "legalForm": "Aktiebolag",
                        "legalStatus": "ACTIVE",
                        "name": "Bygg AB",
                        "orgNumber": "123400-7899",
                        "registeredAddress": {
                            "adminUnitLevel1": "SE",
                            "fullAddress": "Sveavägen 48, 111 34 Stockholm, Sweden",
                            "locatorDesignator": "48",
                            "postCode": "111 34",
                            "postName": "Stockholm",
                            "thoroughFare": "Sveavägen",
                        },
                        "registrationDate": "2005-10-08",
                    },
                    "expirationDate": "2024-06-07T12:52:04Z",
                    "id": "urn:did:f43432ff-6363-44a6-ba12-82e6c5b41c8a",
                    "issuanceDate": "2024-06-07T11:52:04Z",
                    "issued": "2024-06-07T11:52:04Z",
                    "issuer": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnhVe3bugMJPbfkv9GcRq5ogEKVHwnudNt4jMaTMzAgQgM5Pd61nbJ3vGzjn5dqo4C9X1FTZ6RY1rv3dPg6ux6auTrWtBWtUby2KJ3BKfJmKtwAynWLNr8EqRnuz2nFPZbS",
                    "type": ["VerifiableCertificateOfRegistration"],
                    "validFrom": "2024-06-07T11:52:04Z",
                }
            ),
        ]

        expected_matched_credentials = (
            [
                MatchedCredential(
                    index=0,
                    fields=[
                        MatchedField(
                            index=0,
                            path=MatchedPath(
                                path="$.credentialSubject.identifier",
                                index=0,
                                value="123400-7899",
                            ),
                        ),
                        MatchedField(
                            index=1,
                            path=MatchedPath(
                                path="$.credentialSubject.legalName",
                                index=0,
                                value="Bygg AB",
                            ),
                        ),
                    ],
                )
            ],
            None,
        )

        matched_credentials = match_credentials(
            input_descriptor_json=input_descriptor, credentials=credentials
        )

        condition_1 = matched_credentials == expected_matched_credentials
        self.assert_(
            condition_1,
            "Expected matched credential doesn't match with result",
        )

    async def test_extract_disclosure_values(self):
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "credentialSchema": [
                {
                    "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                    "type": "FullJsonSchemaValidator2021",
                }
            ],
            "credentialSubject": {
                "_sd": ["7sCYwjBINYYha3SbjxvLpdt8q-uUjcxA0HC5z2N15Vs"],
                "activity": "test",
                "id": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnhVe3bugMJPbfkv9GcRq5ogEKVHwnudNt4jMaTMzAgQgM5Pd61nbJ3vGzjn5dqo4C9X1FTZ6RY1rv3dPg6ux6auTrWtBWtUby2KJ3BKfJmKtwAynWLNr8EqRnuz2nFPZbS",
                "legalForm": "tt",
                "name": "test",
                "orgNumber": "1111",
                "registeredAddress": {
                    "_sd": [
                        "WgasKnzLW0ZxJ4tUg_INr0Qs51DLqda_A_JXadqM1Iw",
                        "UkbKFenSPl93IJ5H4QcreNahGQG_KNu0_OjbmUcyTu4",
                        "Fk1TPdjypTc-vwLSet2FrjTNevtZFqJIea_-RDyE1D4",
                    ],
                    "fullAddress": "wee6",
                    "postCode": "jko",
                    "postName": "dfgg",
                },
                "registrationDate": "14-06-2024",
            },
            "expirationDate": "2024-06-14T10:58:04Z",
            "id": "urn:did:9b0757ae-450b-4775-b680-15ab0c4a83a0",
            "issuanceDate": "2024-06-14T09:58:04Z",
            "issued": "2024-06-14T09:58:04Z",
            "issuer": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnhVe3bugMJPbfkv9GcRq5ogEKVHwnudNt4jMaTMzAgQgM5Pd61nbJ3vGzjn5dqo4C9X1FTZ6RY1rv3dPg6ux6auTrWtBWtUby2KJ3BKfJmKtwAynWLNr8EqRnuz2nFPZbS",
            "type": ["VerifiableCertificateOfRegistration"],
            "validFrom": "2024-06-14T09:58:04Z",
        }


        disclosure = {
            "7sCYwjBINYYha3SbjxvLpdt8q-uUjcxA0HC5z2N15Vs": "WyI1YjU2ZGU2ZjUzZWFmYjQ2NzAzYmRjMTU3NmE2MzE2ZDZlZmI5Mjk0ZDgyNzUyODI4NTI5ZDIzNTJhY2ZkNWZlIiwibGVnYWxTdGF0dXMiLCJ0ZXN0Il0",
            "WgasKnzLW0ZxJ4tUg_INr0Qs51DLqda_A_JXadqM1Iw": "WyI1NDNkMWNiMmE5MGNkM2ExMmVjNmFlZDRmZTI1YjljY2RiNmU3MmI5N2I1YTZkNTI4OWYzM2ZlYTZiMzA2YWU0IiwiYWRtaW5Vbml0TGV2ZWwxIiwidHkiXQ",
            "UkbKFenSPl93IJ5H4QcreNahGQG_KNu0_OjbmUcyTu4": "WyIwMThlN2VkYmRlNzkyMzhiNTAzNDBiMzNhNDM3ODRmYWFhYWViNTdlNWM4YzZlZjY5MTlmODM2MGZkMzdjMDRhIiwibG9jYXRvckRlc2lnbmF0b3IiLCJ0dTkiXQ",
            "Fk1TPdjypTc-vwLSet2FrjTNevtZFqJIea_-RDyE1D4": "WyIyNTBjY2U3YzAyZDI5YzRhNGZmOTkzZmU1MDFiY2IzYWMxMDAyNmU0MjhhNGMyOTdjMDcwOTg0OGY4NGRjMTQ2IiwidGhvcm91Z2hGYXJlIiwidmJibiJd",
        }

        input_descriptor = {
            "id": "ef91319b-81a5-4f71-a602-de3eacccb543",
            "constraints": {
                "limit_disclosure": "required",
                "fields": [
                    {"path": ["$.credentialSubject.registeredAddress.adminUnitLevel1"]},
                    {"path": ["$.credentialSubject.registeredAddress.locatorDesignator"]},
                    {"path": ["$.credentialSubject.legalStatus"]},
                    {
                        "path": ["$.credentialSubject.legalForm"],
                        "filter": {"type": "string", "const": "EKM"},
                    },
                ],
            },
        }
        expected_disclosures = ['WyI1NDNkMWNiMmE5MGNkM2ExMmVjNmFlZDRmZTI1YjljY2RiNmU3MmI5N2I1YTZkNTI4OWYzM2ZlYTZiMzA2YWU0IiwiYWRtaW5Vbml0TGV2ZWwxIiwidHkiXQ', 'WyIwMThlN2VkYmRlNzkyMzhiNTAzNDBiMzNhNDM3ODRmYWFhYWViNTdlNWM4YzZlZjY5MTlmODM2MGZkMzdjMDRhIiwibG9jYXRvckRlc2lnbmF0b3IiLCJ0dTkiXQ', 'WyI1YjU2ZGU2ZjUzZWFmYjQ2NzAzYmRjMTU3NmE2MzE2ZDZlZmI5Mjk0ZDgyNzUyODI4NTI5ZDIzNTJhY2ZkNWZlIiwibGVnYWxTdGF0dXMiLCJ0ZXN0Il0']

        disclosures = extract_disclosure_values(input_descriptor=input_descriptor,credential=credential,disclosure=disclosure)

        condition_1 = disclosures == expected_disclosures
        self.assert_(
            condition_1,
            "Expected disclosures doesn't match with result",
        )

        condition_2 = disclosures[0] == expected_disclosures[0]
        self.assert_(
            condition_1,
            "Expected disclosure doesn't match with result",
        )


if __name__ == "__main__":
    unittest.main()
