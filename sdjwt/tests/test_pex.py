import unittest
import json
from unittest import IsolatedAsyncioTestCase
from sdjwt.pex import (
    match_credentials,
    MatchedCredential,
    MatchedField,
    MatchedPath,
    extract_disclosure_values,
    match_credentials_for_sd_jwt,
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
                    {
                        "path": [
                            "$.credentialSubject.registeredAddress.locatorDesignator"
                        ]
                    },
                    {"path": ["$.credentialSubject.legalStatus"]},
                    {
                        "path": ["$.credentialSubject.legalForm"],
                        "filter": {"type": "string", "const": "EKM"},
                    },
                ],
            },
        }
        expected_disclosures = [
            "WyI1NDNkMWNiMmE5MGNkM2ExMmVjNmFlZDRmZTI1YjljY2RiNmU3MmI5N2I1YTZkNTI4OWYzM2ZlYTZiMzA2YWU0IiwiYWRtaW5Vbml0TGV2ZWwxIiwidHkiXQ",
            "WyIwMThlN2VkYmRlNzkyMzhiNTAzNDBiMzNhNDM3ODRmYWFhYWViNTdlNWM4YzZlZjY5MTlmODM2MGZkMzdjMDRhIiwibG9jYXRvckRlc2lnbmF0b3IiLCJ0dTkiXQ",
            "WyI1YjU2ZGU2ZjUzZWFmYjQ2NzAzYmRjMTU3NmE2MzE2ZDZlZmI5Mjk0ZDgyNzUyODI4NTI5ZDIzNTJhY2ZkNWZlIiwibGVnYWxTdGF0dXMiLCJ0ZXN0Il0",
        ]

        disclosures = extract_disclosure_values(
            input_descriptor=input_descriptor,
            credential=credential,
            disclosure=disclosure,
        )

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

    async def test_match_credentials_for_sd_jwt(self):
        credentials = [
            {
                "73c30c00-8188-481d-b983-dd3528081c18": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHBZRnp1NnlRNWZ0cExibnV4RFNON3RaS29wdTNwWXJzem94RXdRaHFkOUhWdmdlOUpGamU1YjlNd3pVb1g2MVByQ01nc1hkQ2p0TEFzTTdWQk5kNmk1M3ZTQ2g5b3gyN0RMRUd3Mm5YTTJGaVZSTmRuaTVxSGlHZTR5RDVDZEJyayN6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwcFlGenU2eVE1ZnRwTGJudXhEU043dFpLb3B1M3BZcnN6b3hFd1FocWQ5SFZ2Z2U5SkZqZTViOU13elVvWDYxUHJDTWdzWGRDanRMQXNNN1ZCTmQ2aTUzdlNDaDlveDI3RExFR3cyblhNMkZpVlJOZG5pNXFIaUdlNHlENUNkQnJrIiwidHlwIjoiSldUIn0.eyJleHAiOjE3MjM5MjcxODAsImlhdCI6MTcyMTMzNTE4MCwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwcFlGenU2eVE1ZnRwTGJudXhEU043dFpLb3B1M3BZcnN6b3hFd1FocWQ5SFZ2Z2U5SkZqZTViOU13elVvWDYxUHJDTWdzWGRDanRMQXNNN1ZCTmQ2aTUzdlNDaDlveDI3RExFR3cyblhNMkZpVlJOZG5pNXFIaUdlNHlENUNkQnJrIiwianRpIjoidXJuOmRpZDpiNGNhYmFkMC1hMDg3LTQyZGEtODU0Yi00ZWE4MThlM2ZjMjgiLCJuYmYiOjE3MjEzMzUxODAsInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticThlY05BQ3RpbWRKakFtYVQ3TDJWR3JKZWlXRXVGeDFkU2ZuUFZTdlBVQUpuaG96bmY0cEp0WHA5czdvWTZMaEJMaHNEQ0VQTkdjTW5pU0F4ODJ3SjNrODNpejduTUFteHRYbXFOWlJTTWRaeWlMQTI4NFZORkJrMzQ3c1BTeUxGTiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOlt7ImlkIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS90cnVzdGVkLXNjaGVtYXMtcmVnaXN0cnkvdjIvc2NoZW1hcy96M01nVUZVa2I3MjJ1cTR4M2R2NXlBSm1uTm16REZlSzVVQzh4ODNRb2VMSk0iLCJ0eXBlIjoiRnVsbEpzb25TY2hlbWFWYWxpZGF0b3IyMDIxIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsicExXTmczQ2o3aHVHbmZsNllHdjd3dVZUWThETzg3OGNqWGxYMXFJcFM4YyIsIlhPcGViRUJFbTdvMHloSUNKc0dWRG5IUUl3Y2JZbFpCVjR0YWpYdGpkSWsiXSwiaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnE4ZWNOQUN0aW1kSmpBbWFUN0wyVkdySmVpV0V1RngxZFNmblBWU3ZQVUFKbmhvem5mNHBKdFhwOXM3b1k2TGhCTGhzRENFUE5HY01uaVNBeDgyd0ozazgzaXo3bk1BbXh0WG1xTlpSU01kWnlpTEEyODRWTkZCazM0N3NQU3lMRk4ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI0LTA4LTE3VDIwOjM5OjQwWiIsImlkIjoidXJuOmRpZDpiNGNhYmFkMC1hMDg3LTQyZGEtODU0Yi00ZWE4MThlM2ZjMjgiLCJpc3N1YW5jZURhdGUiOiIyMDI0LTA3LTE4VDIwOjM5OjQwWiIsImlzc3VlZCI6IjIwMjQtMDctMThUMjA6Mzk6NDBaIiwiaXNzdWVyIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwcFlGenU2eVE1ZnRwTGJudXhEU043dFpLb3B1M3BZcnN6b3hFd1FocWQ5SFZ2Z2U5SkZqZTViOU13elVvWDYxUHJDTWdzWGRDanRMQXNNN1ZCTmQ2aTUzdlNDaDlveDI3RExFR3cyblhNMkZpVlJOZG5pNXFIaUdlNHlENUNkQnJrIiwidHlwZSI6WyJWZXJpZmlhYmxlTGVnYWxQZXJzb25hbERhdGEyIl0sInZhbGlkRnJvbSI6IjIwMjQtMDctMThUMjA6Mzk6NDBaIn19.SZiOPw6V8uWHbIlwXVo6bYNNxVQEiU7diprOHQlmHkEIcIF5v2jPCmYfqWK5nQxkN1CxV81OMmUtX4tc-jVDgw~WyJlMzRhOGE2OGU3Y2RiMGFhZWVkOGJkY2MxOTQ5NmI2MTgzZWYzMmRlMTI3ZDVlODZiODdkZDY5ZTdhNjJmYzNjIiwiaWRlbnRpZmllciIsIjAwMCJd~WyJiODkzZGFiNTAxZTAxMDdhM2Y5NTI5ZDg1MTNhODdiZjQwNWI0MTQ4YTEyZjViMDczMDExZDEzOTBhNGM4ZDlhIiwibGVnYWxOYW1lIiwiYWxiaW4iXQ"
            },
            {
                "915cf847-f870-41cf-a4e8-60282db6cde7": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHBZRnp1NnlRNWZ0cExibnV4RFNON3RaS29wdTNwWXJzem94RXdRaHFkOUhWdmdlOUpGamU1YjlNd3pVb1g2MVByQ01nc1hkQ2p0TEFzTTdWQk5kNmk1M3ZTQ2g5b3gyN0RMRUd3Mm5YTTJGaVZSTmRuaTVxSGlHZTR5RDVDZEJyayN6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwcFlGenU2eVE1ZnRwTGJudXhEU043dFpLb3B1M3BZcnN6b3hFd1FocWQ5SFZ2Z2U5SkZqZTViOU13elVvWDYxUHJDTWdzWGRDanRMQXNNN1ZCTmQ2aTUzdlNDaDlveDI3RExFR3cyblhNMkZpVlJOZG5pNXFIaUdlNHlENUNkQnJrIiwidHlwIjoiSldUIn0.eyJleHAiOjE3MjM5MjczNTMsImlhdCI6MTcyMTMzNTM1MywiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwcFlGenU2eVE1ZnRwTGJudXhEU043dFpLb3B1M3BZcnN6b3hFd1FocWQ5SFZ2Z2U5SkZqZTViOU13elVvWDYxUHJDTWdzWGRDanRMQXNNN1ZCTmQ2aTUzdlNDaDlveDI3RExFR3cyblhNMkZpVlJOZG5pNXFIaUdlNHlENUNkQnJrIiwianRpIjoidXJuOmRpZDoxMGRmYTM4MC0wODFlLTQxMDMtYWQ0Ni1hODU4NzUwZTJiOWQiLCJuYmYiOjE3MjEzMzUzNTMsInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticThlY05BQ3RpbWRKakFtYVQ3TDJWR3JKZWlXRXVGeDFkU2ZuUFZTdlBVQUpuaG96bmY0cEp0WHA5czdvWTZMaEJMaHNEQ0VQTkdjTW5pU0F4ODJ3SjNrODNpejduTUFteHRYbXFOWlJTTWRaeWlMQTI4NFZORkJrMzQ3c1BTeUxGTiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOlt7ImlkIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS90cnVzdGVkLXNjaGVtYXMtcmVnaXN0cnkvdjIvc2NoZW1hcy96M01nVUZVa2I3MjJ1cTR4M2R2NXlBSm1uTm16REZlSzVVQzh4ODNRb2VMSk0iLCJ0eXBlIjoiRnVsbEpzb25TY2hlbWFWYWxpZGF0b3IyMDIxIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiWExKaGQzTXNVSFdMaDlCTFg0UWVlTmJ1RWJTR2REX2cwR0hQV0FGNjFBTSIsIjlwUndDdEdfM21qblUxdDRGcTU1SEJ1OWZmbTJZdUl4bGlHOWl6YmE1bFUiXSwiaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnE4ZWNOQUN0aW1kSmpBbWFUN0wyVkdySmVpV0V1RngxZFNmblBWU3ZQVUFKbmhvem5mNHBKdFhwOXM3b1k2TGhCTGhzRENFUE5HY01uaVNBeDgyd0ozazgzaXo3bk1BbXh0WG1xTlpSU01kWnlpTEEyODRWTkZCazM0N3NQU3lMRk4ifSwiZXhwaXJhdGlvbkRhdGUiOiIyMDI0LTA4LTE3VDIwOjQyOjMzWiIsImlkIjoidXJuOmRpZDoxMGRmYTM4MC0wODFlLTQxMDMtYWQ0Ni1hODU4NzUwZTJiOWQiLCJpc3N1YW5jZURhdGUiOiIyMDI0LTA3LTE4VDIwOjQyOjMzWiIsImlzc3VlZCI6IjIwMjQtMDctMThUMjA6NDI6MzNaIiwiaXNzdWVyIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwcFlGenU2eVE1ZnRwTGJudXhEU043dFpLb3B1M3BZcnN6b3hFd1FocWQ5SFZ2Z2U5SkZqZTViOU13elVvWDYxUHJDTWdzWGRDanRMQXNNN1ZCTmQ2aTUzdlNDaDlveDI3RExFR3cyblhNMkZpVlJOZG5pNXFIaUdlNHlENUNkQnJrIiwidHlwZSI6WyJWZXJpZmlhYmxlTGVnYWxQZXJzb25hbElkZW50aWZpY2F0aW9uRGF0YSJdLCJ2YWxpZEZyb20iOiIyMDI0LTA3LTE4VDIwOjQyOjMzWiJ9fQ.IRQebpnVr3vx8r8nrFKRnyGZltR_eDU4kgFxUa2sBoFr3RWu5ZBTtNLBVCOqT1EfawtA1ix1ScGRWZ5NJEkpFA~WyJiZDgwY2FlZWM2NzIxMWI2NGEwNTc4ZjViZDc5MDViMWQ1ZTRjZTJiMmI5Y2UxZDE1ODMxNzdjOTkwMDhjN2U5IiwiaWRlbnRpZmllciIsIjAwMCJd~WyJlM2U0YmY4ZmU4YThlNmM1NGU4ZjdkNjcwNDRlMDM1OTE0MWZmYTIwOWMzOGYzYTdlNTY1MmVkZTkxOGExMWE2IiwibGVnYWxOYW1lIiwiYWwiXQ"
            },
            {
                "0bd0cdd3-58c1-4192-a0b2-2853b7f4d283": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHBZRnp1NnlRNWZ0cExibnV4RFNON3RaS29wdTNwWXJzem94RXdRaHFkOUhWdmdlOUpGamU1YjlNd3pVb1g2MVByQ01nc1hkQ2p0TEFzTTdWQk5kNmk1M3ZTQ2g5b3gyN0RMRUd3Mm5YTTJGaVZSTmRuaTVxSGlHZTR5RDVDZEJyayN6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwcFlGenU2eVE1ZnRwTGJudXhEU043dFpLb3B1M3BZcnN6b3hFd1FocWQ5SFZ2Z2U5SkZqZTViOU13elVvWDYxUHJDTWdzWGRDanRMQXNNN1ZCTmQ2aTUzdlNDaDlveDI3RExFR3cyblhNMkZpVlJOZG5pNXFIaUdlNHlENUNkQnJrIiwidHlwIjoiSldUIn0.eyJleHAiOjE3MjM5ODIxMDEsImlhdCI6MTcyMTM5MDEwMSwiaXNzIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JwcFlGenU2eVE1ZnRwTGJudXhEU043dFpLb3B1M3BZcnN6b3hFd1FocWQ5SFZ2Z2U5SkZqZTViOU13elVvWDYxUHJDTWdzWGRDanRMQXNNN1ZCTmQ2aTUzdlNDaDlveDI3RExFR3cyblhNMkZpVlJOZG5pNXFIaUdlNHlENUNkQnJrIiwianRpIjoidXJuOmRpZDo5OTY3MTY1Mi03Zjg4LTQyMmQtOTg3Yi0wMTNmODE5NDg1OTAiLCJuYmYiOjE3MjEzOTAxMDEsInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticThlY05BQ3RpbWRKakFtYVQ3TDJWR3JKZWlXRXVGeDFkU2ZuUFZTdlBVQUpuaG96bmY0cEp0WHA5czdvWTZMaEJMaHNEQ0VQTkdjTW5pU0F4ODJ3SjNrODNpejduTUFteHRYbXFOWlJTTWRaeWlMQTI4NFZORkJrMzQ3c1BTeUxGTiIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sImNyZWRlbnRpYWxTY2hlbWEiOlt7ImlkIjoiaHR0cHM6Ly9hcGktY29uZm9ybWFuY2UuZWJzaS5ldS90cnVzdGVkLXNjaGVtYXMtcmVnaXN0cnkvdjIvc2NoZW1hcy96M01nVUZVa2I3MjJ1cTR4M2R2NXlBSm1uTm16REZlSzVVQzh4ODNRb2VMSk0iLCJ0eXBlIjoiRnVsbEpzb25TY2hlbWFWYWxpZGF0b3IyMDIxIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJfc2QiOlsiTUVmQUhQcXljamNndEdTLUZ4ZVQzcWhvQi1XUFNsQlNfWDhCSFNxSUYzRSIsIi14MEJ6WUV3dE80Nmd5bC12UFk5VTA2WHVVMG9uSWZuYjlzSXVvNUozZjAiLCJYaXNCS3dpVU5tS1NTbVFta3NiaUluR01vZHNQcDZHQnNGLWxmOVAtckU4IiwiN0ZBaDhGa2ZxcVpEa2N6X0dvd3UyejBNX1dsWV85ZXZyRTQ0aDFLdGtPVSIsIjNGNXl2bFpSMmN5UkMwaGh4QUhJMW51aThGMzZBZFQxUjF0dlM4Tk11S1kiLCJ0d0FPaUdvejF4SXdZdE5hX3hHWnJhTUgwclNSdFhtRHl0eXBzdGJCWGxZIl0sImlkIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxOGVjTkFDdGltZEpqQW1hVDdMMlZHckplaVdFdUZ4MWRTZm5QVlN2UFVBSm5ob3puZjRwSnRYcDlzN29ZNkxoQkxoc0RDRVBOR2NNbmlTQXg4MndKM2s4M2l6N25NQW14dFhtcU5aUlNNZFp5aUxBMjg0Vk5GQmszNDdzUFN5TEZOIiwibGVnYWxGb3JtIjoiYWRjIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNC0wOC0xOFQxMTo1NTowMVoiLCJpZCI6InVybjpkaWQ6OTk2NzE2NTItN2Y4OC00MjJkLTk4N2ItMDEzZjgxOTQ4NTkwIiwiaXNzdWFuY2VEYXRlIjoiMjAyNC0wNy0xOVQxMTo1NTowMVoiLCJpc3N1ZWQiOiIyMDI0LTA3LTE5VDExOjU1OjAxWiIsImlzc3VlciI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUticHBZRnp1NnlRNWZ0cExibnV4RFNON3RaS29wdTNwWXJzem94RXdRaHFkOUhWdmdlOUpGamU1YjlNd3pVb1g2MVByQ01nc1hkQ2p0TEFzTTdWQk5kNmk1M3ZTQ2g5b3gyN0RMRUd3Mm5YTTJGaVZSTmRuaTVxSGlHZTR5RDVDZEJyayIsInR5cGUiOlsiVmVyaWZpYWJsZUNlcnRpZmljYXRlT2ZSZWdpc3RyYXRpb24iXSwidmFsaWRGcm9tIjoiMjAyNC0wNy0xOVQxMTo1NTowMVoifX0.JQYvx-ET6GmiqhIseNvvcyGNg2EYnIKyb0I4gF3InfDy2aadxGzCZNuvMSq2zKfcPFKkFiFYUdVQZqdHffamZw~WyI5ODQyNDEyOGU5MDA5YWI4MTJmMGZkOWUxNzdlYzY5NTRlNzIxNWMzMjcwMzIzNGRkM2M0MmRlN2RiODcxOWRhIiwibmFtZSIsInRlc3QiXQ~WyI3Y2ZiOWNmZmVmODFmNTRlYTQ4YjI4YzY2MTViYjQxZjNiMDhhNjJlYTQ1MWJkYWYxOGQ4MmExYTA2Mzk5OWIxIiwiYWN0aXZpdHkiLCJhYmMiXQ~WyI5Njc5YTU3YWJlMTQ5ZWRmZjQ2NDg1NDEwZTliZjU0NzE1ODJmZDJlYjYyZDhhMjY3ZDJmNWQ3Y2I1NzBkNzgzIiwicmVnaXN0cmF0aW9uRGF0ZSIsIjMyMSJd~WyJiY2QyZjVkNWU5NzM3Yjk2MDRkNGQ0NDU1YjJhODFhMTAzMjY5NDlhNzcwODQwMGY1YjYwMGI1MDQ5NTAzYTNmIiwibGVnYWxTdGF0dXMiLCJhc2FkZmEiXQ~WyI5NjMwZWE5ZDk4Yzk1MmFlNTRjOWU4YTQxZDY1YWIwNWFlNjNkODQ1Yzc3Y2IwNjQxNjc5Nzc2ZmFkN2UxY2E1IiwicmVnaXN0ZXJlZEFkZHJlc3MiLHsiYWRtaW5Vbml0TGV2ZWwxIjoiMSIsImZ1bGxBZGRyZXNzIjoiMiIsImxvY2F0b3JEZXNpZ25hdG9yIjoiMyIsInBvc3RDb2RlIjoiNCIsInBvc3ROYW1lIjoiNSIsInRob3JvdWdoRmFyZSI6IjYifV0~WyI0OTA3NjRmZmFhYTBkMDFlNzAwMjFjMjcxNTA4ZjU0YmUxNDU3ZmQ2YjJiMDg5MWYwNDJkZTExMTgwMTNiYmQzIiwib3JnTnVtYmVyIiwiMTIzIl0"
            },
        ]
        input_descriptor = json.dumps(
            {
                "constraints": {
                    "fields": [
                        {
                            "filter": {
                                "contains": {
                                    "const": "VerifiableCertificateOfRegistration"
                                },
                                "type": "array",
                            },
                            "path": ["$.type"],
                        },
                        {"path": ["$.credentialSubject.name"]},
                        {"path": ["$.credentialSubject.legalForm"]},
                        {"path": ["$.credentialSubject.adminUnitLevel1"]},
                    ],
                    "limit_disclosure": "required",
                },
                "id": "95d57868-11c7-4726-870b-71b0a8af4cb1",
            }
        )
        matched_credentials = match_credentials_for_sd_jwt(
            input_descriptor_json=input_descriptor, credentials=credentials
        )

        expected_matched_credentials = ([], None)
        condition_1 = matched_credentials == expected_matched_credentials
        self.assert_(
            condition_1,
            f"Expected matched credential doesn't match with result",
        )

        input_descriptor_2 = json.dumps(
            {
                "constraints": {
                    "fields": [
                        {
                            "filter": {
                                "contains": {
                                    "const": "VerifiableCertificateOfRegistration"
                                },
                                "type": "array",
                            },
                            "path": ["$.type"],
                        },
                        {"path": ["$.credentialSubject.name"]},
                        {"path": ["$.credentialSubject.legalForm"]},
                        {"path": ["$.credentialSubject.registeredAddress"]},
                    ],
                    "limit_disclosure": "required",
                },
                "id": "95d57868-11c7-4726-870b-71b0a8af4cb1",
            }
        )
        matched_credentials = match_credentials_for_sd_jwt(
            input_descriptor_json=input_descriptor_2, credentials=credentials
        )

        expected_matched_credentials = (
            [
                MatchedCredential(
                    index="0bd0cdd3-58c1-4192-a0b2-2853b7f4d283",
                    fields=[
                        MatchedField(
                            index=0,
                            path=MatchedPath(
                                path="$.type",
                                index=0,
                                value=["VerifiableCertificateOfRegistration"],
                            ),
                        ),
                        MatchedField(
                            index=1,
                            path=MatchedPath(
                                path="$.credentialSubject.name", index=0, value="test"
                            ),
                        ),
                        MatchedField(
                            index=2,
                            path=MatchedPath(
                                path="$.credentialSubject.legalForm",
                                index=0,
                                value="adc",
                            ),
                        ),
                        MatchedField(
                            index=3,
                            path=MatchedPath(
                                path="$.credentialSubject.registeredAddress",
                                index=0,
                                value={
                                    "adminUnitLevel1": "1",
                                    "fullAddress": "2",
                                    "locatorDesignator": "3",
                                    "postCode": "4",
                                    "postName": "5",
                                    "thoroughFare": "6",
                                },
                            ),
                        ),
                    ],
                )
            ],
            None,
        )
        condition_2 = matched_credentials == expected_matched_credentials
        self.assert_(
            condition_2,
            f"Expected matched credential doesn't match with result",
        )


if __name__ == "__main__":
    unittest.main()
