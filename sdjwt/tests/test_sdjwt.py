import unittest
from unittest import IsolatedAsyncioTestCase
from sdjwt.sdjwt import generate_did_key_from_seed, create_w3c_vc_jwt


class Test(IsolatedAsyncioTestCase):
    async def test_create_w3c_vc_jwt(self):
        crypto_seed = "helloworld"
        key_did = await generate_did_key_from_seed(crypto_seed)
        key_did.generate()
        vc = create_w3c_vc_jwt(didkey=key_did)

        condition1 = len(vc) > 0
        self.assert_(condition1, "VC is empty")
        condition2 = len(vc.split(".")) == 3
        self.assert_(condition2, "VC doesn't contain one of header/claims/signature or all")

    async def test_create_sd_jwt_for_flat_passport(self):
        """
        Passport claims is as below:
        {
            "name": "Jane Doe",
            "address": "Kochi",
            "age": 22,
            "country": "IN"
        }

        Passport SD-JWT should then look like below:
        {
            ...
            "_sd": [
                "L2CsUNcwmJCugCEZ7prOT0z1-I5cBJihOAz-I0RX_M0",
                "Ebc3DRFV7dHBgKbUloME2Uv9qHbp7lz9jIOrEzjapJY",
                "cDYOavCaPigty_P2NpYElIIzGf4jz5lYQ-pPMbvuJw8",
                "OMaA6Aw2vVCBXzIjS2KdID1jA64vn7nhLeYmwuPRbbA"
            ]
            ...
        }

        Disclosures is as below

        ~WyJiMWQyNjNmMmI2ZWNjYzVjZTEzZmY1YTAwYzYyNDE0MSIsIm5hbWUiLCJKYW5lIERvZSJd
        ~WyJhNDM3N2U4Y2MyN2MzMzc0ODg0OWI3YjZiYWExODgyMiIsImFkZHJlc3MiLCJLb2NoaSJd
        ~WyJiYTBjM2UzNGMxYWU5YzMwZmIwYjA3ZWNiNDc1N2Y2MSIsImFnZSIsMjJd
        ~WyI0YjJkY2ViYmQ4MzUyOTBlNTk2Y2NkNzY3NGRmYTE2ZCIsImNvdW50cnkiLCJJTiJd

        """
        raise NotImplementedError("error")

    async def test_create_sd_jwt_for_w3c_vc_passport(self):
        """
        Passport SD-JWT should then look like below:
        {
            "vc": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1"
                ],
                "credentialSchema": [
                    {
                        "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
                        "type": "FullJsonSchemaValidator2021"
                    }
                ],
                "credentialSubject": {
                    "_sd": [
                        "1V_K-8lDQ8iFXBFXbZY9ehqR4HabWCi5T0ybIzZPeww",
                        "JzjLgtP29dP-B3td12P674gFmK2zy81HMtBgf6CJNWg",
                        "R2fGbfA07Z_YlkqmNZyma1xyyx1XstIiS6B1Ybl2JZ4",
                        "TCmzrl7K2gev_du7pcMIyzRLHp-Yeg-Fl_cxtrUvPxg",
                        "V7kJBLK78TmVDOmrfJ7ZuUPHuK_2cc7yZRa4qV1txwM",
                        "b0eUsvGP-ODDdFoY4NlzlXc3tDslWJtCJF75Nw8Oj_g",
                        "zJK_eSMXjwM8dXmMZLnI8FGM08zJ3_ubGeEMJ-5TBy0"
                    ]
                },
                "expirationDate": "2024-04-19T13:19:12Z",
                "id": "urn:did:abc",
                "issuanceDate": "2024-04-19T12:19:12Z",
                "issued": "2024-04-19T12:19:12Z",
                "issuer": "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbptQwoaj2VP1S6Ahzo7REFCT4NBTPYdQinCZbCcyoqWKi9Q2uEW36DNSXhCwiYnGz6BAZkzytQAEBE5cPidCGnadH4SsLDbSZeG2SEChrqvQpdK4Mk8H32vs3B5g8Wr7kcc",
                "type": [
                    "Passport"
                ],
                "validFrom": "2024-04-19T12:19:12Z"
            }
        }

        Disclosures is as below ...

        """
        raise NotImplementedError("error")

if __name__ == "__main__":
    unittest.main()
