import unittest
from unittest import IsolatedAsyncioTestCase
from sdjwt.sdjwt import generate_did_key_from_seed, create_w3c_vc_jwt


class Test(IsolatedAsyncioTestCase):
    async def test_create_did_key(self):
        crypto_seed = "helloworld"
        key_did = await generate_did_key_from_seed(crypto_seed)
        key_did.generate()
        vc = create_w3c_vc_jwt(didkey=key_did)

        condition1 = len(vc) > 0
        self.assert_(condition1, "VC is empty")
        condition2 = len(vc.split(".")) == 3
        self.assert_(condition2, "VC doesn't contain one of header/claims/signature or all")


if __name__ == "__main__":
    unittest.main()
