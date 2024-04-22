import unittest
from unittest import TestCase
from sdjwt.adapter import DataAttribute, DataAttributesAdapter


class TestDataAttributesAdapter(TestCase):
    def test_to_json_schema(self):
        data_attributes = [
            DataAttribute(
                name="age",
                description="Age of the individual",
                data_type="number",
            ),
            DataAttribute(
                name="vaccine.medicinalProductName",
                description="Product name",
                data_type="string",
            ),
        ]
        adapter = DataAttributesAdapter(data_attributes=data_attributes, title="VaccinationCertificate")
        out = adapter.to_json_schema()

        expect = {"type": "object", "title": "VaccinationCertificate",
                  "properties": {"age": {"type": "number"},
                                 "vaccine": {"type": "object", "properties": {
                                     "medicinalProductName": {"type": "string"}}}}}
        self.assertDictEqual(out, expect)
    
    def test_to_credential(self):
        data_attributes = [
                DataAttribute(
                    name="age",
                    value=25,
                ),
                DataAttribute(
                    name="vaccine.medicinalProductName",
                    value="Moderna",
                ),
            ]
        t = DataAttributesAdapter(data_attributes=data_attributes, title="VaccinationCertificate")
        out = t.to_credential()

        expect = {"age": 25, "vaccine": {"medicinalProductName": "Moderna"}}
        self.assertDictEqual(out, expect)


if __name__ == "__main__":
    unittest.main()
