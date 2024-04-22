import typing
import json
from dataclasses import dataclass


@dataclass
class DataAttribute:
    name: str
    description: str = ""
    limited_disclosure: bool = False
    data_type: str = "string"
    value: typing.Any = None


class DataAttributesAdapter:
    def __init__(self, data_attributes: typing.List[DataAttribute], title: str):
        self.data_attributes = data_attributes
        self.title = title

    def to_json_schema(self) -> dict:
        jsonschema = {"title": self.title, "type": "object", "properties": {}}
        properties = {}
        for data_attribute in self.data_attributes:
            layers = data_attribute.name.split(".")
            current_dict = properties
            for index, part in enumerate(layers):
                if part not in current_dict:
                    if index == len(layers) - 1:
                        current_dict[part] = {"type": data_attribute.data_type}
                    else:
                        current_dict[part] = {"type": "object", "properties": {}}
                if "properties" in current_dict[part]:
                    current_dict = current_dict[part]["properties"]
        jsonschema["properties"] = properties
        return jsonschema

    def to_credential(self):
        credential = {}
        for data_attribute in self.data_attributes:
            layers = data_attribute.name.split('.')
            current_dict = credential
            for part in layers[:-1]:
                if part not in current_dict:
                    current_dict[part] = {}
                current_dict = current_dict[part]
            current_dict[layers[-1]] = data_attribute.value
        return credential
