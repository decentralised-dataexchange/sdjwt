import typing
import json
from dataclasses import dataclass


@dataclass
class DataAttribute:
    name: str
    description: str = ""
    limited_disclosure: typing.Optional[bool] = False
    data_type: str = "string"
    value: any = None


class DataAttributesAdapter:
    def __init__(self, data_attributes: typing.List[DataAttribute]):
        self.data_attributes = data_attributes

    def to_json_schema(self) -> dict:
        jsonschema = {"type": "object", "properties": {}}
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
            layers = data_attribute.name.split(".")
            current_dict = credential
            for part in layers[:-1]:
                if part not in current_dict:
                    current_dict[part] = {}
                current_dict = current_dict[part]
            current_dict[layers[-1]] = data_attribute.value
        return credential

    @classmethod
    def from_json_schema(cls, schema: dict):
        data_attributes = cls._from_json_schema(schema)
        return cls(data_attributes)

    @classmethod
    def from_credential(cls, credential: dict):
        data_attributes = cls._from_credential(credential)
        return cls(data_attributes)

    @staticmethod
    def _from_json_schema(data: dict, prefix=""):
        data_attributes = []
        for key, value in data.items():
            if isinstance(value, dict):
                if value["type"] == "object":
                    data_attributes.extend(
                        DataAttributesAdapter._from_json_schema(
                            value["properties"], f"{prefix}{key}."
                        )
                    )
                else:
                    attribute = DataAttribute(
                        name=f"{prefix}{key}", data_type=value["type"]
                    )
                    data_attributes.append(attribute)
            else:
                attribute = DataAttribute(name=f"{prefix}{key}", data_type=value)
                data_attributes.append(attribute)

        return data_attributes

    @staticmethod
    def _detect_json_schema_type(data: any) -> str:
        if isinstance(data, str):
            return "string"
        elif isinstance(data, dict):
            return "object"
        elif isinstance(data, int):
            return "number"
        elif isinstance(data, float):
            return "number"

    @staticmethod
    def _from_credential(data: dict, prefix=""):
        data_attributes = []
        for key, value in data.items():
            if isinstance(value, dict):
                data_attributes.extend(
                    DataAttributesAdapter._from_credential(value, f"{prefix}{key}.")
                )
            else:
                attribute = DataAttribute(
                    name=f"{prefix}{key}",
                    value=value,
                    data_type=DataAttributesAdapter._detect_json_schema_type(value),
                )
                data_attributes.append(attribute)
        return data_attributes
