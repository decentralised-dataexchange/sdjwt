from jsonschema import exceptions, validate


from typing import List, Any, Optional
from pydantic import BaseModel, ValidationError


class Field(BaseModel):
    path: List[str]
    filter: Optional[Any] = None
    optional: Optional[bool] = None


class Constraints(BaseModel):
    fields: List[Field]
    limited_disclosure: Optional[str] = None


class InputDescriptor(BaseModel):
    id: str
    name: Optional[str] = None
    purpose: Optional[str] = None
    constraints: Constraints


class PresentationDefinition(BaseModel):
    id: str
    input_descriptors: List[InputDescriptor]


external_data = {
    "id": "first simple example",
    "input_descriptors": [
        {
            "id": "A specific type of VC",
            "name": "A specific type of VC",
            "purpose": "We want a VC of this type",
            "constraints": {
                "fields": [
                    {
                        "path": ["$.type"],
                        "filter": {
                            "type": "array",
                            "contains": {
                                "type": "string",
                                "pattern": "^<the type of VC e.g. degree certificate>$",
                            },
                        },
                    }
                ]
            },
        }
    ],
}

try:
    pex = PresentationDefinition(**external_data)
    print(pex.model_dump_json(exclude_unset=True))
except ValidationError as e:
    print(e.errors())
