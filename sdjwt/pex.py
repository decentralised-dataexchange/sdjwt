from jsonschema import exceptions, validate
import json
import base64
from typing import List, Dict, Union, Optional, Tuple
from pydantic import BaseModel
from sdjwt.didkey import DIDKey
from jwcrypto import jwk, jwt


class Field(BaseModel):
    id: Optional[str] = None
    optional: Optional[bool] = None
    path: List[str]
    purpose: Optional[str] = None
    name: Optional[str] = None
    intent_to_retain: Optional[bool] = None
    filter: Optional[Union[str, Dict]] = None


class InputDescriptor(BaseModel):
    id: str
    name: Optional[str] = None
    purpose: Optional[str] = None
    constraints: Dict[str, Union[str, List[Field]]]


class PresentationDefinition(BaseModel):
    id: str
    input_descriptors: List[InputDescriptor]
    format: Dict[str, Union[Dict[str, List[str]], Dict[str, List[str]]]]


PresentationDefinitionJsonSchema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Presentation Definition",
    "definitions": {
        "field": {
            "type": "object",
            "oneOf": [
                {
                    "properties": {
                        "id": {"type": "string"},
                        "optional": {"type": "boolean"},
                        "path": {"type": "array", "items": {"type": "string"}},
                        "purpose": {"type": "string"},
                        "name": {"type": "string"},
                        "intent_to_retain": {"type": "boolean"},
                        "filter": {"$ref": "http://json-schema.org/draft-07/schema#"},
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
                {
                    "properties": {
                        "id": {"type": "string"},
                        "optional": {"type": "boolean"},
                        "path": {"type": "array", "items": {"type": "string"}},
                        "purpose": {"type": "string"},
                        "intent_to_retain": {"type": "boolean"},
                        "filter": {"$ref": "http://json-schema.org/draft-07/schema#"},
                        "name": {"type": "string"},
                        "predicate": {
                            "type": "string",
                            "enum": ["required", "preferred"],
                        },
                    },
                    "required": ["path", "filter", "predicate"],
                    "additionalProperties": False,
                },
            ],
        },
        "input_descriptor": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "purpose": {"type": "string"},
                "constraints": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "limit_disclosure": {
                            "type": "string",
                            "enum": ["required", "preferred"],
                        },
                        "fields": {
                            "type": "array",
                            "items": {"$ref": "#/definitions/field"},
                        },
                    },
                },
            },
            "required": ["id", "constraints"],
        },
    },
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "input_descriptors": {
            "type": "array",
            "items": {"$ref": "#/definitions/input_descriptor"},
        },
        "format": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Presentation Definition Claim Format Designations",
            "type": "object",
            "additionalProperties": False,
            "patternProperties": {
                "^(jwt|jwt_vc|jwt_vp|vp\+sd-jwt|vc\+sd-jwt|sd-jwt)$": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "alg": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                        }
                    },
                },
                "^ldp_vc$|^ldp_vp$|^ldp$": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "proof_type": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string"},
                        }
                    },
                },
            },
        },
    },
    "required": ["id", "input_descriptors"],
    "additionalProperties": False,
}


class PresentationSubmissionValidationError(Exception):
    pass


class PresentationDefinitionValidationError(Exception):
    pass


PresentationSubmissionJsonSchema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Presentation Submission",
    "type": "object",
    "properties": {
        "presentation_submission": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "definition_id": {"type": "string"},
                "descriptor_map": {
                    "type": "array",
                    "items": {"$ref": "#/definitions/descriptor"},
                },
            },
            "required": ["id", "definition_id", "descriptor_map"],
            "additionalProperties": False,
        }
    },
    "definitions": {
        "descriptor": {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "path": {"type": "string"},
                "path_nested": {"type": "object", "$ref": "#/definitions/descriptor"},
                "format": {
                    "type": "string",
                    "enum": [
                        "jwt",
                        "jwt_vc",
                        "jwt_vp",
                        "ldp",
                        "ldp_vc",
                        "ldp_vp",
                        "vc+sd-jwt",
                        "vp+sd-jwt",
                        "sd-jwt",
                    ],
                },
            },
            "required": ["id", "path", "format"],
            "additionalProperties": False,
        }
    },
    "required": ["presentation_submission"],
    "additionalProperties": False,
}


class Descriptor(BaseModel):
    id: str
    path: str
    path_nested: Optional[Dict] = None
    format: str


class PresentationSubmission(BaseModel):
    id: str
    definition_id: str
    descriptor_map: Optional[List[Descriptor]] = None


class PresentationSubmissionRequest(BaseModel):
    presentation_submission: Optional[PresentationSubmission] = None


def validate_and_deserialise_presentation_definition(
    presentation_definition: dict,
) -> PresentationDefinition:
    try:
        validate(
            instance=presentation_definition, schema=PresentationDefinitionJsonSchema
        )
        return PresentationDefinition(**presentation_definition)
    except exceptions.ValidationError as e:
        raise PresentationDefinitionValidationError(e.message)


def validate_and_deserialise_presentation_submission(
    presentation_submission: dict,
) -> PresentationSubmissionRequest:
    try:
        validate(
            instance=presentation_submission, schema=PresentationSubmissionJsonSchema
        )
        return PresentationSubmissionRequest(**presentation_submission)
    except exceptions.ValidationError as e:
        raise PresentationSubmissionValidationError(e.message)


def decode_header_and_claims_in_jwt(token: str) -> Tuple[dict, dict]:
    headers_encoded, claims_encoded, _ = token.split(".")
    claims_decoded = base64.b64decode(claims_encoded + "=" * (-len(claims_encoded) % 4))
    headers_decoded = base64.b64decode(
        headers_encoded + "=" * (-len(headers_encoded) % 4)
    )
    return (json.loads(headers_decoded), json.loads(claims_decoded))


class VpTokenExpiredError(Exception):
    pass


class UnSupportedSignatureAlgorithmError(Exception):
    pass


def verify_vp_token(vp_token: str):
    headers, _ = decode_header_and_claims_in_jwt(vp_token)
    kid = headers.get("kid")
    alg = headers.get("alg")
    jwk_dict = headers.get("jwk")

    if alg != "ES256":
        raise UnSupportedSignatureAlgorithmError("Signature algorithm not supported")

    key = None
    if kid:
        if kid.startswith("did:key"):
            method_specific_identifier = kid.split("#")[1]
            key = DIDKey.method_specific_identifier_to_jwk(method_specific_identifier)
        else:
            raise UnSupportedSignatureAlgorithmError("Failed to parse the key ID")
    elif jwk:
        key = jwk.JWK(**jwk_dict)
    else:
        raise UnSupportedSignatureAlgorithmError(
            "Failed to obtain the public key to verify the VP token"
        )
    try:
        _ = jwt.JWT(key=key, jwt=vp_token)
    except jwt.JWTExpired:
        raise VpTokenExpiredError("VP token expired")


def validate_vp_token_against_presentation_submission_and_presentation_definition(
    vp_token: str,
    presentation_definition: Optional[dict] = None,
    presentation_submission: Optional[dict] = None,
):
    if presentation_definition:
        pd = validate_and_deserialise_presentation_definition(
            presentation_definition=presentation_definition
        )
    if presentation_submission:
        ps = validate_and_deserialise_presentation_submission(
            presentation_submission=presentation_submission
        )
    verify_vp_token(vp_token=vp_token)
