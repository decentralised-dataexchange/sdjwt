from jsonschema import exceptions, validate, ValidationError
import json
import uuid
import base64
from typing import List, Dict, Union, Optional, Tuple, Any
from pydantic import BaseModel
from sdjwt.didkey import DIDKey
from sdjwt.sdjwt import get_all_disclosures_with_sd_from_token, decode_disclosure_base64
from jwcrypto import jwk, jwt
from jsonpath_ng import jsonpath, parse
from dataclasses import dataclass


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
    format: Optional[Dict[str, Union[Dict[str, List[str]], Dict[str, List[str]]]]] = (
        None
    )


class PresentationDefinition(BaseModel):
    id: str
    input_descriptors: List[InputDescriptor]
    format: Optional[Dict[str, Union[Dict[str, List[str]], Dict[str, List[str]]]]] = (
        None
    )


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
                        "path": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                        },
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
                        "path": {
                            "type": "array",
                            "items": {"type": "string"},
                            "minItems": 1,
                        },
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
                "format": {
                    "$schema": "http://json-schema.org/draft-07/schema#",
                    "title": "Presentation Definition Claim Format Designations",
                    "type": "object",
                    "additionalProperties": False,
                    "patternProperties": {
                        "mso_mdoc": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "alg": {
                                    "type": "array",
                                    "minItems": 1,
                                    "items": {"type": "string", "enum": ["ES256"]},
                                }
                            },
                        },
                        "^(jwt|jwt_vc|jwt_vc_json|jwt_vp|vp\+sd-jwt|vc\+sd-jwt|sd-jwt)$": {
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
                    },
                },
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
                            "minItems": 1,
                        },
                    },
                    "required": ["fields"],
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
                "^(jwt|jwt_vc|jwt_vc_json|jwt_vp|vp\+sd-jwt|vc\+sd-jwt|sd-jwt)$": {
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
                "mso_mdoc": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "alg": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string", "enum": ["ES256"]},
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
                        "mso_mdoc",
                        "jwt_vc_json",
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
        presentation_definition_dict = PresentationDefinition(**presentation_definition)
        if not presentation_definition_dict.format:
            for input_descriptor in presentation_definition_dict.input_descriptors:
                format = input_descriptor.format
                if not format:
                    raise PresentationDefinitionValidationError("Format is required")
        return PresentationDefinition(**presentation_definition)
    except exceptions.ValidationError as e:
        # FIXME: Temporary hack to validate presentation definition from itb
        if e.message == "Additional properties are not allowed ('name' was unexpected)":
            return PresentationDefinition(**presentation_definition)
        else:
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
    try:
        claims_decoded = base64.b64decode(
            claims_encoded + "=" * (-len(claims_encoded) % 4)
        )
        headers_decoded = base64.b64decode(
            headers_encoded + "=" * (-len(headers_encoded) % 4)
        )
        return (json.loads(headers_decoded), json.loads(claims_decoded))
    except Exception:
        claims_decoded = base64.urlsafe_b64decode(
            claims_encoded + "=" * (-len(claims_encoded) % 4)
        )
        headers_decoded = base64.urlsafe_b64decode(
            headers_encoded + "=" * (-len(headers_encoded) % 4)
        )
        return (json.loads(headers_decoded), json.loads(claims_decoded))


class VpTokenExpiredError(Exception):
    pass


class VpTokenValidationError(Exception):
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
        # FIXME: We only support signature verification using did:key
        #   This has to be extended for JWK by resolving JWKs URI
        if kid.startswith("did:key"):
            method_specific_identifier = kid.split("#")[1]
            key = DIDKey.method_specific_identifier_to_jwk(method_specific_identifier)
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
    is_vp_token_validated = validate_vp_token(
        vp_token=vp_token,
        presentation_submission=presentation_submission.get("presentation_submission"),
        presentation_definition=json.dumps(presentation_definition),
    )
    if not is_vp_token_validated:
        raise VpTokenValidationError("Failed to validate vp token")


@dataclass
class MatchedPath:
    path: str
    index: int
    value: Any


@dataclass
class MatchedField:
    index: int
    path: MatchedPath


@dataclass
class MatchedCredential:
    index: int
    fields: List[MatchedField]


def apply_json_path(input_json_string, path):
    try:
        # Parse input JSON string
        parsed_input = json.loads(input_json_string)
    except json.JSONDecodeError as e:
        return None, e

    try:
        # Parse JSON path string
        jsonpath_expr = parse(path)
    except Exception as e:
        return None, e

    # Apply JSON path on input and get the matches
    matches = [match.value for match in jsonpath_expr.find(parsed_input)]
    return matches, None


def validate_json_schema(input_json_string, schema_string):

    try:
        # Parse schema JSON string
        schema = json.loads(schema_string)
    except json.JSONDecodeError as e:
        return e

    try:
        # Validate JSON schema against the input JSON
        validate(instance=input_json_string, schema=schema)
    except ValidationError as e:
        return e

    return None


def match_credentials(
    input_descriptor_json, credentials
) -> Tuple[List[MatchedCredential], Optional[Exception]]:
    # Deserialise input descriptor json string
    try:
        descriptor = json.loads(input_descriptor_json)
    except json.JSONDecodeError as e:
        return [], e

    # To store the matched credentials
    matches = []

    # Iterate through each credential
    for credential_index, credential in enumerate(credentials):

        # Assume credential matches until proven otherwise
        credential_matched = True
        matched_fields = []

        # Iterate through fields specified in the constraints
        for field_index, field in enumerate(descriptor["constraints"]["fields"]):

            # Assume field matches until proven otherwise
            field_matched = False

            # Iterate through JSON paths for the current field
            for path_index, path in enumerate(field["path"]):

                # Apply JSON path on the credential
                path_matches, err = apply_json_path(credential, path)

                if len(path_matches) > 0 and err is None:
                    if "filter" in field:
                        try:
                            filter_bytes = json.dumps(field["filter"])
                        except (TypeError, ValueError) as e:
                            # Continue to next path, since filter has failed to serialise
                            continue

                        # Validate the matched JSON against the field's filter
                        if (
                            validate_json_schema(path_matches[0], filter_bytes)
                            is not None
                        ):
                            # Field doesn't match since validation failed
                            field_matched = False
                            break

                    # Add the matched field to the list
                    field_matched = True
                    matched_fields.append(
                        MatchedField(
                            index=field_index,
                            path=MatchedPath(
                                path=path, index=path_index, value=path_matches[0]
                            ),
                        )
                    )

            if not field_matched:
                # If any one field didn't match then move to next credential
                credential_matched = False
                break

        if credential_matched:
            # All fields matched, then credential is matched
            matches.append(
                MatchedCredential(index=credential_index, fields=matched_fields)
            )

    return matches, None


def decode_base64(encoded_str):
    decoded_bytes = base64.urlsafe_b64decode(encoded_str + "==")
    return json.loads(decoded_bytes.decode("utf-8"))


def find_all_sd_values(data):
    sd_values = []
    if isinstance(data, dict):
        for key, value in data.items():
            if key == "_sd" and isinstance(value, list):
                sd_values.extend(value)
            else:
                sd_values.extend(find_all_sd_values(value))
    elif isinstance(data, list):
        for item in data:
            sd_values.extend(find_all_sd_values(item))
    return sd_values


# Function to extract relevant disclosure values
def extract_disclosure_values(input_descriptor, credential, disclosure):
    fields = input_descriptor["constraints"]["fields"]
    sd_values = find_all_sd_values(credential)

    matching_disclosures = []
    for field in fields:
        path = field["path"][0]
        key_to_match = path.split(".")[-1]

        for sd in sd_values:
            if sd in disclosure:
                decoded_value = decode_base64(disclosure[sd])
                if key_to_match == decoded_value[1]:
                    matching_disclosures.append(disclosure[sd])
                    break

    return matching_disclosures


def update_disclosures_in_token(token: str, disclosures: list) -> str:
    token_with_disclosures = token.split("~")
    jwt_token = token_with_disclosures[:1][0]
    sd_string = "~" + "~".join(disclosures)

    sd_jwt = jwt_token + sd_string
    return sd_jwt


def decode_credential_sd_to_credential_subject_with_key_mapping(
    disclosure_mapping: dict, credential_subject: dict
) -> dict:
    credential_subject = {"credentialSubject": credential_subject}
    _credentialSubject = {**credential_subject}
    key_mapping = {}

    def replace_sd_with_credential_subject_attributes(sds: list, disclosure: dict):
        credential_attribute = {}
        for sd in sds:
            disclosure_base64 = disclosure.get(sd)
            key, value = decode_disclosure_base64(disclosure_base64=disclosure_base64)
            id = str(uuid.uuid4())
            key_mapping[id] = value
            credential_attribute[key] = id
        return credential_attribute, key_mapping

    def update_value(obj, path, credential_attribute):
        # Construct json path dot notation
        dot_notation_path = ".".join(path)

        # Find matches for the json path
        jp = parse(dot_notation_path)
        matches = jp.find(obj)

        # Iterate through the matches
        for match in matches:
            if isinstance(match.context.value, dict):
                match.context.value[str(match.path)].pop("_sd")
                for key, value in credential_attribute.items():
                    match.context.value[str(match.path)][key] = value

    def iterate_mapping(obj, path):
        for key, value in obj.items():

            if isinstance(value, dict):
                new_path = path + [f"'{key}'"]
                # Check if sd is present or not
                if "_sd" in value and value["_sd"]:
                    credential_attribute, key_mapping = (
                        replace_sd_with_credential_subject_attributes(
                            value["_sd"], disclosure=disclosure_mapping
                        )
                    )
                    update_value(_credentialSubject, new_path, credential_attribute)
                iterate_mapping(value, new_path)

    iterate_mapping(credential_subject, [])
    return credential_subject["credentialSubject"], key_mapping


def match_credentials_for_sd_jwt(
    input_descriptor_json,
    credentials,
) -> Tuple[List[MatchedCredential], Optional[Exception]]:
    # Deserialise input descriptor json string
    try:
        descriptor = json.loads(input_descriptor_json)
    except json.JSONDecodeError as e:
        return [], e

    # To store the matched credentials
    matches = []

    # Iterate through each credential
    for item in credentials:
        for credential_id, credential_token in item.items():

            # Assume credential matches until proven otherwise
            credential_matched = True
            matched_fields = []
            disclosure_mapping = get_all_disclosures_with_sd_from_token(
                token=credential_token
            )
            _, credential_decoded = decode_header_and_claims_in_jwt(credential_token)
            credential_subject, key_mapping = (
                decode_credential_sd_to_credential_subject_with_key_mapping(
                    disclosure_mapping=disclosure_mapping,
                    credential_subject=credential_decoded
                )
            )
            credential = credential_decoded
            credential = credential_subject
            credential = json.dumps(credential)

            # Iterate through fields specified in the constraints
            for field_index, field in enumerate(descriptor["constraints"]["fields"]):

                # Assume field matches until proven otherwise
                field_matched = False

                # Iterate through JSON paths for the current field
                for path_index, path in enumerate(field["path"]):

                    # Apply JSON path on the credential
                    path_matches, err = apply_json_path(credential, path)

                    if len(path_matches) > 0 and err is None:
                        if "filter" in field:
                            try:
                                filter_bytes = json.dumps(field["filter"])
                            except (TypeError, ValueError) as e:
                                # Continue to next path, since filter has failed to serialise
                                continue

                            # Validate the matched JSON against the field's filter
                            if (
                                validate_json_schema(path_matches[0], filter_bytes)
                                is not None
                            ):
                                # Field doesn't match since validation failed
                                field_matched = False
                                break

                        # Add the matched field to the list
                        field_matched = True
                        value = key_mapping.get(str(path_matches[0]))
                        if value:

                            matched_fields.append(
                                MatchedField(
                                    index=field_index,
                                    path=MatchedPath(
                                        path=path, index=path_index, value=value
                                    ),
                                )
                            )
                        else:
                            matched_fields.append(
                                MatchedField(
                                    index=field_index,
                                    path=MatchedPath(
                                        path=path,
                                        index=path_index,
                                        value=path_matches[0],
                                    ),
                                )
                            )

                if not field_matched:
                    # If any one field didn't match then move to next credential
                    credential_matched = False
                    break

            if credential_matched:
                # All fields matched, then credential is matched
                matches.append(
                    MatchedCredential(index=credential_id, fields=matched_fields)
                )

    return matches, None


def remove_sd_and_add_disclosure_value(
    credential_subject, disclosure_key, disclosure_value
):

    if isinstance(credential_subject, dict):
        keys_to_modify = list(
            credential_subject.keys()
        )  # Create a list of keys to avoid changing the dict during iteration
        for key in keys_to_modify:
            value = credential_subject[key]
            credential_subject[key] = remove_sd_and_add_disclosure_value(
                value, disclosure_key, disclosure_value
            )
            if key == "_sd":
                if disclosure_key in value:
                    value.remove(disclosure_key)
                    attribute_key, attribute_value = decode_disclosure_base64(
                        disclosure_base64=disclosure_value
                    )
                    credential_subject[attribute_key] = attribute_value
    elif isinstance(credential_subject, list):
        for i in range(len(credential_subject)):
            credential_subject[i] = remove_sd_and_add_disclosure_value(
                credential_subject[i], disclosure_key, disclosure_value
            )
    return credential_subject


def create_credential_subject_for_sdjwt(credential_subject, disclosure_mapping):
    for disclosure_key, disclosure_value in disclosure_mapping.items():
        credential_subject = remove_sd_and_add_disclosure_value(
            credential_subject=credential_subject,
            disclosure_key=disclosure_key,
            disclosure_value=disclosure_value,
        )
    return credential_subject


def validate_vp_token(
    vp_token: str,
    presentation_submission: dict,
    presentation_definition: dict,
) -> bool:
    headers, claims = decode_header_and_claims_in_jwt(vp_token)
    for descriptor in presentation_submission.get("descriptor_map"):
        is_verified = False
        if "path_nested" in descriptor:
            format = descriptor["format"]
            path = descriptor["path_nested"]["path"]
            id = descriptor["id"]
            # Parse the JSON data
            jsonpath_expr = parse(path)
            matches = jsonpath_expr.find(claims)

            # Extract the value
            vc_token = matches[0].value if matches else None

            vc_headers, vc_claims = decode_header_and_claims_in_jwt(vc_token)

            if vc_claims and format == "vc+sd-jwt":
                disclosure_mapping = get_all_disclosures_with_sd_from_token(vc_token)

                credential_subject = create_credential_subject_for_sdjwt(
                    credential_subject=vc_claims,
                    disclosure_mapping=disclosure_mapping,
                )
                vc_claims = credential_subject
            elif vc_claims and format == "jwt_vc":
                pass

            input_descriptors = json.loads(presentation_definition).get(
                "input_descriptors"
            )
            format_info = json.loads(presentation_definition).get("format")
            for input_descriptor in input_descriptors:
                credential_format = input_descriptor.get("format")
                if not credential_format:
                    credential_format = format_info
                if input_descriptor.get("id") == id:
                    limit_disclosure = input_descriptor.get("constraints").get(
                        "limit_disclosure", None
                    )
                    if "vc+sd-jwt" in credential_format:
                        matches = match_credentials(
                            json.dumps(input_descriptor),
                            credentials=[json.dumps(vc_claims)],
                        )
                    else:
                        matches = match_credentials(
                            json.dumps(input_descriptor),
                            credentials=[json.dumps(vc_claims["vc"])],
                        )
                    if not matches or not matches[0]:
                        return False
                    else:
                        is_verified = True
        if not is_verified:
            return False
    return True

def decode_credential_sd_to_credential_claims(
    disclosure_mapping: dict, credential_subject: dict
) -> dict:
    credential_subject = {"credentialSubject": credential_subject}
    _credentialSubject = {**credential_subject}

    def replace_sd_with_credential_subject_attributes(sds: list, disclosure: dict):
        credential_attribute = {}
        for sd in sds:
            disclosure_base64 = disclosure.get(sd)
            if disclosure_base64:
                key, value = decode_disclosure_base64(disclosure_base64=disclosure_base64)
                credential_attribute[key] = value
        return credential_attribute

    def update_value(obj, path, credential_attribute):
        # Construct json path dot notation
        dot_notation_path = ".".join(path)

        # Find matches for the json path
        jp = parse(dot_notation_path)
        matches = jp.find(obj)

        # Iterate through the matches
        for match in matches:
            if isinstance(match.context.value, dict):
                match.context.value[str(match.path)].pop("_sd")
                for key, value in credential_attribute.items():
                    match.context.value[str(match.path)][key] = value

    def iterate_mapping(obj, path):
        for key, value in obj.items():

            if isinstance(value, dict):
                new_path = path + [f"'{key}'"]
                # Check if sd is present or not
                if "_sd" in value and value["_sd"]:
                    credential_attribute = (
                        replace_sd_with_credential_subject_attributes(
                            value["_sd"], disclosure=disclosure_mapping
                        )
                    )
                    update_value(_credentialSubject, new_path, credential_attribute)
                iterate_mapping(value, new_path)

    iterate_mapping(credential_subject, [])
    return credential_subject["credentialSubject"]
