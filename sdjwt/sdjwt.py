from jwcrypto import jwk, jwt
import typing
import time
import json
from datetime import datetime, timedelta
from sdjwt.didkey import DIDKey
from sdjwt.adapter import DataAttribute, DataAttributesAdapter
from secrets import token_hex
import pytz
import hashlib
import base64
from jsonpath_ng import jsonpath, parse


def get_current_datetime_in_epoch_seconds_and_iso8601_format(
    delta_in_seconds=0,
) -> typing.Tuple[int, str]:
    # Get the current date and time in UTC
    now = datetime.now(pytz.UTC)
    # Increment the current date by the specified number of seconds
    incremented_datetime = now + timedelta(seconds=delta_in_seconds)
    # Format the datetime object in ISO 8601 format
    iso_8601_datetime = incremented_datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Calculate the UTC epoch seconds
    epoch_seconds = int(
        (incremented_datetime - datetime(1970, 1, 1, tzinfo=pytz.UTC)).total_seconds()
    )
    return epoch_seconds, iso_8601_datetime


def get_alg_for_key(key: jwk.JWK) -> typing.Union[str, None]:
    alg = None
    if key.key_curve == "P-256":
        alg = "ES256"
    return alg


def create_jwt(
    jti: str,
    sub: str,
    iss: str,
    kid: str,
    key: typing.Union[jwk.JWK, None],
    vc: typing.Union[dict, None] = None,
    iat: typing.Union[int, None] = None,
    exp: typing.Union[int, None] = None,
    **kwargs,
) -> str:
    header = {"typ": "JWT", "alg": get_alg_for_key(key), "kid": kid}

    iat = iat or int(time.time())
    nbf = iat
    exp = exp or iat + 86400
    claims = {
        "iat": iat,
        "jti": jti,
        "nbf": nbf,
        "exp": exp,
        "sub": sub,
        "iss": iss,
        **kwargs,
    }
    if vc:
        claims["vc"] = vc
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)

    return token.serialize()


def create_w3c_vc_jwt(
    jti: str,
    iss: str,
    sub: str,
    kid: str,
    key: jwk.JWK,
    credential_issuer: str,
    credential_id: str,
    credential_type: typing.List[str],
    credential_context: typing.List[str],
    credential_subject: dict,
    credential_schema: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
    credential_status: typing.Optional[dict] = None,
    terms_of_use: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
) -> str:
    expiry_in_seconds = 2592000
    issuance_epoch, issuance_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format()
    )
    expiration_epoch, expiration_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format(expiry_in_seconds)
    )
    vc = {
        "@context": credential_context,
        "id": credential_id,
        "type": credential_type,
        "issuer": credential_issuer,
        "issuanceDate": issuance_8601,
        "validFrom": issuance_8601,
        "expirationDate": expiration_8601,
        "issued": issuance_8601,
        "credentialSubject": credential_subject,
    }
    if credential_schema:
        vc["credentialSchema"] = credential_schema
    if credential_status:
        vc["credentialStatus"] = credential_status
    if terms_of_use:
        vc["termsOfUse"] = terms_of_use
    return create_jwt(
        vc=vc,
        jti=jti,
        sub=sub,
        iss=iss,
        kid=kid,
        key=key,
        iat=issuance_epoch,
        exp=expiration_epoch,
    )


async def generate_did_key_from_seed(
    crypto_seed: str,
) -> DIDKey:
    crypto_seed_bytes = crypto_seed.encode("utf-8")
    key_did = DIDKey(seed=crypto_seed_bytes)
    return key_did


def create_sd_from_disclosure_base64(disclosure_base64: str) -> str:
    hash_digest = hashlib.sha256(disclosure_base64.encode("utf-8")).digest()
    hash_base64 = base64.urlsafe_b64encode(hash_digest).rstrip(b"=").decode("utf-8")
    return hash_base64


def create_random_salt(length: int) -> str:
    return token_hex(length)


def create_disclosure_base64(random_salt: str, key: str, value: str) -> str:
    disclosure = [random_salt, key, value]
    disclosure_json = json.dumps(disclosure, separators=(",", ":"))
    disclosure_base64 = (
        base64.urlsafe_b64encode(disclosure_json.encode("utf-8"))
        .rstrip(b"=")
        .decode("utf-8")
    )
    return disclosure_base64


def create_flat_sd_jwt(
    jti: str,
    iss: str,
    sub: str,
    kid: str,
    key: jwk.JWK,
    credential_subject: dict,
    iat: typing.Union[int, None] = None,
    exp: typing.Union[int, None] = None,
) -> str:
    _sd = []
    disclosures = []
    for name, value in credential_subject.items():
        disclosure_base64 = None
        disclosure_base64 = create_disclosure_base64(
            create_random_salt(32), key=name, value=value
        )
        sd = create_sd_from_disclosure_base64(disclosure_base64)
        disclosures.append(disclosure_base64)
        _sd.append(sd)

    sd_payload = {"_sd": _sd}

    vc_jwt = create_jwt(
        jti=jti,
        sub=sub,
        iss=iss,
        kid=kid,
        key=key,
        iat=iat,
        exp=exp,
        **sd_payload,
    )

    _sd_string = "~" + "~".join(disclosures)

    sd_jwt = vc_jwt + _sd_string
    return sd_jwt


def create_w3c_vc_sd_jwt(
    jti: str,
    iss: str,
    sub: str,
    kid: str,
    key: jwk.JWK,
    credential_issuer: str,
    credential_id: str,
    credential_type: typing.List[str],
    credential_context: typing.List[str],
    credential_subject: dict,
    credential_schema: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
    credential_status: typing.Optional[dict] = None,
    terms_of_use: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
) -> str:
    expiry_in_seconds = 2592000
    issuance_epoch, issuance_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format()
    )
    expiration_epoch, expiration_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format(expiry_in_seconds)
    )
    _sd = []
    disclosures = []
    for name, value in credential_subject.items():
        disclosure_base64 = None
        disclosure_base64 = create_disclosure_base64(
            create_random_salt(32), key=name, value=value
        )
        sd = create_sd_from_disclosure_base64(disclosure_base64)
        disclosures.append(disclosure_base64)
        _sd.append(sd)

    sd_payload = {"_sd": _sd}

    vc = {
        "@context": credential_context,
        "id": credential_id,
        "type": credential_type,
        "issuer": credential_issuer,
        "issuanceDate": issuance_8601,
        "validFrom": issuance_8601,
        "expirationDate": expiration_8601,
        "issued": issuance_8601,
        "credentialSubject": sd_payload,
    }
    if credential_schema:
        vc["credentialSchema"] = credential_schema
    if credential_status:
        vc["credentialStatus"] = credential_status
    if terms_of_use:
        vc["termsOfUse"] = terms_of_use

    jwt_credential = create_jwt(
        vc=vc,
        jti=jti,
        sub=sub,
        iss=iss,
        kid=kid,
        key=key,
        iat=issuance_epoch,
        exp=expiration_epoch,
    )
    sd_disclosures = "~" + "~".join(disclosures)

    return jwt_credential + sd_disclosures


def create_w3c_vc_sd_jwt_for_data_attributes(
    jti: str,
    iss: str,
    sub: str,
    kid: str,
    key: jwk.JWK,
    credential_issuer: str,
    credential_id: str,
    credential_type: typing.List[str],
    credential_context: typing.List[str],
    data_attributes: typing.List[DataAttribute],
    credential_schema: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
    credential_status: typing.Optional[dict] = None,
    terms_of_use: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
    limited_disclosure: typing.Optional[bool] = None,
):
    expiry_in_seconds = 2592000
    issuance_epoch, issuance_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format()
    )
    expiration_epoch, expiration_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format(expiry_in_seconds)
    )

    vc = {
        "@context": credential_context,
        "id": credential_id,
        "type": credential_type,
        "issuer": credential_issuer,
        "issuanceDate": issuance_8601,
        "validFrom": issuance_8601,
        "expirationDate": expiration_8601,
        "issued": issuance_8601,
    }

    sd_disclosures = ""
    if limited_disclosure is None:
        disclosures = []
        adapter = DataAttributesAdapter(data_attributes=data_attributes)

        # Create a copy and modifications are done to it.
        credentialSubject = adapter.to_credential()
        tempCredentialSubject = adapter.to_credential()
        for data_attribute in data_attributes:
            _sd = []
            if data_attribute.limited_disclosure:
                child_jp = parse(data_attribute.name)

                # Create disclosure from jsonpath matches
                for match in child_jp.find(credentialSubject):
                    name = str(match.path)
                    value = match.value
                    disclosure_base64 = None
                    disclosure_base64 = create_disclosure_base64(
                        create_random_salt(32),
                        key=name,
                        value=value,
                    )
                    sd = create_sd_from_disclosure_base64(disclosure_base64)
                    disclosures.append(disclosure_base64)
                    _sd.append(sd)

                    # To add _sd array in to previous node.
                    parent_paths = data_attribute.name.split(".")
                    if len(parent_paths) > 1:
                        parent_path = (
                            ".".join(parent_paths[:-1])
                            if len(parent_paths) > 1
                            else data_attribute.name
                        )
                        parent_jp = parse(parent_path)
                        for parent_match in parent_jp.find(tempCredentialSubject):
                            # if _sd array is present, then extend it
                            if parent_match.value.get("_sd"):
                                # Kick out the field marked as limited disclosure
                                del parent_match.value[str(match.path)]
                                parent_match.value["_sd"].extend(_sd)
                                parent_jp.update(
                                    tempCredentialSubject,
                                    parent_match.value,
                                )
                            else:
                                parent_match.value["_sd"] = _sd
                                # Kick out the field marked as limited disclosure
                                del parent_match.value[str(match.path)]
                                parent_jp.update(
                                    tempCredentialSubject, parent_match.value
                                )
                    else:
                        # Kick out the field marked as limited disclosure
                        del tempCredentialSubject[str(match.path)]
                        if tempCredentialSubject.get("_sd"):
                            tempCredentialSubject["_sd"].extend(_sd)
                        else:
                            tempCredentialSubject["_sd"] = _sd
            else:
                child_jp = parse(data_attribute.name)
                for match in child_jp.find(credentialSubject):
                    # To add in to previous node.
                    parent_paths = data_attribute.name.split(".")
                    if len(parent_paths) > 1:
                        parent_path = (
                            ".".join(parent_paths[:-1])
                            if len(parent_paths) > 1
                            else data_attribute.name
                        )
                        parent_jp = parse(parent_path)
                        for parent_match in parent_jp.find(tempCredentialSubject):
                            # if _sd array is present, the add
                            # data attribute as a separate key in the dict
                            if parent_match.value.get("_sd"):
                                parent_match.value[str(match.path)] = match.value
                                parent_jp.update(
                                    tempCredentialSubject,
                                    parent_match.value,
                                )

        vc["credentialSubject"] = tempCredentialSubject
        if len(disclosures) > 0:
            sd_disclosures = "~" + "~".join(disclosures)
    else:
        if limited_disclosure:
            disclosures = []
            _sd = []
            adapter = DataAttributesAdapter(data_attributes=data_attributes)
            credentialSubject = adapter.to_credential()
            for name, value in credentialSubject.items():
                disclosure_base64 = None
                disclosure_base64 = create_disclosure_base64(
                    create_random_salt(32), key=name, value=value
                )
                sd = create_sd_from_disclosure_base64(disclosure_base64)
                disclosures.append(disclosure_base64)
                _sd.append(sd)
            if len(disclosures) > 0:
                sd_disclosures = "~" + "~".join(disclosures)
            vc["credentialSubject"] = {"_sd": _sd}
        else:
            t = DataAttributesAdapter(data_attributes=data_attributes)
            vc["credentialSubject"] = t.to_credential()

    if credential_schema:
        vc["credentialSchema"] = credential_schema
    if credential_status:
        vc["credentialStatus"] = credential_status
    if terms_of_use:
        vc["termsOfUse"] = terms_of_use

    jwt_credential = create_jwt(
        vc=vc,
        jti=jti,
        sub=sub,
        iss=iss,
        kid=kid,
        key=key,
        iat=issuance_epoch,
        exp=expiration_epoch,
    )

    return jwt_credential + sd_disclosures


def create_w3c_vc_jwt_with_disclosure_mapping(
    jti: str,
    iss: str,
    sub: str,
    kid: str,
    key: jwk.JWK,
    credential_issuer: str,
    credential_id: str,
    credential_type: typing.List[str],
    credential_context: typing.List[str],
    credential_subject: dict,
    credential_schema: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
    credential_status: typing.Optional[dict] = None,
    terms_of_use: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
    disclosure_mapping: typing.Optional[dict] = None,
) -> str:
    expiry_in_seconds = 2592000
    issuance_epoch, issuance_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format()
    )
    expiration_epoch, expiration_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format(expiry_in_seconds)
    )
    _credentialSubject = {**credential_subject}
    if disclosure_mapping:
        disclosures = []

        def calculate_sd(name, value):
            _sd = []
            disclosure_base64 = create_disclosure_base64(
                create_random_salt(32), key=name, value=value
            )
            sd = create_sd_from_disclosure_base64(disclosure_base64)
            disclosures.append(disclosure_base64)
            _sd.append(sd)
            return _sd

        def update_value(obj, path):
            # Construct json path dot notation
            dot_notation_path = ".".join(path)

            # Find matches for the json path
            jp = parse(dot_notation_path)
            matches = jp.find(obj)

            # Iterate through the matches and calculated sd
            for match in matches:
                sd = calculate_sd(str(match.path), match.value)
                if isinstance(match.context.value, dict):
                    if not match.context.value.get("_sd"):
                        match.context.value.setdefault("_sd", sd)
                        del match.context.value[str(match.path)]
                    else:
                        match.context.value["_sd"].extend(sd)
                        del match.context.value[str(match.path)]

        def iterate_mapping(obj, path):
            for key, value in obj.items():
                if isinstance(value, dict):
                    new_path = path + [f"'{key}'"]
                    # Check if limitedDisclosure is present or not
                    if "limitedDisclosure" in value and value["limitedDisclosure"]:
                        update_value(_credentialSubject, new_path)
                    iterate_mapping(value, new_path)

        # Iterate through disclosure mapping
        # and add sd to the corresponding field in the
        # credential subject
        iterate_mapping(disclosure_mapping, [])

    vc = {
        "@context": credential_context,
        "id": credential_id,
        "type": credential_type,
        "issuer": credential_issuer,
        "issuanceDate": issuance_8601,
        "validFrom": issuance_8601,
        "expirationDate": expiration_8601,
        "issued": issuance_8601,
        **_credentialSubject,
    }
    if credential_schema:
        vc["credentialSchema"] = credential_schema
    if credential_status:
        vc["credentialStatus"] = credential_status
    if terms_of_use:
        vc["termsOfUse"] = terms_of_use

    jwt_credential = create_jwt(
        vc=vc,
        jti=jti,
        sub=sub,
        iss=iss,
        kid=kid,
        key=key,
        iat=issuance_epoch,
        exp=expiration_epoch,
    )
    sd_disclosures = ""
    if disclosure_mapping:
        sd_disclosures = "~" + "~".join(disclosures)

    return jwt_credential + sd_disclosures


def create_w3c_vc_jwt_with_disclosure_mapping_v2(
    jti: str,
    iss: str,
    sub: str,
    kid: str,
    key: jwk.JWK,
    credential_issuer: str,
    credential_id: str,
    credential_type: typing.List[str],
    credential_context: typing.List[str],
    credential_subject: dict,
    credential_schema: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
    credential_status: typing.Optional[dict] = None,
    terms_of_use: typing.Optional[typing.Union[dict, typing.List[dict]]] = None,
    disclosure_mapping: typing.Optional[dict] = None,
    expiry_in_seconds: typing.Optional[int] = None,
) -> str:
    if not expiry_in_seconds:
        expiry_in_seconds = 2592000
    issuance_epoch, issuance_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format()
    )
    expiration_epoch, expiration_8601 = (
        get_current_datetime_in_epoch_seconds_and_iso8601_format(expiry_in_seconds)
    )
    _credentialSubject = {**credential_subject}
    if disclosure_mapping:
        disclosures = []

        def calculate_sd(name, value):
            _sd = []
            disclosure_base64 = create_disclosure_base64(
                create_random_salt(32), key=name, value=value
            )
            sd = create_sd_from_disclosure_base64(disclosure_base64)
            disclosures.append(disclosure_base64)
            _sd.append(sd)
            return _sd

        def update_value(obj, path):
            # Construct json path dot notation
            dot_notation_path = ".".join(path)

            # Find matches for the json path
            jp = parse(dot_notation_path)
            matches = jp.find(obj)

            # Iterate through the matches and calculated sd
            for match in matches:
                sd = calculate_sd(str(match.path), match.value)
                if isinstance(match.context.value, dict):
                    if not match.context.value.get("_sd"):
                        match.context.value.setdefault("_sd", sd)
                        del match.context.value[str(match.path)]
                    else:
                        match.context.value["_sd"].extend(sd)
                        del match.context.value[str(match.path)]

        def iterate_mapping(obj, path):
            for key, value in obj.items():
                if isinstance(value, dict):
                    new_path = path + [f"'{key}'"]
                    # Check if limitDisclosure is present or not
                    if "limitDisclosure" in value and value["limitDisclosure"]:
                        update_value(_credentialSubject, new_path)
                    iterate_mapping(value, new_path)

        # Iterate through disclosure mapping
        # and add sd to the corresponding field in the
        # credential subject
        iterate_mapping(disclosure_mapping, [])

    vc = {
        "@context": credential_context,
        "id": credential_id,
        "type": credential_type,
        "issuer": credential_issuer,
        "issuanceDate": issuance_8601,
        "validFrom": issuance_8601,
        "expirationDate": expiration_8601,
        "issued": issuance_8601,
        **_credentialSubject,
    }
    if credential_schema:
        vc["credentialSchema"] = credential_schema
    if credential_status:
        vc["credentialStatus"] = credential_status
    if terms_of_use:
        vc["termsOfUse"] = terms_of_use

    jwt_credential = create_jwt(
        vc=vc,
        jti=jti,
        sub=sub,
        iss=iss,
        kid=kid,
        key=key,
        iat=issuance_epoch,
        exp=expiration_epoch,
    )
    sd_disclosures = ""
    if disclosure_mapping:
        sd_disclosures = "~" + "~".join(disclosures)

    return jwt_credential + sd_disclosures


def decode_disclosure_base64(disclosure_base64: str):
    # Add padding back to the base64 string if needed
    while len(disclosure_base64) % 4 != 0:
        disclosure_base64 += "="

    # Decode base64 string
    decoded_bytes = base64.urlsafe_b64decode(disclosure_base64.encode("utf-8"))

    # Decode JSON
    disclosure_json = decoded_bytes.decode("utf-8")
    disclosure = json.loads(disclosure_json)

    return disclosure[-2], disclosure[-1]


def get_all_disclosures_with_sd_from_token(token: str) -> dict:
    disclosures = token.split("~")
    disclosures = disclosures[1:]
    disclosure_mapping = {}
    for disclosure in disclosures:
        sd = create_sd_from_disclosure_base64(disclosure)
        disclosure_mapping[sd] = disclosure
    return disclosure_mapping


def decode_credential_sd_to_credential_subject(
    disclosure_mapping: dict, credential_subject: dict
) -> dict:
    credential_subject = {"credentialSubject": credential_subject}
    _credentialSubject = {**credential_subject}

    def replace_sd_with_credential_subject_attributes(sds: list, disclosure: dict):
        credential_attribute = {}
        for sd in sds:
            disclosure_base64 = disclosure.get(sd)
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


def _create_disclosure_mapping_from_credential_definition(data):
    result = {}
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, dict) and "limitDisclosure" in value and value["limitDisclosure"] is True:
                # Direct property with limitDisclosure
                result[key] = {k: v for k, v in value.items() if k == "limitDisclosure"}
            elif isinstance(value, dict) and "properties" in value:
                # Nested property, need to go deeper
                nested_result = _create_disclosure_mapping_from_credential_definition(value["properties"])
                if nested_result:
                    result[key] = nested_result
    return result

def create_disclosure_mapping_from_credential_definition(credential_definition):
    data = credential_definition["properties"]
    disclosure_mapping = {}
    disclosure_mapping["credentialSubject"] = _create_disclosure_mapping_from_credential_definition(data)
    return disclosure_mapping
