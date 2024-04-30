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
    expiry_in_seconds = 3600
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
    expiry_in_seconds = 3600
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
    expiry_in_seconds = 3600
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
        if (len(disclosures) > 0):
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
            if (len(disclosures) > 0):
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