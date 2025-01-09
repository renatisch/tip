import requests
from typing import Optional
from pydantic import BaseModel
import jwt
import random, string
import boto3


class OidcData(BaseModel):
    """OIDC OAuth data"""
    id_token: Optional[str] = None
    access_token: Optional[str] = None
    jwt_email: Optional[str] = None
    jwt_sub: Optional[str] = None

def get_oidc_id_token(base_url: str, code: str, token_uri: str, client_id: str,
                      client_secret: str, timeout: int = 120) -> OidcData:
    """Obtain OIDC access and identity token"""
    payload = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': base_url,
        'client_id':client_id,
        'client_secret': client_secret
    }
    exchange = requests.post(
        token_uri,
        data=payload,
        timeout=timeout
    ).json()    
    id_token = exchange.get("id_token")
    oidc_id_jwt = jwt.decode(
        id_token,
        algorithms=["RS256"],
        options={"verify_signature": False}
    )


    access_token = exchange.get("access_token")
    return OidcData(
        id_token=id_token,
        access_token=access_token,
        jwt_sub=oidc_id_jwt.get("sub"),
        jwt_email=oidc_id_jwt.get("email"),
    )


def get_idc_sts_id_context(idc_app_auth_provider_arn: str, id_token: str,
                           region_name: str) -> str:
    """Exchanges OIDC ID token with IDC provide app to get STS id context"""
    sso_oidc_client = boto3.client('sso-oidc', region_name=region_name)
    try:
        idc_sso_resp = sso_oidc_client.create_token_with_iam(
            clientId=idc_app_auth_provider_arn,
            grantType="urn:ietf:params:oauth:grant-type:jwt-bearer",
            assertion=id_token,
        )
        # print("Issued token type ->>> ",idc_sso_resp['issuedTokenType'])
        # print("AWS Scopes ->>>>", idc_sso_resp['scope'])
        # print("ID Token ->>>>", idc_sso_resp['idToken'])
        idc_id_jwt = jwt.decode(
            idc_sso_resp["idToken"],
            algorithms=["RS256"],
            options={"verify_signature": False}
        )
        return idc_id_jwt["sts:identity_context"]
    except Exception as Error:
        # err_msg = (
        #     "CreateTokenWithIAM failed with invalid grant exception. "
        #     "Check if 1/ identity token is reused, 2/ IDC is missing TTI configuration, "
        #     "or 3/ user's primary email in IAM identity center matches the email address of user "
        #     "signing-in via external identity provider."
        # )
        print(Error)

def get_sts_credential(idc_assume_role_arn: str, sts_context: str,
                       region_name: str) -> dict:
    """Assumes IDC ID based role and generates aws credentials"""
    sts_client = boto3.client('sts', region_name=region_name)
    # Random hash used of unique session name. collisions are fine.
    session_name = "qbusiness-idc-" + "".join(
        random.choices(string.ascii_letters + string.digits, k=32)  # nosec
    )
    assumed_role_object = sts_client.assume_role(
        RoleArn=idc_assume_role_arn,
        RoleSessionName=session_name,
        ProvidedContexts=[{
            "ProviderArn": "arn:aws:iam::aws:contextProvider/IdentityCenter",
            "ContextAssertion": sts_context
        }]
    )
    credential = assumed_role_object.get('Credentials')
    return credential


  