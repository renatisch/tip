from flask import Flask, render_template, redirect, request, url_for
import requests
from utils import get_oidc_id_token, get_idc_sts_id_context, get_sts_credential
import dotenv, os
from redshift import fetch_redshift_data

app = Flask(__name__)
dotenv.load_dotenv()
# Get initial variables
tenant_id = os.getenv("tenant_id")
client_id = os.getenv("client_id")
client_secret = os.getenv("client_secret")
app_host = os.getenv("app_host")
idc_provider_apl_arn = os.getenv("idc_provider_apl_arn")
region = os.getenv("region_name")
aws_role = os.getenv("aws_role")
redshift_host = os.getenv("aws_role")
redshift_database = os.getenv("aws_role")

# print(aws_role)
# print(idc_provider_apl_arn)
# print(client_id)

@app.route("/success")
def success():
    access_key_id = request.args.get('access_key_id')
    secret_access_key = request.args.get('secret_access_key')
    session_token = request.args.get("session_token")
    azure_ad_access_token = request.args.get("azure_ad_access_token")
    azure_ad_id_token = request.args.get("azure_ad_id_token")
    """Success page"""
    return render_template("success.html",
                           access_key_id=access_key_id,
                           secret_access_key=secret_access_key,
                           session_token=session_token,
                           azure_ad_access_token = azure_ad_access_token,
                           azure_ad_id_token = azure_ad_id_token
                           )

@app.route("/")
def home():
    """Home page"""
    return render_template("home.html")

@app.route("/login")
def login():
    """Sign-on user with Azure AD app"""
    query_params = {
        'client_id': client_id,
        'redirect_uri': f'http://{app_host}/authorization-code/callback',
        'scope': "openid email profile",
        'state': "APP_STATE",
        'nonce': "NONCE",
        'response_type': 'code',
        'response_mode': 'query'
    }
    base_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    query_params = requests.compat.urlencode(query_params)
    request_uri = f"{base_url}?{query_params}"
    return redirect(request_uri)

@app.route("/authorization-code/callback")
def callback():
    """SSO callback"""
    code = request.args.get("code")
    if not code:
        return "The authorization code was not returned or is not accessible", 403
    # Get OIDC token from azure ad
    oidc_data = get_oidc_id_token(
        base_url=request.base_url,
        code=code,
        token_uri=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        client_id=f"{client_id}",
        client_secret=f"{client_secret}"
    )

    # Get STS ID context IDC
    idc_sts_context = get_idc_sts_id_context(
            idc_app_auth_provider_arn=idc_provider_apl_arn,
            id_token=oidc_data.id_token,
            region_name="eu-central-1"
        )
    # print("AWS STS context ->>>", idc_sts_context)
    # GET STS credentials
    credential = get_sts_credential(
        idc_assume_role_arn=aws_role,
        sts_context=idc_sts_context,
        region_name="eu-central-1"
        )
    # print("Final AWS credentials ->>>", credential)
    
    return redirect(url_for("success",
                            access_key_id = credential['AccessKeyId'],
                            secret_access_key = credential['SecretAccessKey'],
                            session_token = credential['SessionToken'],
                            azure_ad_id_token=oidc_data.id_token,
                            azure_ad_access_token=oidc_data.access_token
                            )
                            )


@app.route("/data/read", methods=['POST'])
def read_redshift_data():
    azure_ad_id_token = request.form.get('azure_ad_id_token')
    db_host="default-workgroup.195275659820.eu-central-1.redshift-serverless.amazonaws.com"
    db_name="dev"
    redshift_data = fetch_redshift_data(host=db_host, database=db_name, token=azure_ad_id_token)
    users = [user[0] for user in redshift_data]
    return render_template("redshift.html",
                           azure_ad_id_token = azure_ad_id_token,
                           users = users
                           )

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=True)
