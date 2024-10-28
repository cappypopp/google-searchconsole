# encoding: utf-8

"""
Convenience function for authenticating with Google Search
Console. You can use saved client configuration files or a
mapping object and generate your credentials using OAuth2, a
serialized credentials file, or a service account.

For more details on formatting your configuration files, see:
http://google-auth-oauthlib.readthedocs.io/en/latest/reference/google_auth_oauthlib.flow.html
"""

import collections.abc
import json
import os

from apiclient import discovery
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials as OAuthCredentials
from google.oauth2.service_account import Credentials as ServiceAccountCredentials
from google_auth_oauthlib.flow import InstalledAppFlow

from .account import Account


def authenticate(client_config, credentials=None, serialize=None, flow="web", user=None):
    """
    The `authenticate` function will authenticate a user with the Google Search
    Console API.

    Args:
        client_config (collections.abc.Mapping or str): Client configuration
            parameters in the Google format specified in the module docstring.
        credentials (collections.abc.Mapping or str): OAuth2 credentials
            parameters in the Google format specified in the module docstring.
        serialize (str): Path to where credentials should be serialized.
        flow (str): Authentication environment. Specify "console" for environments (like Google Colab)
            where the standard "web" flow isn't possible, or "service_account" for delegated authority.
        user (str): Email address of the user to impersonate when using a service account.

    Returns:
        `searchconsole.account.Account`: Account object containing web
        properties that can be queried.

    Usage:
        >>> import searchconsole
        >>> account = searchconsole.authenticate(
        ...     client_config='auth/client_secrets.json',
        ...     credentials='auth/credentials.dat',
        ...     flow='service_account',
        ...     user='<EMAIL>'
        ... )
    """
    SCOPES = ['https://www.googleapis.com/auth/webmasters.readonly']

    # If no credentials are provided, authenticate using client_config
    if not credentials:

        # Using client secrets or mapping for OAuth flow
        if isinstance(client_config, collections.abc.Mapping):
            auth_flow = InstalledAppFlow.from_client_config(
                client_config=client_config,
                scopes=SCOPES
            )

        elif isinstance(client_config, str) and flow == "service_account":
            # Service account flow with impersonation
            credentials = service_account.Credentials.from_service_account_file(
                client_config, scopes=SCOPES
            )
            if user:
                credentials = credentials.with_subject(user)

        elif isinstance(client_config, str):
            # OAuth2 client secrets file
            auth_flow = InstalledAppFlow.from_client_secrets_file(
                client_secrets_file=client_config,
                scopes=SCOPES
            )
        else:
            raise ValueError("Client secrets must be a mapping or path to file")

        # Handle OAuth2 flow
        if flow in ["web", "console"]:
            if flow == "web":
                auth_flow.run_local_server()
            elif flow == "console":
                auth_flow.run_console()
            credentials = auth_flow.credentials
        elif flow != "service_account":
            raise ValueError("Authentication flow '{}' not supported".format(flow))

    # If credentials are provided, load them
    else:
        if isinstance(credentials, str):
            with open(credentials, 'r') as f:
                credentials = json.load(f)
        if 'refresh_token' in credentials:
            # we have oauth credentials
            credentials = OAuthCredentials(
                token=credentials['token'],
                refresh_token=credentials['refresh_token'],
                id_token=credentials['id_token'],
                token_uri=credentials['token_uri'],
                client_id=credentials['client_id'],
                client_secret=credentials['client_secret'],
                scopes=credentials['scopes']
            )
        elif 'service_account_email' in credentials:
            # we have a service account, use its credentials
            credentials = ServiceAccountCredentials(
                    signer=credentials['signer'],
                    service_account_email=credentials['service_account_email'],
                    token_uri=credentials['token_uri'],
                    scopes=credentials['scopes'],
                    default_scopes=credentials['default_scopes'],
                    subject=credentials['subject'],
                    project_id=credentials['project_id']
            )
        else:
            raise ValueError('Loaded credentials are not OAuth or Service Account type.')



    # Build the service object
    service = discovery.build(
        serviceName='searchconsole',
        version='v1',
        credentials=credentials,
        cache_discovery=False,
    )

    # Serialize credentials if requested
    if serialize and isinstance(serialize, str):
        if os.path.exists(serialize):
            if 'refresh_token' in credentials:
                serialized = {
                    'token': credentials.token,
                    'refresh_token': credentials.refresh_token,
                    'id_token': credentials.id_token,
                    'token_uri': credentials.token_uri,
                    'client_id': credentials.client_id,
                    'client_secret': credentials.client_secret,
                    'scopes': credentials.scopes
                }
            else: # service account
                serialized = {
                    'signer': credentials['signer'],
                    'service_account_email': credentials['service_account_email'],
                    'token_uri': credentials['token_uri'],
                    'scopes': credentials['scopes'],
                    'default_scopes': credentials['default_scopes'],
                    'subject': credentials['subject'],
                    'project_id': credentials['project_id']
                }
            with open(serialize, 'w') as f:
                json.dump(serialized, f)
    elif serialize:
        raise TypeError('`serialize` must be a path.')

    return Account(service, credentials)
