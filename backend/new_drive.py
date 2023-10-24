# -*- coding: utf-8 -*-

import os
import flask
import requests

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

import io
from flask import send_file


# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
# CLIENT_SECRETS_FILE = "client_secret.json"
CLIENT_SECRETS_FILE = "credentials.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
# SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly']
SCOPES = [
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/drive.metadata.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/drive',
    'openid'
]


API_SERVICE_NAME = 'drive'
API_VERSION = 'v3'

app = flask.Flask(__name__)
# Note: A secret key is included in the sample so that it works.
# If you use this code in your application, replace this with a truly secret
# key. See https://flask.palletsprojects.com/quickstart/#sessions.
app.secret_key = 'REPLACE ME - this value is here as a placeholder.'


@app.route('/')
def index():
    return print_index_table()


# 找到主目录（My Drive）的 ID
def find_root_id(drive_service):
    # 我们假设主目录没有父目录（parents）
    results = drive_service.files().list(q="name='root' and mimeType='application/vnd.google-apps.folder' and trashed=false").execute()
    items = results.get('files', [])
    if len(items) > 0:
        return items[0]['id']
    else:
        return None

@app.route('/test')
def test_api_request():
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    drive = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # files = drive.files().list().execute()
    # files = drive.files().list(fields='files(id, name, mimeType, webViewLink)').execute()
    files = drive.files().list(fields='files(id, name, mimeType, parents)').execute()

    # 递归地构建文件树
    def build_tree(files, parent=None):
        return [
            {
                'file': file,
                'children': build_tree(files, file['id']),
                # 'type': 'folder' if file['mimeType'] == 'application/vnd.google-apps.folder' else 'file'
            }
            for file in files if (not file.get('parents') and not parent) or (file.get('parents') and file['parents'][0] == parent) 
        ] 

    # root_id = find_root_id(drive)
    # print(root_id)

    # file_id set
    file_ids = set()
    for file in files['files']:
        file_ids.add(file['id'])
    # parent_id set
    parent_ids = set()
    for file in files['files']:
        if file.get('parents'):
            parent_ids.add(file['parents'][0])
    root_list = list(parent_ids - file_ids)
    assert len(root_list) == 1
    root = root_list[0]
    file_tree = build_tree(files['files']) + build_tree(files['files'], root)

    # Save credentials back to session in case access token was refreshed.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    flask.session['credentials'] = credentials_to_dict(credentials)

    # return flask.jsonify(**files)
    # return flask.render_template('test.html', files_json=flask.json.dumps(files))
    return flask.render_template('file_tree.html', file_tree=file_tree)



@app.route('/file/<file_id>')
def get_file(file_id):
    if 'credentials' not in flask.session:
        return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    drive = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials)

    # Attempt to get the file's metadata to determine its type.
    file_metadata = drive.files().get(fileId=file_id).execute()
    mime_type = file_metadata.get('mimeType', '')

    if mime_type.startswith('application/vnd.google-apps.'):
        # This is a Google Docs editor file; export it.
        request = drive.files().export_media(fileId=file_id, mimeType='application/pdf')
        file_extension = '.pdf'
    else:
        # This is not a Google Docs editor file; download it.
        request = drive.files().get_media(fileId=file_id)
        file_extension = ''


    fh = io.BytesIO()
    downloader = googleapiclient.http.MediaIoBaseDownload(fh, request)
    done = False
    while done is False:
        status, done = downloader.next_chunk()

    # Save credentials back to session in case access token was refreshed.
    flask.session['credentials'] = credentials_to_dict(credentials)

    # Return the file content.
    response = send_file(
        io.BytesIO(fh.getvalue()),
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'downloaded_file{file_extension}'
    )
    # response.headers["Content-Disposition"] = f"attachment; filename=downloaded_file{file_extension}"
    response.headers["Content-Disposition"] = f"inline; filename=downloaded_file{file_extension}"
    return response

@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    # The URI created here must exactly match one of the authorized redirect URIs
    # for the OAuth 2.0 client, which you configured in the API Console. If this
    # value doesn't match an authorized URI, you will get a 'redirect_uri_mismatch'
    # error.
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state

    return flask.redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)

    return flask.redirect(flask.url_for('test_api_request'))


@app.route('/revoke')
def revoke():
    if 'credentials' not in flask.session:
        return ('You need to <a href="/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials'])

    revoke = requests.post('https://oauth2.googleapis.com/revoke',
                           params={'token': credentials.token},
                           headers={'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return ('Credentials successfully revoked.' + print_index_table())
    else:
        return ('An error occurred.' + print_index_table())


@app.route('/clear')
def clear_credentials():
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>' +
            print_index_table())


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


def print_index_table():
    return ('<table>' +
            '<tr><td><a href="/test">Test an API request</a></td>' +
            '<td>Submit an API request and see a formatted JSON response. ' +
            '    Go through the authorization flow if there are no stored ' +
            '    credentials for the user.</td></tr>' +
            '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
            '<td>Go directly to the authorization flow. If there are stored ' +
            '    credentials, you still might not be prompted to reauthorize ' +
            '    the application.</td></tr>' +
            '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
            '<td>Revoke the access token associated with the current user ' +
            '    session. After revoking credentials, if you go to the test ' +
            '    page, you should see an <code>invalid_grant</code> error.' +
            '</td></tr>' +
            '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
            '<td>Clear the access token currently stored in the user session. ' +
            '    After clearing the token, if you <a href="/test">test the ' +
            '    API request</a> again, you should go back to the auth flow.' +
            '</td></tr></table>')


if __name__ == '__main__':
    # When running locally, disable OAuthlib's HTTPs verification.
    # ACTION ITEM for developers:
    #     When running in production *do not* leave this option enabled.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    # Specify a hostname and port that are set as a valid redirect URI
    # for your API project in the Google API Console.
    app.run('localhost', 3000, debug=True)
