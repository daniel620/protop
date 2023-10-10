# server.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from oauth2client.client import Credentials
from pydrive.drive import GoogleDrive

app = Flask(__name__)
CORS(app)

@app.route('/auth/google', methods=['POST'])
def google_auth():
    token = request.json.get('token')
    credentials = Credentials.from_client_info(client_info={
        "client_id": "404310616763-0et1d3adnh5kdmf29pujrtmbrrgmlehf.apps.googleusercontent.com",
        "client_secret": "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",
        "redirect_uris": ["http://localhost:3000"],  # Replace with your redirect URI
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://accounts.google.com/o/oauth2/token"
    }, token_response={"access_token": token})
    
    drive = GoogleDrive(credentials)
    file1 = drive.CreateFile({'title': 'Hello.txt'})  # Create GoogleDriveFile instance with title 'Hello.txt'.
    file1.Upload()  # Upload the file.
    return jsonify({"message": "File uploaded"}), 200

if __name__ == '__main__':
    app.run(debug=True)

# [submodule "google-login]
#   path = google-login