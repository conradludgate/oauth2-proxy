# oauth2-proxy

Managed access to oauth2 accounts

## How it works

1)  Go to https://oauth2.conrad.cafe/register
2)  Enter a username and password and click register
3)  Choose the token type you want to create (currently only supports spotify)
4)  Give the token a name and select the scopes
5)  Clicking submit will redirect you to the identity provider
6)  Redirected back to the token management page. Save the api key and get the token id from the page url

And you're all set. Now you can make a request to

```
POST https://oauth2.conrad.cafe/api/v1/token/<token_id>
Authorization: Basic <base64 encoded username:api_key>
```

And it will respond with your account's access token, token type and expiry time.

```json
{"access_token": "XXXXX", "token_type": "Bearer", "expires": 1610115227}
```

For example:

```
$ xhs post oauth2.conrad.cafe/api/v1/token/1b5420b2-6ede-4a8d-88ce-ee82b5a04678 --auth conradludgate
https: password for conradludgate@oauth2.conrad.cafe: *********
HTTP/1.1 200 OK
content-length: 254
content-type: application/json

{
    "access_token": "BQBZ****BfHA",
    "token_type": "bearer",
    "expires": 1627992501
}
```

When the token has expired, simply call the endpoint again to get a new access token. The proxy takes care of the refreshing of the token.

## Self hosting

> WIP. This documentation needs some work

This project makes use of dynamodb to store data (The free tier is very permissive).

Create a `.env` file will your aws credentials

```
AWS_ACCESS_KEY_ID="..."
AWS_SECRET_ACCESS_KEY="..."
AWS_DEFAULT_REGION="..."
```

And configure your DynamoDB tables according to https://github.com/conradludgate/oauth2-proxy/blob/main/terraform/main.tf

> If you want to self host DynamoDB, check out https://localstack.cloud/

Configure a `Rocket.toml` file similar to the following (adding the oauth2 providers you need)

```toml
[default]
state_key = "random-base64-bytes: `openssl rand -base64 96`"

[default.providers.spotify]
name = "Spotify"

client_id = "Spotify client ID"
client_secret = "Spotify Client Secret"

auth_url = "https://accounts.spotify.com/authorize"
token_url = "https://accounts.spotify.com/api/token"

scopes = [
    "ugc-image-upload",
    "user-read-recently-played",
    "user-top-read",
    "user-read-playback-position",
    "user-read-playback-state",
    "user-modify-playback-state",
    "user-read-currently-playing",
    "app-remote-control",
    "streaming",
    "playlist-modify-public",
    "playlist-modify-private",
    "playlist-read-private",
    "playlist-read-collaborative",
    "user-follow-modify",
    "user-follow-read",
    "user-library-modify",
    "user-library-read",
    "user-read-email",
    "user-read-private",
]

[default.providers.google]
name = "Google"

client_id = "Google client ID"
client_secret = "Google Client Secret"

auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
token_url = "https://oauth2.googleapis.com/token"

scopes = [
    "...",
]
```

Then start the docker container

```
docker run -v `pwd`/Rocket.toml:/app/Rocket.toml --env-file .env -p 27228:27228 ghcr.io/conradludgate/oauth2-proxy:latest
```
