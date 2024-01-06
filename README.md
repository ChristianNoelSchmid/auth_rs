# Rust Auth Server
`auth_rs` is a web application that handles simple authentication and authorization. It has a series of service traits that handle registration, logging in, email verification, and refreshing access. There are core services that implement the application via JSON web tokens.

# Installation
1. Install [Rust](https://www.rust-lang.org/tools/install) using the instructions in the link. 
2. Pull this repository to your local machine
3. Certain environment variables need to be set to run the application. These can be set using your operating system's standard approach, or by creating a `.env` file in the root directory of the program. The variables that need to be set are:
- - `DATABASE_URL`: this is the specific location of the database file on disk. `auth_rs` uses SQLite, and this variable establishes where to load the database from.
- - `JWT_SECRET`: the secret associated with generation of the JSON web tokens. For the default implementation, it must be at least 256 bits (for ASCII, 32 characters).
- - `SENDGRID_API_KEY`: the API key for the mailing service being used in the web application. The application, by default, uses SendGrid - unique implementation is required if other mailing services are desired.

# Config Values
The config values found in `config.json` in the root directory are summarized as follows:
- `auth_service_settings` - the settings associated with the authorization service
- - `issuer` - the JWT issuer. Usually the URL of the web application itself.
- - `audience` - the JWT audience. The intended recipient of the JWT.
- - `refr_token_lifetime` - the lifespan of the refresh token. The format is `<DAYS>.<HOURS>:<MINUTES>:<SECONDS>`. The default is 30 days.
- - `access_token_lifetime` - the lifespan of access tokens. The format is equivalent to `refr_token_lifetime`. The default is 5 minutes.
- `send_email_service_settings` - the settings associated with the email verification service
- - `base_url` - the base URL of this web application. Used to set up the verification link.
- - `from_email_addr` - the email address the email API will send the message from.