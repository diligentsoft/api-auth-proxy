# api-auth-proxy

API authentication proxy, able to handle both the client and server side concerns of the OAuth Client Credentials flow
by operating in forward and reverse proxy modes.

## Features

### Current

 * Signing of outgoing requests (in forward proxy mode) by obtaining an access token
 * Authentication of incoming requests (in reverse proxy mode) by checking access token in Authorization header
 * Basic configuration - some parameters used in token operations externalised as configuration properties

### Future

 * Re-use valid token between requests instead of fetching anew each time
 * Refresh token when expired
 * Authorisation checks on URL paths and HTTP methods
 * Comprehensive configuration - all parameters used in token operations externalised as configuration properties
 * Auto-discovery of token and key endpoints using well-known OAuth config URL
