# Oauth2 Client
This library is designed to simplify consuming Oauth2 enabled REST Services. It wraps a restclient and takes care of reauthenticating expired access_tokens when needed.

## Flows

Implemented flows are:

- Client Credentials Grant
- Resource Owner Password Credentials Grant

## Example

Retrieve a client with access_token using Password Credentials Grant

```erlang
1> oauth2c:retrieve_access_token(<<"password">>, <<"Url">>, <<"Uid">>, <<"Pwd">>).
{ok, Headers, Client}
```

Retrieve a client with access_token using Client Credentials Grant

```erlang
2> oauth2c:retrieve_access_token(<<"client_credentials">>, <<"Url">>, <<"Client">>, <<"Secret">>).
{ok, Headers, Client}
```

The Opaque `Client` object is to be used on subsequent requests like:

```erlang
3> oauth2c:request(get, json, <<"Url">>, [200], Client).
{{ok, Status, Headers, Body} Client2}
```

See [restclient](https://github.com/kivra/restclient) for more info on how requests work.

## License
The KIVRA oauth2 library uses an [MIT license](http://en.wikipedia.org/wiki/MIT_License). So go ahead and do what
you want!
