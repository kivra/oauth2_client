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

## Twitter Example

```erlang
-module(oauth2c_twitter_example).

-export([ run/0
        ]).

-define(CONSUMER_SECRET, <<"my_consumer_secret">>).
-define(CONSUMER_KEY, <<"my_consumer_key">>).

-define(OAUTH2_TOKEN_URL, <<"https://api.twitter.com/oauth2/token">>).

-define(USER_TIMELINE_URL(User, StrCount),
        <<"https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name="
          , User, "&count=", StrCount>>).

-define(APP_LIMITS_URL(Resources),
        << "https://api.twitter.com/1.1/application/rate_limit_status.json?resources="
           , Resources>>).
run() ->
    application:ensure_all_started(oauth2c),
    application:ensure_all_started(ssl),
    {ok, _Headers, Client} =
        oauth2c:retrieve_access_token(
          <<"client_credentials">>, ?OAUTH2_TOKEN_URL, ?CONSUMER_KEY,
          ?CONSUMER_SECRET),
    {{ok, _Status1, _Headers1, Tweets}, Client2} =
        oauth2c:request(
          get, json, ?USER_TIMELINE_URL("twitterapi", "4"), [200], Client),
    io:format("Tweets: ~p~n", [Tweets]),
    {{ok, _Status2, _Headers2, Limits}, _Client3} =
        oauth2c:request(
          get, json, ?APP_LIMITS_URL("help,users,search,statuses"),
          [200], Client2),
    io:format("Limits: ~p~n", [Limits]),
    ok.
```

## License
The KIVRA oauth2 library uses an [MIT license](http://en.wikipedia.org/wiki/MIT_License). So go ahead and do what
you want!
