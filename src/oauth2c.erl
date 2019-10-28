%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 Client
%%
%% Copyright (c) 2012-2016 KIVRA
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.
%%
%% ----------------------------------------------------------------------------

-module(oauth2c).

-export([retrieve_access_token/4]).
-export([retrieve_access_token/5]).
-export([retrieve_access_token/6]).

-export([request/3]).
-export([request/4]).
-export([request/5]).
-export([request/6]).
-export([request/7]).
-export([request/8]).

-define(DEFAULT_ENCODING, json).

-record(client, {
        grant_type    = undefined :: binary()     | undefined,
        auth_url      = undefined :: binary()     | undefined,
        access_token  = undefined :: binary()     | undefined,
        token_type    = undefined :: token_type() | undefined,
        refresh_token = undefined :: binary()     | undefined,
        id            = undefined :: binary()     | undefined,
        secret        = undefined :: binary()     | undefined,
        scope         = undefined :: binary()     | undefined
}).

-type method()         :: head    |
                          get     |
                          put     |
                          patch   |
                          post    |
                          trace   |
                          options |
                          delete.
-type url()            :: binary().
%% <<"password">> or <<"client_credentials">>
-type at_type()        :: binary().
-type headers()        :: [header()].
-type header()         :: {binary(), binary()}.
-type status_codes()   :: [status_code()].
-type status_code()    :: integer().
-type reason()         :: term().
-type content_type()   :: json | xml | percent.
-type property()       :: atom() | tuple().
-type proplist()       :: [property()].
-type options()        :: proplist().
-type body()           :: proplist().
-type restc_response() :: { ok
                          , Status::status_code()
                          , Headers::headers()
                          , Body::body()}          |
                          { error
                          , Status::status_code()
                          , Headers::headers()
                          , Body::body()}          |
                          { error, Reason::reason()}.
-type response()       :: {restc_response(), #client{}}.
-type token_type()     :: bearer | unsupported.
-type client()         :: #client{}.

%%% API ========================================================================
-spec retrieve_access_token(Type, URL, ID, Secret) ->
    {ok, Headers::headers(), client()} | {error, Reason :: binary()} when
    Type   :: at_type(),
    URL    :: url(),
    ID     :: binary(),
    Secret :: binary().
retrieve_access_token(Type, Url, ID, Secret) ->
  retrieve_access_token(Type, Url, ID, Secret, undefined).

-spec retrieve_access_token(Type, URL, ID, Secret, Scope) ->
    {ok, Headers::headers(), client()} | {error, Reason :: binary()} when
    Type   :: at_type(),
    URL    :: url(),
    ID     :: binary(),
    Secret :: binary(),
    Scope  :: binary() | undefined.
retrieve_access_token(Type, Url, ID, Secret, Scope) ->
  retrieve_access_token(Type, Url, ID, Secret, Scope, []).

-spec retrieve_access_token(Type, URL, ID, Secret, Scope, Options) ->
    {ok, Headers::headers(), client()} | {error, Reason :: binary()} when
    Type    :: at_type(),
    URL     :: url(),
    ID      :: binary(),
    Secret  :: binary(),
    Scope   :: binary() | undefined,
    Options :: list().
retrieve_access_token(Type, Url, ID, Secret, Scope, Options) ->
  Client = #client{
              grant_type = Type
             ,auth_url  = Url
             ,id        = ID
             ,secret    = Secret
             ,scope     = Scope
             },
  do_retrieve_access_token(Client, Options).

-spec request(Method, Url, Client) -> Response::response() when
    Method :: method(),
    Url    :: url(),
    Client :: client().
request(Method, Url, Client) ->
  request(Method, ?DEFAULT_ENCODING, Url, [], [], [], Client).

-spec request(Method, Url, Expect, Client) -> Response::response() when
    Method :: method(),
    Url    :: url(),
    Expect :: status_codes(),
    Client :: client().
request(Method, Url, Expect, Client) ->
  request(Method, ?DEFAULT_ENCODING, Url, Expect, [], [], Client).

-spec request(Method, Type, Url, Expect, Client) -> Response::response() when
    Method :: method(),
    Type   :: content_type(),
    Url    :: url(),
    Expect :: status_codes(),
    Client :: client().
request(Method, Type, Url, Expect, Client) ->
  request(Method, Type, Url, Expect, [], [], Client).

-spec request(Method, Type, Url, Expect, Headers, Client) ->
        Response::response() when
    Method  :: method(),
    Type    :: content_type(),
    Url     :: url(),
    Expect  :: status_codes(),
    Headers :: headers(),
    Client  :: client().
request(Method, Type, Url, Expect, Headers, Client) ->
    request(Method, Type, Url, Expect, Headers, [], Client).

-spec request(Method, Type, Url, Expect, Headers, Body, Client) ->
        Response::response() when
    Method  :: method(),
    Type    :: content_type(),
    Url     :: url(),
    Expect  :: status_codes(),
    Headers :: headers(),
    Body    :: body(),
    Client  :: client().
request(Method, Type, Url, Expect, Headers, Body, Client) ->
  request(Method, Type, Url, Expect, Headers, Body, [], Client).

-spec request(Method, Type, Url, Expect, Headers, Body, Options, Client) ->
        Response::response() when
    Method  :: method(),
    Type    :: content_type(),
    Url     :: url(),
    Expect  :: status_codes(),
    Headers :: headers(),
    Body    :: body(),
    Options :: options(),
    Client  :: client().
request(Method, Type, Url, Expect, Headers, Body, Options, Client) ->
  case do_request(Method,Type,Url,Expect,Headers,Body,Options,Client) of
    {{_, 401, _, _}, Client2} ->
      {ok, _RetrHeaders, Client3} =
        do_retrieve_access_token(Client2, Options),
      do_request(Method,Type,Url,Expect,Headers,Body,Options,Client3);
    Result -> Result
  end.
%%% INTERNAL ===================================================================
do_retrieve_access_token(#client{grant_type = <<"password">>} = Client, Opts) ->
  Payload0 = [
              {<<"grant_type">>, Client#client.grant_type}
             ,{<<"username">>, Client#client.id}
             ,{<<"password">>, Client#client.secret}
             ],
  Payload = case Client#client.scope of
              undefined -> Payload0;
              Scope -> [{<<"scope">>, Scope}|Payload0]
            end,
  Response =
    restc:request(post, percent, Client#client.auth_url, [200], [],
                  Payload, Opts),
  case Response of
    {ok, _, Headers, Body} ->
      AccessToken = proplists:get_value(<<"access_token">>, Body),
      RefreshToken = proplists:get_value(<<"refresh_token">>, Body),
      Result = case RefreshToken of
                 undefined ->
                   #client{
                      grant_type    = Client#client.grant_type
                     ,auth_url     = Client#client.auth_url
                     ,access_token = AccessToken
                     ,id           = Client#client.id
                     ,secret       = Client#client.secret
                     ,scope        = Client#client.scope
                     };
                 _ ->
                   #client{
                      grant_type     = Client#client.grant_type
                     ,auth_url      = Client#client.auth_url
                     ,access_token  = AccessToken
                     ,refresh_token = RefreshToken
                     ,scope         = Client#client.scope
                     }
               end,
      {ok, Headers, Result};
    {error, _, _, Reason} ->
      {error, Reason};
    {error, Reason} ->
      {error, Reason}
  end;
do_retrieve_access_token(#client{grant_type = <<"client_credentials">>,
                                 id = Id, secret = Secret} = Client, Opts) ->
  Payload0 = [{<<"grant_type">>, Client#client.grant_type}],
  Payload = case Client#client.scope of
              undefined ->
                Payload0;
              Scope ->
                [{<<"scope">>, Scope}|Payload0]
            end,
  Auth = base64:encode(<<Id/binary, ":", Secret/binary>>),
  Header = [{<<"Authorization">>, <<"Basic ", Auth/binary>>}],
  case restc:request(post, percent, Client#client.auth_url,
                     [200], Header, Payload, Opts) of
    {ok, _, Headers, Body} ->
      AccessToken = proplists:get_value(<<"access_token">>, Body),
      TokenType = proplists:get_value(<<"token_type">>, Body, ""),
      Result = #client{
                  grant_type    = Client#client.grant_type
                 ,auth_url     = Client#client.auth_url
                 ,access_token = AccessToken
                 ,token_type   = get_token_type(TokenType)
                 ,id           = Client#client.id
                 ,secret       = Client#client.secret
                 ,scope        = Client#client.scope
                 },
      {ok, Headers, Result};
    {error, _, _, Reason} ->
      {error, Reason};
    {error, Reason} ->
      {error, Reason}
  end;
do_retrieve_access_token(#client{grant_type = <<"azure_client_credentials">>,
                                 id = Id, secret = Secret} = Client, Opts) ->
  Payload0 = [{<<"grant_type">>, <<"client_credentials">>},
              {<<"client_id">>, Id},
              {<<"client_secret">>, Secret}],
  Payload = case Client#client.scope of
              undefined ->
                Payload0;
              Scope ->
                [{<<"resource">>, Scope}|Payload0]
            end,
  case restc:request(post, percent, Client#client.auth_url,
                     [200], [], Payload, Opts) of
    {ok, _, Headers, Body} ->
      AccessToken = proplists:get_value(<<"access_token">>, Body),
      TokenType = proplists:get_value(<<"token_type">>, Body, ""),
      Result = #client{
                  grant_type    = Client#client.grant_type
                 ,auth_url     = Client#client.auth_url
                 ,access_token = AccessToken
                 ,token_type   = get_token_type(TokenType)
                 ,id           = Client#client.id
                 ,secret       = Client#client.secret
                 ,scope        = Client#client.scope
                 },
      {ok, Headers, Result};
    {error, _, _, Reason} ->
      {error, Reason};
    {error, Reason} ->
      {error, Reason}
  end.

-spec get_token_type(binary()) -> token_type().
get_token_type(Type) ->
  get_str_token_type(string:to_lower(binary_to_list(Type))).

-spec get_str_token_type(string()) -> token_type().
get_str_token_type("bearer") -> bearer;
get_str_token_type(_Else) -> unsupported.

do_request(Method, Type, Url, Expect, Headers, Body, Options, Client) ->
  Headers2 = add_auth_header(Headers, Client),
  {restc:request(Method, Type, Url, Expect, Headers2, Body, Options), Client}.

add_auth_header(Headers, #client{grant_type = <<"azure_client_credentials">>,
                                 access_token = AccessToken}) ->
  AH = {<<"Authorization">>, <<"bearer ", AccessToken/binary>>},
  [AH | proplists:delete(<<"Authorization">>, Headers)];
add_auth_header(Headers, #client{token_type = bearer,
                                 access_token = AccessToken}) ->
  AH = {<<"Authorization">>, <<"bearer ", AccessToken/binary>>},
  [AH | proplists:delete(<<"Authorization">>, Headers)];
add_auth_header(Headers, #client{access_token = AccessToken}) ->
  AH = {<<"Authorization">>, <<"token ", AccessToken/binary>>},
  [AH | proplists:delete(<<"Authorization">>, Headers)].

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
