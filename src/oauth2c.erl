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

-export([client/4]).
-export([client/5]).

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
-define(TOKEN_CACHE_SERVER, oauth2c_token_cache).

-include("oauth2c.hrl").

%%% API ========================================================================

-spec client(Type, URL, ID, Secret) -> client() when
    Type   :: at_type(),
    URL    :: url(),
    ID     :: binary(),
    Secret :: binary().
client(Type, URL, ID, Secret) ->
  client(Type, URL, ID, Secret, undefined).

-spec client(Type, URL, ID, Secret, Scope) -> client() when
    Type   :: at_type(),
    URL    :: url(),
    ID     :: binary(),
    Secret :: binary(),
    Scope  :: binary() | undefined.
client(Type, URL, ID, Secret, Scope) ->
   #client{ grant_type = Type
          , auth_url  = URL
          , id        = ID
          , secret    = Secret
          , scope     = Scope
          }.

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
    Options :: options().
retrieve_access_token(Type, Url, ID, Secret, Scope, Options) ->
  Client = #client{ grant_type = Type
                  , auth_url  = Url
                  , id        = ID
                  , secret    = Secret
                  , scope     = Scope
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

request(Method, Type, Url, Expect, Headers, Body, Options, Client0) ->
  Client1 = ensure_client_has_access_token(Client0, Options),
  case do_request(Method,Type,Url,Expect,Headers,Body,Options,Client1) of
    {{_, 401, _, _}, Client2} ->
      {ok, Client3} = get_access_token(Client2#client{access_token = undefined},
                                      [force_revalidate | Options]),
      do_request(Method, Type, Url, Expect, Headers, Body, Options, Client3);
    Result -> Result
  end.

%%% INTERNAL ===================================================================

ensure_client_has_access_token(Client0, Options) ->
  case Client0 of
    #client{access_token = undefined} ->
      {ok, Client} = get_access_token(Client0, Options),
      Client;
    _ ->
      Client0
  end.

do_retrieve_access_token(Client, Opts) ->
  #{headers := RequestHeaders,
    body := RequestBody} = prepare_token_request(Client, Opts),
  case restc:request(post, percent, Client#client.auth_url,
                     [200], RequestHeaders, RequestBody, Opts)
  of
    {ok, _, Headers, Body} ->
      AccessToken = proplists:get_value(<<"access_token">>, Body),
      TokenType = proplists:get_value(<<"token_type">>, Body, ""),
      ExpiresIn = proplists:get_value(<<"expires_in">>, Body),
      RefreshToken = proplists:get_value(<<"refresh_token">>,
                                         Body,
                                         Client#client.refresh_token),
      Result = #client{ grant_type    = Client#client.grant_type
                      , auth_url      = Client#client.auth_url
                      , access_token  = AccessToken
                      , refresh_token = RefreshToken
                      , token_type    = get_token_type(TokenType)
                      , id            = Client#client.id
                      , secret        = Client#client.secret
                      , scope         = Client#client.scope
                      , expires_in    = ExpiresIn
                      },
      {ok, Headers, Result};
    {error, _, _, Reason} ->
      {error, Reason};
    {error, Reason} ->
      {error, Reason}
  end.

prepare_token_request(Client, Opts) ->
  BaseRequest = base_request(Client),
  Request0 = add_client(BaseRequest, Client, Opts),
  add_fields(Request0, Client).

base_request(#client{grant_type = <<"azure_client_credentials">>}) ->
  #{headers => [], body => [{<<"grant_type">>, <<"client_credentials">>}]};
base_request(#client{grant_type = GrantType}) ->
  #{headers => [], body => [{<<"grant_type">>, GrantType}]}.

add_client(Request0, Client, Opts) ->
  #client{id = Id, secret = Secret} = Client,
  case
    {Client#client.grant_type =:= <<"password">>,
     Client#client.grant_type =:= <<"azure_client_credentials">> orelse
     proplists:get_value(credentials_in_body, Opts, false)}
  of
    {false, false} ->
      #{headers := Headers0} = Request0,
      Auth = base64:encode(<<Id/binary, ":", Secret/binary>>),
      Headers = [{<<"Authorization">>, <<"Basic ", Auth/binary>>}
                 | Headers0],
      Request0#{headers => Headers};
    {false, true} ->
      #{body := Body} = Request0,
      Request0#{body => [{<<"client_id">>, Id},
                         {<<"client_secret">>, Secret}
                         | Body]};
    %% This clause is to still support password grant "as is" but
    %% in the future this should be changed in order to support
    %% client authentication in the password grant. Right now we
    %% are assuming that if the grant is password then the client is public
    %% which is not a fair assumption.
    {true, _} ->
      #{body := Body} = Request0,
      Request0#{body => [{<<"username">>, Id},
                         {<<"password">>, Secret} | Body]}
  end.

add_fields(Request, #client{scope=undefined}) ->
  Request;
add_fields(Request, #client{grant_type = <<"azure_client_credentials">>,
                            scope = Scope}) ->
  #{body := Body} = Request,
  Request#{body => [{<<"resource">>, Scope} | Body]};
add_fields(Request, #client{scope = Scope}) ->
  #{body := Body} = Request,
  Request#{body => [{<<"scope">>, Scope} | Body]}.

-spec get_token_type(binary()) -> token_type().
get_token_type(Type) ->
  get_str_token_type(string:to_lower(binary_to_list(Type))).

-spec get_str_token_type(string()) -> token_type().
get_str_token_type("bearer") -> bearer;
get_str_token_type(_Else) -> unsupported.

do_request(Method, Type, Url, Expect, Headers0, Body, Options, Client) ->
  Headers = add_auth_header(Headers0, Client),
  {restc:request(Method, Type, Url, Expect, Headers, Body, Options), Client}.

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

retrieve_access_token_fun(Client0, Options) ->
  fun() ->
      case do_retrieve_access_token(Client0, Options) of
        {ok, _Headers, Client} -> {ok, Client, Client#client.expires_in};
        {error, Reason} -> {error, Reason}
      end
  end.

get_access_token(#client{expires_in = ExpiresIn} = Client0, Options) ->
  case {proplists:get_value(cache_token, Options, false),
        proplists:get_value(force_revalidate, Options, false)}
  of
    {false, _} ->
      {ok, _Headers, Client} = do_retrieve_access_token(Client0, Options),
      {ok, Client};
    {true, false} ->
      Key = hash_client(Client0),
      case oauth2c_token_cache:get(Key) of
        {error, not_found} ->
          RevalidateFun = retrieve_access_token_fun(Client0, Options),
          oauth2c_token_cache:set_and_get(Key, RevalidateFun);
        {ok, Client} ->
          {ok, Client}
      end;
    {true, true} ->
      Key = hash_client(Client0),
      RevalidateFun = retrieve_access_token_fun(Client0, Options),
      oauth2c_token_cache:set_and_get(Key, RevalidateFun, ExpiresIn)
  end.

hash_client(#client{grant_type = Type,
                    auth_url = AuthUrl,
                    id = ID,
                    secret = Secret,
                    scope = Scope}) ->
  erlang:phash2({Type, AuthUrl, ID, Secret, Scope}).

%%%_ * Tests -------------------------------------------------------

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 2
%%% End:
