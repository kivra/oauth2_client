%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 Client
%%
%% Copyright (c) 2012 KIVRA
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

-export([
         retrieve_access_token/4, retrieve_access_token/5
         ,request/3
         ,request/4
         ,request/5
         ,request/6
         ,request/7
        ]).

-type method()       :: head | get | put | post | trace | options | delete.
-type url()          :: binary().
-type at_type()      :: binary(). %% <<"password">> or <<"client_credentials">>
-type headers()      :: [header()].
-type header()       :: {binary(), binary()}.
-type status_codes() :: [status_code()].
-type status_code()  :: integer().
-type reason()       :: term().
-type content_type() :: json | xml | percent.
-type property()     :: atom() | tuple().
-type proplist()     :: [property()].
-type body()         :: proplist().
-type response()     :: {ok, Status::status_code(), Headers::headers(), Body::body()} |
                        {error, Status::status_code(), Headers::headers(), Body::body()} |
                        {error, Reason::reason()}.


-define(DEFAULT_ENCODING, json).

-record(client, {
        grant_type    = undefined :: binary(),
        auth_url      = undefined :: binary(),
        access_token  = undefined :: binary(),
        refresh_token = undefined :: binary(),
        id            = undefined :: binary(),
        secret        = undefined :: binary(),
        scope         = undefined :: binary()
}).


%%% API ========================================================================


-spec retrieve_access_token(Type, URL, ID, Secret) ->
    {ok, Headers::headers(), #client{}} | {error, Reason :: binary()} when
    Type   :: at_type(),
    URL    :: url(),
    ID     :: binary(),
    Secret :: binary().
retrieve_access_token(Type, Url, ID, Secret) ->
    retrieve_access_token(Type, Url, ID, Secret, undefined).

-spec retrieve_access_token(Type, URL, ID, Secret, Scope) ->
    {ok, Headers::headers(), #client{}} | {error, Reason :: binary()} when
    Type   :: at_type(),
    URL    :: url(),
    ID     :: binary(),
    Secret :: binary(),
    Scope  :: binary() | undefined.
retrieve_access_token(Type, Url, ID, Secret, Scope) ->
    Client = #client{
                     grant_type = Type
                     ,auth_url  = Url
                     ,id        = ID
                     ,secret    = Secret
                     ,scope     = Scope
                    },
    do_retrieve_access_token(Client).

-spec request(Method, Url, Client) -> Response::response() when
    Method :: method(),
    Url    :: url(),
    Client :: #client{}.
request(Method, Url, Client) ->
    request(Method, ?DEFAULT_ENCODING, Url, [], [], [], Client).

-spec request(Method, Url, Expect, Client) -> Response::response() when
    Method :: method(),
    Url    :: url(),
    Expect :: status_codes(),
    Client :: #client{}.
request(Method, Url, Expect, Client) ->
    request(Method, ?DEFAULT_ENCODING, Url, Expect, [], [], Client).

-spec request(Method, Type, Url, Expect, Client) -> Response::response() when
    Method :: method(),
    Type   :: content_type(),
    Url    :: url(),
    Expect :: status_codes(),
    Client :: #client{}.
request(Method, Type, Url, Expect, Client) ->
    request(Method, Type, Url, Expect, [], [], Client).

-spec request(Method, Type, Url, Expect, Headers, Client) -> Response::response() when
    Method  :: method(),
    Type    :: content_type(),
    Url     :: url(),
    Expect  :: status_codes(),
    Headers :: headers(),
    Client  :: #client{}.
request(Method, Type, Url, Expect, Headers, Client) ->
    request(Method, Type, Url, Expect, Headers, [], Client).

-spec request(Method, Type, Url, Expect, Headers, Body, Client) -> Response::response() when
    Method  :: method(),
    Type    :: content_type(),
    Url     :: url(),
    Expect  :: status_codes(),
    Headers :: headers(),
    Body    :: body(),
    Client  :: #client{}.
request(Method, Type, Url, Expect, Headers, Body, Client) ->
    case do_request(Method, Type, Url, Expect, Headers, Body, Client) of
        {{_, 401, _, _}, Client2} ->
            {ok, _RetrHeaders, Client3} = do_retrieve_access_token(Client2),
            do_request(Method, Type, Url, Expect, Headers, Body, Client3);
        Result -> Result
    end.


%%% INTERNAL ===================================================================


do_retrieve_access_token(#client{grant_type = <<"password">>} = Client) ->
    Payload0 = [
                {<<"grant_type">>, Client#client.grant_type}
                ,{<<"username">>, Client#client.id}
                ,{<<"password">>, Client#client.secret}
               ],
    Payload = case Client#client.scope of
                 undefined -> Payload0;
                 Scope -> [{<<"scope">>, Scope}|Payload0]
              end,
    case restc:request(post, percent, binary_to_list(Client#client.auth_url), [200], [], Payload) of
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
                                 id = Id, secret = Secret} = Client) ->
    Payload0 = [{<<"grant_type">>, Client#client.grant_type}],
    Payload = case Client#client.scope of
                  undefined ->
                      Payload0;
                  Scope ->
                      [{<<"scope">>, Scope}|Payload0]
              end,
    Auth = base64:encode(<<Id/binary, ":", Secret/binary>>),
    Header = [{"Authorization", binary_to_list(<<"Basic ", Auth/binary>>)}],
    case restc:request(post, percent, binary_to_list(Client#client.auth_url),
                       [200], Header, Payload) of
        {ok, _, Headers, Body} ->
            AccessToken = proplists:get_value(<<"access_token">>, Body),
            Result = #client{
                             grant_type    = Client#client.grant_type
                             ,auth_url     = Client#client.auth_url
                             ,access_token = AccessToken
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

do_request(Method, Type, Url, Expect, Headers, Body, Client) ->
    Headers2 = add_auth_header(Headers, Client),
    {restc:request(Method, Type, binary_to_list(Url), Expect, Headers2, Body), Client}.

add_auth_header(Headers, #client{access_token = AccessToken}) ->
    AH = {"Authorization", binary_to_list(<<"token ", AccessToken/binary>>)},
    [AH | proplists:delete("Authorization", Headers)].
