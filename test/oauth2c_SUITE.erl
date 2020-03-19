-module(oauth2c_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-define(AUTH_URL, <<"https://authurl.com">>).
-define(INVALID_TOKEN_AUTH_URL, <<"https://invalidauthurl.com">>).
-define(REQUEST_URL, <<"https://requesturl.com">>).
-define(CLIENT_CREDENTIALS_GRANT, <<"client_credentials">>).
-define(VALID_TOKEN, <<"iamanaccesstoken">>).
-define(HEADERS(AccessToken),
        [{<<"Authorization">>, <<"bearer ", AccessToken/binary>>}]).

-define(GET_BODY, [{<<"a">>, <<"b">>}]).

groups() -> [].

all() -> [ retrieve_access_token
         , retrieve_cached_access_token
         , retrieve_cached_expired_access_token
         , fetch_access_token_on_request
         , fetch_access_token_on_request
         , fetch_new_token_on_401
         ].

init_per_suite(Config) -> 
  {ok, _Pid} = oauth2c_token_cache:start(),
  Config.
end_per_suite(_Config) -> ok.

init_per_testcase(_TestCase, Config) ->
  mock_http_requests(),
  Config.
end_per_testcase(_TestCase, Config) ->
  meck:unload([restc]),
  oauth2c_token_cache:clear(),
  Config.

retrieve_access_token(_Config) ->
  Response = oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                           ?AUTH_URL,
                                           <<"ID">>,
                                           <<"SECRET">>),
  ?assertMatch({ok, _, _}, Response).

retrieve_cached_access_token(_Config) ->
  oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                           ?AUTH_URL,
                                           <<"ID">>,
                                           <<"SECRET">>),
  oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                           ?AUTH_URL,
                                           <<"ID">>,
                                           <<"SECRET">>),
  ?assertEqual(1, meck:num_calls(restc, request,
                                [ post, percent,
                                  ?AUTH_URL, '_', '_', '_', '_'
                                ])).

retrieve_cached_expired_access_token(_Config) ->
    oauth2c_token_cache:set_ttl(100),
    oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                           ?AUTH_URL,
                                           <<"ID">>,
                                           <<"SECRET">>),
  timer:sleep(200),
  oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                           ?AUTH_URL,
                                           <<"ID">>,
                                           <<"SECRET">>),
  ?assertEqual(2, meck:num_calls(restc, request,
                                [ post, percent,
                                  ?AUTH_URL, '_', '_', '_', '_'
                                ])),
    oauth2c_token_cache:set_ttl(3.6e6).

fetch_access_token_and_do_request(_Config) ->
  {ok, _, Client} = oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                                  ?AUTH_URL,
                                                  <<"ID">>,
                                                  <<"SECRET">>),
  Response = oauth2c:request(get, json, ?REQUEST_URL, [], [], [], [], Client),
  ?assertMatch({{ok, 200, _, ?GET_BODY}, Client}, Response),
  ?assertNot(meck:called(restc, request,
                         [post, percent, ?AUTH_URL, '_', '_', '_', '_'])).


fetch_access_token_on_request(_Config) ->
  Client = oauth2c:client(?CLIENT_CREDENTIALS_GRANT, ?AUTH_URL, <<"ID">>,
                          <<"SECRET">>),
  Response = oauth2c:request(get, json, ?REQUEST_URL, [], [], [], [], Client),
  ?assertMatch({{ok, 200, _, ?GET_BODY}, _}, Response),
  ?assert(meck:called(restc, request,
                      [post, percent, ?AUTH_URL, '_', '_', '_', '_'])).

fetch_new_token_on_401(_Config) ->
  {ok, _, Client} = oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                                  ?INVALID_TOKEN_AUTH_URL,
                                                  <<"ID">>,
                                                  <<"SECRET">>),
  ?assert(1 =:= meck:num_calls(restc, request,
                               [ post, percent,
                                 ?INVALID_TOKEN_AUTH_URL, '_', '_', '_', '_'
                               ])),

  Response = oauth2c:request(get, json, ?REQUEST_URL, [], [], [], [], Client),
  ?assertMatch({{ok, 401, _, _}, Client}, Response),
  ?assert(2 =:= meck:num_calls(restc, request,
                               [ post, percent,
                                 ?INVALID_TOKEN_AUTH_URL, '_', '_', '_', '_'
                               ])).

mock_http_requests() ->
  meck:expect(restc, request,
              fun(post, percent, ?AUTH_URL, [200], _, _, _) ->
                  Body = [{<<"access_token">>, ?VALID_TOKEN},
                          {<<"token_type">>, <<"bearer">>}],
                  {ok, 200, [], Body};
                 (post, percent, ?INVALID_TOKEN_AUTH_URL, [200], _, _, _) ->
                  Body = [{<<"access_token">>, <<"invalid">>},
                          {<<"token_type">>, <<"bearer">>}],
                  {ok, 200, [], Body};
                 (get, json, _, _, Headers, _, _) ->
                  ValidToken = ?HEADERS(?VALID_TOKEN),
                  case Headers of
                    ValidToken -> {ok, 200, [], [{<<"a">>, <<"b">>}]};
                    _ -> {ok, 401, [], []}
                  end
              end).

%_* Editor ===================================================================
% Local Variables:
% allout-layout: t
% erlang-indent-level: 2
% End:
