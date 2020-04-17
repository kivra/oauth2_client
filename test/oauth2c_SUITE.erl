-module(oauth2c_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("oauth2c.hrl").

-define(AUTH_URL, <<"https://authurl.com">>).
-define(INVALID_TOKEN_AUTH_URL, <<"https://invalidauthurl.com">>).
-define(REQUEST_URL, <<"https://requesturl.com">>).
-define(REQUEST_URL_401, <<"https://requesturl401.com">>).
-define(CLIENT_CREDENTIALS_GRANT, <<"client_credentials">>).
-define(VALID_TOKEN, <<"iamanaccesstoken">>).
-define(HEADERS(AccessToken),
        [{<<"Authorization">>, <<"bearer ", AccessToken/binary>>}]).

-define(GET_BODY, [{<<"a">>, <<"b">>}]).

groups() -> [].

all() -> [ client_credentials_in_body
         , client_credentials_in_header
         , retrieve_access_token
         , fetch_access_token_on_request
         , fetch_access_token_on_request
         , fetch_new_token_on_401
         , retrieve_cached_access_token
         , retrieve_cached_expired_access_token
         , retrieve_cached_token_burst
         , retrieve_cached_token_burst_with_expire
         , retrieve_cached_token_on_401
         , retrieve_cached_token_on_401_burst
         ].

init_per_suite(Config) ->
  {ok, Pid} = oauth2c_token_cache:start(1),
  [{pid, Pid}|Config].
end_per_suite(Config) ->
  {pid, Pid} = proplists:lookup(pid, Config),
  exit(Pid, shutdown),
  ok.

init_per_testcase(retrieve_cached_token_on_401_burst, Config) ->
  mock_http_request_401_burst(),
  Config;
init_per_testcase(retrieve_cached_token_on_401, Config) ->
  mock_http_request_401(),
  Config;
init_per_testcase(_TestCase, Config) ->
  mock_http_requests(),
  Config.
end_per_testcase(_TestCase, Config) ->
  meck:unload([restc]),
  oauth2c_token_cache:clear(),
  Config.

client_credentials_in_body(_Config) ->
  oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                               ?AUTH_URL,
                               <<"ID">>,
                               <<"SECRET">>,
                               undefined,
                               [credentials_in_body]),
  ?assert(meck:called(restc, request, [post,
                                       percent,
                                       ?AUTH_URL,
                                       '_',
                                       [], %% empty headers
                                       ['_', '_', '_'], %% grant_type + creds
                                       '_'])).

client_credentials_in_header(_Config) ->
  oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                ?AUTH_URL,
                                <<"ID">>,
                                <<"SECRET">>),
  ?assert(meck:called(restc, request, [post,
                                       percent,
                                       ?AUTH_URL,
                                       '_',
                                       ['_'], %% credentials
                                       ['_'], %% grant_type
                                       '_'])).

retrieve_access_token(_Config) ->
  Response = oauth2c:retrieve_access_token(?CLIENT_CREDENTIALS_GRANT,
                                           ?AUTH_URL,
                                           <<"ID">>,
                                           <<"SECRET">>),
  ?assertMatch({ok, _, _}, Response).

retrieve_cached_access_token(_Config) ->
  Client = client(?AUTH_URL),
  oauth2c:request(get, json, ?REQUEST_URL, [], [], [], [cache_token], Client),
  oauth2c:request(get, json, ?REQUEST_URL, [], [], [], [cache_token], Client),
  ?assertEqual(1, meck:num_calls(restc, request,
                                [ post, percent,
                                  ?AUTH_URL, '_', '_', '_', '_'
                                ])).

retrieve_cached_expired_access_token(_Config) ->
  Client = client(?AUTH_URL),
  oauth2c:request(get, json, ?REQUEST_URL, [], [], [], [cache_token], Client),
  % TTL is 1000ms for a cached entry, hence sleeping for 1050ms should
  % make the cached entry invalid.
  timer:sleep(1050),
  oauth2c:request(get, json, ?REQUEST_URL, [], [], [], [cache_token], Client),
  ?assertEqual(2, meck:num_calls(restc, request,
                                [ post, percent,
                                  ?AUTH_URL, '_', '_', '_', '_'
                                ])).

retrieve_cached_token_burst(_Config) ->
  % The cache server should be able to handle multiple concurrent requests
  % and only perform a single token request.
  Client0 = client(?AUTH_URL),
  N = 1000,
  Fun = fun() ->
          oauth2c:request(get, json, ?REQUEST_URL, [], [], [],
                          [cache_token], Client0)
        end,
  process_flag(trap_exit, true),
  [spawn_link(Fun) || _ <- lists:seq(1, N)],
  [receive {'EXIT', _, _} -> ok end || _ <- lists:seq(1, N)],
  ?assertEqual(1, meck:num_calls(restc, request,
                                [ post, percent,
                                  ?AUTH_URL, '_', '_', '_', '_'
                                ])).

retrieve_cached_token_burst_with_expire(_Config) ->
  Client0 = client(?AUTH_URL),
  N = 1000,
  Fun =
  fun(M) ->
    fun() ->
        case M > 50 of
          true ->
            % Force oauth2c:request to look inside of the cache
            Client = Client0#client{access_token = undefined},
            oauth2c:request(get, json, ?REQUEST_URL, [], [], [],
                           [cache_token], Client);
          _ ->
            oauth2c:request(get, json, ?REQUEST_URL, [], [], [],
                           [cache_token], Client0)
        end
      end
    end,
  process_flag(trap_exit, true),
  [case Num of
    51 -> timer:sleep(1050), spawn_link(Fun(Num));
    _ -> spawn_link(Fun(Num))
    end || Num <- lists:seq(1, N)],
  [receive {'EXIT', _, _} -> ok end || _ <- lists:seq(1, N - 1)],
  ?assertEqual(2, meck:num_calls(restc, request,
                                [ post, percent,
                                  ?AUTH_URL, '_', '_', '_', '_'
                                ])).

retrieve_cached_token_on_401(_Config) ->
  Client0 = client(?AUTH_URL),
  Response1 = oauth2c:request(get, json,
    ?REQUEST_URL, [], [], [], [cache_token], Client0),
  ?assertMatch({{ok, 200, _, _}, _}, Response1),
  {_, Client1} = Response1,
  % Second call to request will return 401 and
  % an automatic refresh av token should be triggered
  Response2 = oauth2c:request(get, json,
    ?REQUEST_URL, [], [], [], [cache_token], Client1),
  ?assertMatch({{ok, 401, _, _}, _}, Response2),
  ?assertEqual(2, meck:num_calls(restc, request,
                              [ post, percent,
                                ?AUTH_URL, '_', '_', '_', '_'
                              ])),
  ?assertMatch({{ok, 200, _, _}, _}, Response1),
  {_, Client1} = Response1,
  {_, Client2} = Response2,
  ?assert(Client1#client.expire_time < Client2#client.expire_time).

retrieve_cached_token_on_401_burst(_Config) ->
  Client = client(?AUTH_URL),
  % First call to request will return a access token with expires_in X,
  % and this token will be cached.
  {{ok, 200, _, _}, Client1} = oauth2c:request(get, json,
          ?REQUEST_URL, [], [], [], [cache_token], Client),
  N = 10,

  % Subsequent calls to request will fail with 401, and
  % the access token will automatically be refreshed by all N
  % processes concurrently. However, only 1 of the N processes
  % should request a new access token and the other N - 1 should
  % use the token fetched by the one process.
  Fun = fun() ->
          {{ok, 401, _, _}, _} = oauth2c:request(get, json,
          ?REQUEST_URL, [], [], [], [cache_token], Client1)
        end,
  process_flag(trap_exit, true),
  [spawn_link(Fun) || _ <- lists:seq(1, N)],
  [receive {'EXIT', _, _} -> ok end || _ <- lists:seq(1, N - 1)],
  ?assertEqual(2, meck:num_calls(restc, request,
                            [ post, percent,
                              ?AUTH_URL, '_', '_', '_', '_'
                            ])),
  ?assertEqual(N * 2 + 1, meck:num_calls(restc, request,
                          [ get, json,
                            ?REQUEST_URL, '_', '_', '_', '_'
                          ])),
  % Perform a final call to request to get back the currently cached
  % token and make sure that it has indeed been updated by 1 of the N
  % processes,
  {{ok, 401, _, _}, Client2} = oauth2c:request(get, json,
    ?REQUEST_URL, [], [], [], [cache_token], Client1),
  ?assert(Client1#client.expire_time < Client2#client.expire_time).

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
                          {<<"expires_in">>, 1},
                          {<<"token_type">>, <<"bearer">>}],
                  {ok, 200, [], Body};
                 (post, percent, ?INVALID_TOKEN_AUTH_URL, [200], _, _, _) ->
                  Body = [{<<"access_token">>, <<"invalid">>},
                          {<<"token_type">>, <<"bearer">>}],
                  {ok, 200, [], Body};
                 (get, json, ?REQUEST_URL_401, _, _, _, _) ->
                  {ok, 401, [], []};
                 (get, json, _, _, Headers, _, _) ->
                  ValidToken = ?HEADERS(?VALID_TOKEN),
                  case Headers of
                    ValidToken -> {ok, 200, [], [{<<"a">>, <<"b">>}]};
                    _ -> {ok, 401, [], []}
                  end
              end).

mock_http_request_401() ->
  meck:expect(restc, request,
    [
      {[post, percent, ?AUTH_URL, [200], '_', '_', '_'],
        meck:seq([
          {ok, 200, [], [{<<"access_token">>, <<"token1">>},
                          {<<"expires_in">>, 1},
                          {<<"token_type">>, <<"bearer">>}]},
          {ok, 200, [], [{<<"access_token">>, <<"token2">>},
                          {<<"expires_in">>, 10},
                          {<<"token_type">>, <<"bearer">>}]}
        ])
      },
      {[get, json, ?REQUEST_URL, '_', '_', '_', '_'],
        meck:seq([
          {ok, 200, [], [{<<"access_token">>, <<"invalid">>},
                        {<<"token_type">>, <<"bearer">>}]},
          {ok, 401, [], [{<<"access_token">>, ?VALID_TOKEN},
                        {<<"expires_in">>, 1},
                        {<<"token_type">>, <<"bearer">>}]}
        ])
      }
    ]
  ).

mock_http_request_401_burst() ->
  meck:expect(restc, request,
    [
      {[post, percent, ?AUTH_URL, [200], '_', '_', '_'],
        meck:seq([
          {ok, 200, [], [{<<"access_token">>, ?VALID_TOKEN},
                          {<<"expires_in">>, 10},
                          {<<"token_type">>, <<"bearer">>}]},
          {ok, 200, [], [{<<"access_token">>, ?VALID_TOKEN},
                          {<<"expires_in">>, 20},
                          {<<"token_type">>, <<"bearer">>}]}
        ])
      },
      {[get, json, ?REQUEST_URL, '_', '_', '_', '_'],
        meck:seq([
            {ok, 200, [], []},
            {ok, 401, [], []}
        ])
      }
    ]
  ).



client(Url) ->
oauth2c:client( <<"client_credentials">>
              , Url
              , <<"client_id">>
              , <<"client_secret">>).

%_* Editor ===================================================================
% Local Variables:
% allout-layout: t
% erlang-indent-level: 2
% End:
