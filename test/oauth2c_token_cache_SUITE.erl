-module(oauth2c_token_cache_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

all() -> [ get_valid_token
         , get_expired_token
         , set_and_get_token
         , overwrite_and_get_token
].

init_per_suite(Config) ->
  {ok, Pid} = oauth2c_token_cache:start(),
  [{pid, Pid}|Config].

end_per_suite(Config) ->
  {pid, Pid} = proplists:lookup(pid, Config),
  exit(Pid, shutdown),
  ok.

init_per_testcase(TestCase, Config) ->
  ?MODULE:TestCase({init, Config}).

end_per_testcase(TestCase, Config) ->
  ?MODULE:TestCase({'end', Config}).

get_valid_token({init, Config}) ->
  Config;
get_valid_token({'end', Config}) ->
  oauth2c_token_cache:clear(),
  Config;
get_valid_token(_Config) ->
  ExpiryTime =  erlang:system_time(second) + 100,
  Client = client,
  LazyToken =
    fun() -> {ok, Client, ExpiryTime} end,
  oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  ?assertMatch({ok, Client}, oauth2c_token_cache:get(?FUNCTION_NAME)).

set_and_get_token({init, Config}) -> Config;
set_and_get_token({'end', Config}) ->
  oauth2c_token_cache:clear(),
  Config;
set_and_get_token(_Config) ->
  ExpiryTime =  erlang:system_time(second) + 100,
  Client = client,
  LazyToken =
    fun() -> {ok, Client, ExpiryTime} end,
  Res1 = oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  Res2 = oauth2c_token_cache:get(?FUNCTION_NAME),
  [
    ?assertMatch({ok, Client}, Res1),
    ?assertMatch({ok, Client}, Res2)
  ].

overwrite_and_get_token({init, Config}) -> Config;
overwrite_and_get_token({'end', Config}) ->
  oauth2c_token_cache:clear(),
  Config;
overwrite_and_get_token(_Config) ->
  ExpiryTime1 = erlang:system_time(second) + 10,
  ExpiryTime2 = erlang:system_time(second) + 20,
  Client1 = client1,
  Client2 = client2,
  Client3 = client3,
  LazyToken1 =
    fun() -> {ok, Client1, ExpiryTime1} end,
  LazyToken2 =
    fun() -> {ok, Client2, ExpiryTime1} end,
  LazyToken3 =
    fun() -> {ok, Client3, ExpiryTime2} end,

  Res1 = oauth2c_token_cache:set_and_get(?FUNCTION_NAME,
                                        LazyToken1),
  Res2 = oauth2c_token_cache:set_and_get(?FUNCTION_NAME,
                                        LazyToken2),
  Res3 = oauth2c_token_cache:set_and_get(?FUNCTION_NAME,
                                        LazyToken3, ExpiryTime2),
  [
    ?assertMatch({ok, Client1}, Res1),
    ?assertMatch({ok, Client1}, Res2),
    ?assertMatch({ok, Client3}, Res3)
  ].

get_expired_token({init, Config}) -> Config;
get_expired_token({'end', Config}) ->
  oauth2c_token_cache:clear(),
  Config;
get_expired_token(_Config) ->
  ExpiryTime =  erlang:system_time(second) - 100,
  Client = client,
  LazyToken =
    fun() -> {ok, Client, ExpiryTime} end,
  oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  Res = oauth2c_token_cache:get(?FUNCTION_NAME),
  ?assertMatch({error, not_found}, Res).
