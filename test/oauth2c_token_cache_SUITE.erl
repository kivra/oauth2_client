-module(oauth2c_token_cache_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").
-include("oauth2c.hrl").


all() -> [ get_valid_token
         , get_expired_token
         , set_and_get_token
         , delete_token
         , delete_token_invalid_ttl
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
  Client = #client{expiry_time = erlang:system_time(second) + 100},
  LazyToken =
    fun() -> {ok, header, Client} end,
  oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  ?assertMatch([{header, Client}], oauth2c_token_cache:get(?FUNCTION_NAME)).

set_and_get_token({init, Config}) -> Config;
set_and_get_token({'end', Config}) ->
  oauth2c_token_cache:clear(),
  Config;
set_and_get_token(_Config) ->
  Client = #client{expiry_time = erlang:system_time(second) + 100},
  LazyToken =
    fun() -> {ok, header, Client} end,
  Res1 = oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  Res2 = oauth2c_token_cache:get(?FUNCTION_NAME),
  [
    ?assertMatch({ok, header, Client}, Res1),
    ?assertMatch([{header, Client}], Res2)
  ].


get_expired_token({init, Config}) -> Config;
get_expired_token({'end', Config}) ->
  oauth2c_token_cache:clear(),
  Config;
get_expired_token(_Config) ->
  Client = #client{expiry_time = erlang:system_time(second) - 100},
  LazyToken =
    fun() -> {ok, header, Client} end,
  oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  Res = oauth2c_token_cache:get(?FUNCTION_NAME),
  ?assertMatch([], Res).

delete_token({init, Config}) -> Config;
delete_token({'end', Config}) ->
  oauth2c_token_cache:clear(),
  Config;
delete_token(_Config) ->
  TTL = erlang:system_time(second) + 100,
  Client = #client{expiry_time = TTL},
  LazyToken =
    fun() -> {ok, header, Client} end,
  Res1 = oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  oauth2c_token_cache:delete_token(?FUNCTION_NAME, TTL),
  Res2 = oauth2c_token_cache:get(?FUNCTION_NAME),
  [
    ?assertMatch({ok, header, Client}, Res1),
    ?assertMatch([], Res2)
  ].

delete_token_invalid_ttl({init, Config}) -> Config;
delete_token_invalid_ttl({'end', Config}) ->
  oauth2c_token_cache:clear(),
  Config;
delete_token_invalid_ttl(_Config) ->
  TTL = erlang:system_time(second) + 100,
  Client = #client{expiry_time = TTL},
  LazyToken =
    fun() -> {ok, header, Client} end,
  Res1 = oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  oauth2c_token_cache:delete_token(?FUNCTION_NAME, TTL + 1),
  Res2 = oauth2c_token_cache:get(?FUNCTION_NAME),
  [
    ?assertMatch({ok, header, Client}, Res1),
    ?assertMatch([{header, Client}], Res2)
  ].

