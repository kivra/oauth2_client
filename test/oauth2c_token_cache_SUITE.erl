-module(oauth2c_token_cache_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").


all() -> [ get_valid_token
         , get_expired_token
         , set_and_get_token
].

init_per_suite(Config) ->
  {ok, Pid} = oauth2c_token_cache:start(),
  [{pid, Pid}|Config].

end_per_suite(Config) ->
  {pid, Pid} = proplists:lookup(pid, Config),
  exit(Pid, shutdown),
  ok.

init_per_testcase(TestCase, Config) ->
  ?MODULE:TestCase({init, Config}),
  Config.

end_per_testcase(TestCase, Config) ->
  ?MODULE:TestCase({'end', Config}),
  Config.

set_and_get_token({init, _Config}) -> ok;
set_and_get_token({'end', _Config}) ->
  oauth2c_token_cache:clear();
set_and_get_token(_Config) ->
  LazyToken =
    fun() -> {ok, header, result, erlang:system_time(second) + 100} end,
  Res1 = oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken),
  Res2 = oauth2c_token_cache:get(?FUNCTION_NAME),
  [
    ?assertMatch({ok, header, result}, Res1),
    ?assertMatch([{header, result}], Res2)
  ].

get_valid_token({init, _Config}) ->
  LazyToken =
    fun() -> {ok, header, result, erlang:system_time(second) + 100} end,
  oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken);
get_valid_token({'end', _Config}) ->
  oauth2c_token_cache:clear();
get_valid_token(_Config) ->
  Res = oauth2c_token_cache:get(?FUNCTION_NAME),
  ?assertMatch([{header, result}], Res).

get_expired_token({init, _Config}) ->
  LazyToken =
    fun() -> {ok, header, result, erlang:system_time(second) - 100} end,
  oauth2c_token_cache:set_and_get(?FUNCTION_NAME, LazyToken);
get_expired_token({'end', _Config}) ->
  oauth2c_token_cache:clear();
get_expired_token(_Config) ->
  Res = oauth2c_token_cache:get(?FUNCTION_NAME),
  ?assertMatch([], Res).
