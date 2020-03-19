-module(oauth2c_token_cache_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").


all() -> [
  get_token,
  get_expired_token,
  insert_token,
  delete_token
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

get_token({init, _Config}) ->
  oauth2c_token_cache:insert(?FUNCTION_NAME, token);
get_token({'end', _Config}) ->
  oauth2c_token_cache:delete(?FUNCTION_NAME);
get_token(_Config) ->
  Res = oauth2c_token_cache:get(?FUNCTION_NAME),
  ?assertMatch({ok, token}, Res).

get_expired_token({init, _Config}) ->
  oauth2c_token_cache:set_ttl(100),
  oauth2c_token_cache:insert(?FUNCTION_NAME, token);
get_expired_token({'end', _Config}) ->
  oauth2c_token_cache:set_ttl(3.6e6),
  oauth2c_token_cache:delete(?FUNCTION_NAME);
get_expired_token(_Config) ->
  % Trying to fetch an expired token should return not found.
  timer:sleep(100),
  Res = oauth2c_token_cache:get(?FUNCTION_NAME),
  ?assertMatch(not_found, Res).

insert_token({init, _Config}) -> ok;
insert_token({'end', _Config}) ->
  oauth2c_token_cache:delete(?FUNCTION_NAME);
insert_token(_Config) ->
  Res1 = oauth2c_token_cache:get(?FUNCTION_NAME),
  oauth2c_token_cache:insert(?FUNCTION_NAME, token),
  Res2 = oauth2c_token_cache:get(?FUNCTION_NAME),
  ?assertMatch(not_found, Res1),
  ?assertMatch({ok, token}, Res2).

delete_token({init, _Config}) ->
    oauth2c_token_cache:insert(?FUNCTION_NAME, token);
delete_token({'end', _Config}) -> ok;
delete_token(_Config) ->
  Res1 = oauth2c_token_cache:get(?FUNCTION_NAME),
  oauth2c_token_cache:delete(?FUNCTION_NAME),
  Res2 = oauth2c_token_cache:get(?FUNCTION_NAME),
  ?assertMatch({ok, token}, Res1),
  ?assertMatch(not_found, Res2).
