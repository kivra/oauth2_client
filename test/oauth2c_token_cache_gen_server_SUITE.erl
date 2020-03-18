-module(oauth2c_token_cache_gen_server_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").


all() -> [
  get_token,
  insert_token,
  delete_token
].

init_per_suite(Config) -> Config.
end_per_suite(_Config) -> ok.

init_per_testcase(_TestCase, Config) ->
  Now = os:system_time(millisecond),
  TTL = 3.6e6,
  InitialState = #{cache =>
    #{key1 => {token1, Now}, key2 => {token2, Now - TTL}}, cache_ttl => TTL},
  oauth2c_token_cache_gen_server:start(InitialState),
  Config.
end_per_testcase(_TestCase, Config) ->
  oauth2c_token_cache_gen_server:stop(),
  Config.

get_token(_Config) ->
  Res1 = oauth2c_token_cache_gen_server:get(key1),
  Res2 = oauth2c_token_cache_gen_server:get(key2),
  Res3 = oauth2c_token_cache_gen_server:get(bad_key),
  ?assertMatch({ok, token1}, Res1),
  % Should not be found since token has expired
  ?assertEqual(not_found, Res2),
  ?assertEqual(not_found, Res3).

insert_token(_Config) ->
  oauth2c_token_cache_gen_server:insert(key3, token3),
  Res = oauth2c_token_cache_gen_server:get(key3),
  ?assertMatch({ok, token3}, Res).

delete_token(_Config) ->
  oauth2c_token_cache_gen_server:delete(key1),
  Res = oauth2c_token_cache_gen_server:get(key1),
  ?assertEqual(not_found, Res).