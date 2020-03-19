-module(oauth2c_token_cache_sup_SUITE).
-compile([export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").


all() -> [
  test_sup
].

init_per_suite(Config) -> Config.
end_per_suite(_Config) -> ok.

init_per_testcase(_TestCase, _Config) -> _Config.
end_per_testcase(_TestCase, _Config) -> _Config.

test_sup(_Config) ->
  ?assertEqual(undefined, whereis(oauth2c_token_cache_sup)),
  {ok, SupPid} = oauth2c_token_cache_sup:start_link(),
  ?assertEqual(true, is_process_alive(whereis(oauth2c_token_cache))),
	process_flag(trap_exit, true),
  exit(SupPid, shutdown),
  receive 
		{'EXIT', _, shutdown} -> 
      ?assertEqual(undefined, whereis(oauth2c_token_cache))
  end.
  

