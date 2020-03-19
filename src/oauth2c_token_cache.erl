%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @doc OAuth2 Authentication Token Cache - This gen_server implements a
%%% simple caching mechanism for authentication tokens.
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(oauth2c_token_cache).
-behaviour(gen_server).

%%%_* Exports ==========================================================
%%%_ * API -------------------------------------------------------------

-export([start/0]).
-export([start/1]).
-export([start_link/0]).
-export([start_link/1]).
-export([get/1]).
-export([insert/2]).
-export([delete/1]).
-export([set_ttl/1]).
-export([clear/0]).

%% gen_server
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).

%%%_* Includes =========================================================
%%%_* Code =============================================================
%%%_ * Types -----------------------------------------------------------
%%%_ * API -------------------------------------------------------------

start() -> start(#{cache_ttl => 3600000, cache => #{}}).
start(State) -> gen_server:start({local, ?MODULE}, ?MODULE, State, []).

start_link() -> start_link(#{cache_ttl => 3600000, cache => #{}}).
start_link(State) -> gen_server:start_link({local, ?MODULE}, ?MODULE, State, []).

get(Key) -> gen_server:call(?MODULE, {get, Key}).
insert(Key, Value) -> gen_server:cast(?MODULE, {insert, {Key, Value}}).
delete(Key) -> gen_server:cast(?MODULE, {delete, Key}).
set_ttl(NewTTL) -> gen_server:cast(?MODULE, {set_ttl, NewTTL}).
clear() -> gen_server:cast(?MODULE, clear).

%%%_ * gen_server callbacks --------------------------------------------

init(State) ->
  {ok, State}.

handle_call({get, Key}, _From, State = #{cache := Cache, cache_ttl := TTL}) ->
  case get_token(Cache, Key, TTL, os:system_time(millisecond)) of
    {ok, Token} ->
      {reply, {ok, Token}, State};
    token_expired ->
      {reply, not_found, State#{cache := maps:remove(Key, Cache)}};
    not_found ->
      {reply, not_found, State}
  end.

handle_cast({insert, {Key, Value}}, State = #{cache := Cache}) ->
  NewCache = update_cache(Cache, Key, Value),
  {noreply, State#{cache := NewCache}};

handle_cast({delete, Key}, State = #{cache := Cache}) ->
  {noreply, State#{cache := maps:without([Key], Cache)}};

handle_cast({set_ttl, NewTTL}, State) ->
  {noreply, State#{cache_ttl := NewTTL}};

handle_cast(clear, State) ->
  {noreply, State#{cache := #{}}}.

%%%_ * Private functions -----------------------------------------------

update_cache(Cache, Key, Value) ->
  Cache#{Key => {Value, os:system_time(millisecond)}}.

get_token(Cache, Key, TTL, Now) ->
  case maps:is_key(Key, Cache) of
    true -> get_token_if_not_expired(maps:get(Key, Cache), TTL, Now);
    false -> not_found
  end.

get_token_if_not_expired({Token, CreatedAt}, TTL, Now)
  when (Now - CreatedAt) < TTL ->
  {ok, Token};
get_token_if_not_expired(_Value, _TTL, _Now) ->
  token_expired.

%%%_ * Tests -------------------------------------------------------

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

get_token_test_() ->
  [
    fun() ->
      {Cache, Key, TTL, Now} = Input,
      Actual = get_token(Cache, Key, TTL, Now),
      ?assertEqual(Expected, Actual)
    end
  ||
    {Input, Expected} <-[
      {{#{}, key, 0, 0}, not_found},
      {{#{key => {token, 0}}, other_key, 100, 100}, not_found},
      {{#{key => {token, 0}}, key, 100, 100}, token_expired},
      {{#{key => {token, 0}}, key, 101, 100}, {ok, token}}
    ]
  ].

  update_cache_test_() ->
  [
    fun() ->
      {Cache, Key, Value} = Input,
      Actual = update_cache(Cache, Key, Value),
      % Check that each cache entry contains a timestamp
      maps:fold(
        fun(_, {V, Timestamp}, ok) ->
          ?assert(is_atom(V)),
          ?assert(is_integer(Timestamp))
        end, ok, Actual),
      % Check that cache contains the expected values,´
      ?assertEqual(Expected,
        lists:map(fun({V, _}) -> V end, maps:values(Actual)))
    end
  ||
    {Input, Expected} <-[
      {{#{}, k1, v1}, [v1]},
      {{#{k1 => {v1, 0}}, k2, v2}, [v1, v2]}
    ]
  ].

-endif.