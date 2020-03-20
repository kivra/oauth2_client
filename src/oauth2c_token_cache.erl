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
-export([insert/3]).
-export([delete/1]).
-export([set_default_ttl/1]).
-export([clear/0]).

%% gen_server
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).

-define(DEFAULT_TTL, 3600). % Default cache entry TTL in seconds.

%%%_* Includes =========================================================
%%%_* Code =============================================================
%%%_ * Types -----------------------------------------------------------
%%%_ * API -------------------------------------------------------------

start() -> start(#{default_cache_ttl => ?DEFAULT_TTL, cache => #{}}).
start(State) ->
  gen_server:start({local, ?MODULE}, ?MODULE, State, []).

start_link() -> start_link(#{default_cache_ttl => ?DEFAULT_TTL, cache => #{}}).
start_link(State) ->
  gen_server:start_link({local, ?MODULE}, ?MODULE, State, []).

get(Key) -> gen_server:call(?MODULE, {get, Key}).

insert(Key, Value) ->
  gen_server:cast(?MODULE, {insert, {Key, Value}, undefined}).
insert(Key, Value, ExpireTime) ->
  gen_server:cast(?MODULE, {insert, {Key, Value}, ExpireTime}).

delete(Key) -> gen_server:cast(?MODULE, {delete, Key}).

set_default_ttl(NewTTL) -> gen_server:cast(?MODULE, {set_default_ttl, NewTTL}).

clear() -> gen_server:cast(?MODULE, clear).

%%%_ * gen_server callbacks --------------------------------------------

init(State) ->
  {ok, State}.

handle_call({get, Key}, _From, State = #{cache := Cache}) ->
  case get_token(Cache, Key, os:system_time(second)) of
    {ok, Token} ->
      {reply, {ok, Token}, State};
    token_expired ->
      {reply, not_found, State#{cache := maps:remove(Key, Cache)}};
    not_found ->
      {reply, not_found, State}
  end.

handle_cast({insert, {Key, Value}, undefined},
  State = #{cache := Cache, default_cache_ttl := TTL}) ->
  NewCache = Cache#{Key => {Value, os:system_time(second) + TTL}},
  {noreply, State#{cache := NewCache}};
handle_cast({insert, {Key, Value}, ExpireTime}, State = #{cache := Cache}) ->
  NewCache = Cache#{Key => {Value, ExpireTime}},
  {noreply, State#{cache := NewCache}};

handle_cast({delete, Key}, State = #{cache := Cache}) ->
  {noreply, State#{cache := maps:remove(Key, Cache)}};

handle_cast({set_default_ttl, NewTTL}, State) ->
  {noreply, State#{default_cache_ttl := NewTTL}};

handle_cast(clear, State) ->
  {noreply, State#{cache := #{}}}.

%%%_ * Private functions -----------------------------------------------

%update_cache(Cache, Key, Value, ExpireTime) ->
%  Cache#{Key => {Value, os:system_time(second)}}.

get_token(Cache, Key, Now) ->
  case maps:is_key(Key, Cache) of
    true -> get_token_if_not_expired(maps:get(Key, Cache), Now);
    false -> not_found
  end.

get_token_if_not_expired({Token, ExpireTime}, Now)
  when ExpireTime > Now ->
  {ok, Token};
get_token_if_not_expired(_Value, _Now) ->
  token_expired.

%%%_ * Tests -------------------------------------------------------

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

get_token_test_() ->
  [
    fun() ->
      {Cache, Key, Now} = Input,
      Actual = get_token(Cache, Key, Now),
      ?assertEqual(Expected, Actual)
    end
  ||
    {Input, Expected} <-[
      {{#{}, key, 0}, not_found},
      {{#{key => {token, 0}}, other_key, 100}, not_found},
      {{#{key => {token, 99}}, key, 100}, token_expired},
      {{#{key => {token, 101}}, key, 100}, {ok, token}}
    ]
  ].

%  update_cache_test_() ->
%  [
%    fun() ->
%      {Cache, Key, Value} = Input,
%      Actual = update_cache(Cache, Key, Value),
%      % Check that each cache entry contains a timestamp
%      maps:fold(
%        fun(_, {V, Timestamp}, ok) ->
%          ?assert(is_atom(V)),
%          ?assert(is_integer(Timestamp))
%        end, ok, Actual),
%      % Check that cache contains the expected values,´
%      ?assertEqual(Expected,
%        lists:map(fun({V, _}) -> V end, maps:values(Actual)))
%    end
%  ||
%    {Input, Expected} <-[
%      {{#{}, k1, v1}, [v1]},
%      {{#{k1 => {v1, 0}}, k2, v2}, [v1, v2]}
%    ]
%  ].

-endif.
