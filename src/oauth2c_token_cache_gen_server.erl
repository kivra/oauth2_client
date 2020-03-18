%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @doc OAuth2 Authentication Token Cache - This gen_server implements a
%%% simple caching mechanism for authentication tokens.
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(oauth2c_token_cache_gen_server).
-behaviour(gen_server).

%%%_* Exports ==========================================================
%%%_ * API -------------------------------------------------------------
-export([start/0]).
-export([start/1]).
-export([stop/0]).
-export([get/1]).
-export([insert/2]).
-export([delete/1]).

%% gen_server
-export([init/1]).
-export([terminate/2]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).
-export([code_change/3]).

%%%_* Includes =========================================================
%%%_* Code =============================================================
%%%_ * Types -----------------------------------------------------------
%%%_ * API -------------------------------------------------------------

start() -> start(#{cache_ttl => 3600000, cache => #{}}).
start(State) -> gen_server:start_link({local, ?MODULE}, ?MODULE, State, []).
stop() -> gen_server:cast(?MODULE, stop).
get(Key) -> gen_server:call(?MODULE, {get, Key}).
insert(Key, Value) -> gen_server:cast(?MODULE, {insert, {Key, Value}}).
delete(Key) -> gen_server:cast(?MODULE, {delete, Key}).

%%%_ * gen_server callbacks --------------------------------------------

init(State) ->
  {ok, State}.

handle_call({get, Key}, _From, State = #{cache := Cache, cache_ttl := TTL}) ->
  case get_token(Cache, Key, TTL, os:system_time()) of
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

handle_cast(stop, State) ->
  {stop, normal, ok, State};

handle_cast(_Msg, State) ->
  {noreply, State}.

handle_info(_Info, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%_ * Private functions -----------------------------------------------

update_cache(Cache, Key, Value) ->
  Cache#{Key => {Value, os:system_time()}}.

get_token(Cache, Key, TTL, Now) ->
  case maps:is_key(Key, Cache) of
    true -> get_token_if_not_expired(maps:get(Key, Cache), TTL, Now);
    false -> not_found
  end.

% Token exist and is valid.
get_token_if_not_expired({Token, CreatedAt}, TTL, Now)
  when (Now - CreatedAt) < TTL ->
  {ok, Token};
% Token exist but has expired.
get_token_if_not_expired(_Value, _TTL, _Now) ->
  token_expired.

%%%_ * Tests -------------------------------------------------------

-endif.