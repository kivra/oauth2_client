%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @doc OAuth2 Authentication Token Cache - This gen_server implements a
%%% simple caching mechanism for authentication tokens.
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(oauth2c_token_cache).
-behaviour(gen_server).

%%%_* Exports ==========================================================

-export([start/0]).
-export([start/1]).
-export([start_link/0]).
-export([start_link/1]).
-export([get/1]).
-export([set_and_get/2]).
-export([set_and_get/3]).

%% gen_server
-export([init/1]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([clear/0]).

%%%_* Macros =========================================================

-define(DEFAULT_TTL, 300). % Default cache entry TTL in seconds.
-define(SERVER, ?MODULE).
-define(TOKEN_CACHE_ID, token_cache_id).

%%%_* Code =============================================================
%%%_ * Types -----------------------------------------------------------
%%%_ * API -------------------------------------------------------------

-spec start() -> {atom(), pid()}.
start() ->
  start(?DEFAULT_TTL).
-spec start(non_neg_integer()) -> {atom(), pid()}.
start(DefaultTTL) ->
  gen_server:start({local, ?SERVER}, ?SERVER,
                   #{default_ttl => DefaultTTL}, []).

-spec start_link() -> {atom(), pid()}.
start_link() ->
  start_link(?DEFAULT_TTL).
-spec start_link(non_neg_integer()) -> {atom(), pid()}.
start_link(DefaultTTL) ->
  gen_server:start_link({local, ?SERVER}, ?SERVER,
                        #{default_ttl => DefaultTTL}, []).

-spec get(integer()) -> {error, atom()} | {ok, term()}.
get(Key) ->
  get_token(Key).

-spec set_and_get(Key, LazyValue) -> Value | Error when
    Key :: integer(),
    LazyValue :: fun(() -> Value | Error),
    Value :: {ok, term()},
    Error :: {error, binary()}.
set_and_get(Key, LazyValue) ->
  set_and_get(Key, LazyValue, undefined).

-spec set_and_get(Key, LazyValue, CurrenTokenExpiryTime) -> Value | Error when
    Key :: integer(),
    LazyValue :: fun(() -> Value | Error),
    CurrenTokenExpiryTime :: integer() | undefined,
    Value :: {ok,  term()},
    Error :: {error, atom()}.
set_and_get(Key, LazyValue, CurrenTokenExpiryTime) ->
  gen_server:call(?SERVER, {set_and_get,
                            Key,
                            LazyValue,
                            CurrenTokenExpiryTime}).

-spec clear() -> true.
clear() ->
  ets:delete_all_objects(?TOKEN_CACHE_ID).

%%%_ * gen_server callbacks --------------------------------------------

init(State) ->
  EtsOpts = [set, public, named_table, {read_concurrency, true}],
  ets:new(?TOKEN_CACHE_ID, EtsOpts),
  {ok, State}.

handle_call({set_and_get, Key, LazyValue,
            CurrenTokenExpiryTime}, _From,
            State = #{default_ttl := DefaultTTL}) ->
  % CurrenTokenExpiryTime is used to solve a race-condition
  % that occurs when multiple processes are trying to
  % replace an old token (i.e. the new token has a larger
  % expiry time than the old token).
  case get_token(Key, CurrenTokenExpiryTime) of
    {ok, Result} ->
      {reply, {ok, Result}, State};
    {error, not_found} ->
      case LazyValue() of
        {ok, Result, ExpireTime} ->
          ExpiryTime = get_expire_time(ExpireTime, DefaultTTL),
          ets:insert(?TOKEN_CACHE_ID, {Key, Result, ExpiryTime}),
          {reply, {ok, Result}, State};
        {error, Reason} -> {reply, {error, Reason}, State}
      end
  end.

handle_cast(_, State) -> {noreply, State}.

%%%_ * Private functions -----------------------------------------------

get_token(Key) ->
  get_token(Key, undefined).
get_token(Key, ExpiryTimeLowerLimit) ->
  Now = erlang:system_time(second),
  case ets:lookup(?TOKEN_CACHE_ID, Key) of
    % Only return cache entry if
    % (1) It has not expired
    % (2) Its expiry time is greater than ExpiryTimeLowerLimit
    [{Key, Result, ExpiryTime}] when ExpiryTime > Now
                                     andalso
                                     (ExpiryTimeLowerLimit =:= undefined
                                      orelse
                                      ExpiryTime > ExpiryTimeLowerLimit) ->
      {ok, Result};
    _ ->
      {error, not_found}
  end.

get_expire_time(undefined, DefaultTTL) ->
  erlang:system_time(second) + DefaultTTL;
get_expire_time(ExpireTime, _DefaultTTL) ->
  ExpireTime.

%%%_ * Tests -------------------------------------------------------

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

get_expires_in_test_() ->
  [fun() ->
       {T, Default} = Input,
       Actual = get_expire_time(T, Default),
       ?assertEqual(Expected, Actual)
   end
   || {Input, Expected} <- [{{1, 100}, 1}]
  ].

-endif.
