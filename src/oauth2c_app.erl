%%%-------------------------------------------------------------------
%% @doc oauth2c application callback
%% @end
%%%-------------------------------------------------------------------

-module(oauth2c_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
  oauth2c_sup:start_link().

stop(_State) ->
  ok.
