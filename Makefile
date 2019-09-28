all: compile

compile:
	rebar3 compile

clean:
	rebar3 clean

xref:
	rebar3 xref

dialyze:
	rebar3 dialyzer

upgrade:
	rebar3 upgrade

unlock:
	rebar3 unlock

lock:
	rebar3 lock
