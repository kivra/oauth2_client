ELVIS_IN_PATH := $(shell elvis --version 2> /dev/null)
ELVIS_LOCAL := $(shell .elvis/_build/default/bin/elvis --version 2> /dev/null)

all: compile

compile:
	rebar3 compile

clean:
	rebar3 clean

eunit:
	rebar3 eunit

ct:
	rebar3 ct -v

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

elvis:
ifdef ELVIS_IN_PATH
	elvis git-branch origin/HEAD -V
else ifdef ELVIS_LOCAL
	.elvis/_build/default/bin/elvis git-branch origin/HEAD -V
else
	$(MAKE) compile_elvis
	.elvis/_build/default/bin/elvis git-branch origin/HEAD -V
endif

elvis_rock:
ifdef ELVIS_IN_PATH
	elvis rock
else ifdef ELVIS_LOCAL
	.elvis/_build/default/bin/elvis rock
else
	$(MAKE) compile_elvis
	.elvis/_build/default/bin/elvis rock
endif

compile_elvis:
	git clone https://github.com/inaka/elvis.git .elvis && \
	cd .elvis && \
	rebar3 compile && \
	rebar3 escriptize && \
	cd ..
