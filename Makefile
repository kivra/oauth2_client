REBAR=rebar
DEPS_PLT=$(CURDIR)/.deps_plt
DEPS=erts kernel crypto stdlib inets crypto asn1 public_key ssl

all: deps compile

deps: get-deps compile-all

get-deps:
	$(REBAR) get-deps

compile-all:
	$(REBAR) compile

compile:
	$(REBAR) skip_deps=true compile
	$(REBAR) skip_deps=true xref

clean:
	$(REBAR) clean

$(DEPS_PLT):
	@echo Building local plt at $(DEPS_PLT)
	@echo
	dialyzer --output_plt $(DEPS_PLT) --build_plt --apps $(DEPS) -r deps

dialyzer: $(DEPS_PLT) compile
	dialyzer --fullpath --plt $(DEPS_PLT) -Wrace_conditions -r ./ebin

shell:
	erl -pa deps/erlsom/ebin \
            -pa deps/jsx/ebin \
            -pa deps/mochiweb_util/ebin \
            -pa deps/restc/ebin \
	    -pa ebin
