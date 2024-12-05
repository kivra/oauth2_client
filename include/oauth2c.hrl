-record(service_account,
    { private_key :: binary()
    , project_id  :: binary()
    , iss         :: binary()
    , aud         :: binary()
    }).

-record(client, {grant_type    = undefined :: binary()     | undefined,
                 auth_url      = undefined :: binary()     | undefined,
                 access_token  = undefined :: binary()     | undefined,
                 token_type    = undefined :: token_type() | undefined,
                 refresh_token = undefined :: binary()     | undefined,
                 id            = undefined :: binary()     | undefined,
                 secret        = undefined :: binary()     | undefined,
                 service       = undefined :: #service_account{} | undefined,
                 scope         = undefined :: binary()     | undefined,
                 expire_time   = undefined :: integer()    | undefined
                }).

-type method()         :: head    |
                          get     |
                          put     |
                          patch   |
                          post    |
                          trace   |
                          options |
                          delete.
-type url()            :: binary().
%% <<"password">> or <<"client_credentials">>
-type at_type()        :: binary().
-type headers()        :: restc:headers().
-type header()         :: restc:header().
-type status_codes()   :: [status_code()].
-type status_code()    :: integer().
-type reason()         :: term().
-type content_type()   :: json | xml | percent.
-type property()       :: atom() | tuple().
-type proplist()       :: [property()].
-type options()        :: proplist().
-type body()           :: restc:body().
-type response()       :: {restc:response(), #client{}}.
-type token_type()     :: bearer | unsupported.
-type client()         :: #client{}.
