%% Copyright (c) 2011 Hunter Morris
%% Distributed under the MIT license; see LICENSE for details.
-module(bcrypt).
-author('Richard Jonas <mail@jonasrichard.hu>').

%% API
-export([gen_salt/0, gen_salt/1, hashpw/2]).

-define(ROUND, 12).

gen_salt() ->
    gen_salt(?ROUND).

gen_salt(Rounds) ->
    bcrypt_nif:gen_salt(Rounds).

hashpw(Password, Salt) ->
    bcrypt_nif:hashpw(Password, Salt).
