#!/usr/bin/env escript
%%
%%!

-mode(compile).

-define(TIMEOUT, 60000).
-record(cli, {
  user_addr,
  private_key_path,
  remote_spec,
  l_conn,
  l_chan,
  r_conn,
  r_chan
}).

% key_cb callbacks
-export([user_key/2, is_auth_key/3, is_host_key/4, add_host_key/3, host_key/2]).


-export([init/1, handle_ssh_msg/2, handle_msg/2, terminate/2]).

main(Args) ->
  Opts = parse_args(Args, #{
    server_dir => "priv/server",
    port => 2022,
    private_key_path => "priv/auth",
    user_keys => "priv/users"
  }),
  crypto:start(),
  ssh:start(),
  error_logger:tty(true),
  ServerDir = maps:get(server_dir, Opts),
  Port = maps:get(port, Opts),
  Options = [
    {auth_methods,"publickey"},
    {system_dir, ServerDir},
    {key_cb, {?MODULE, [Opts]}},
    {ssh_cli, {?MODULE, [Opts]}},
    {connectfun, fun on_connect/3},
    {disconnectfun, fun on_disconnect/1},
    {ssh_msg_debug_fun, fun(A,B,C,D) -> io:format("~p ~p ~p ~p\n",[A,B,C,D]) end}
  ],
  {ok, Daemon} = ssh:daemon(any, Port, Options),
  {ok, Info} = ssh:daemon_info(Daemon),
  io:format("Listening on port ~p\n", [proplists:get_value(port, Info)]),
  receive
    _ -> ok
  end.



parse_args([], Opts) ->
  Opts;
parse_args(["-h"|_], _) ->
  io:format(
"    -i private_ssh_dir      - directory with id_rsa key, used for authentication. By default priv/auth\n"
"    -u users_keys_directory - directory with user keys, used for authentication. By default priv/users\n"
"    -t private_daemon_dir   - private daemon dir with his host key. By default priv/server\n"
"    -p port                 - port to listen. By default 2022\n"
),
  init:stop(2);
parse_args(["-i", PrivateKey|Args], Opts) ->
  parse_args(Args, Opts#{private_key_path => PrivateKey});
parse_args(["-u", UsersKeysDir|Args], Opts) ->
  parse_args(Args, Opts#{user_keys => UsersKeysDir});
parse_args(["-t", TempDir|Args], Opts) ->
  parse_args(Args, Opts#{server_dir => TempDir});
parse_args(["-p", Port|Args], Opts) ->
  parse_args(Args, Opts#{port => list_to_integer(Port)});
parse_args([Opt|_], _Opts) ->
  io:format("Unknown key: ~s\n", [Opt]),
  init:stop(3).




is_auth_key(PublicKey,Username,Opts0) ->
  try is_auth_key0(PublicKey,Username,Opts0)
  catch
    C:E ->
      ST = erlang:get_stacktrace(),
      io:format("~p:~p in\n~p\n", [C,E,ST]),
      false
  end.


is_auth_key0(PublicKey,Username,Opts0) ->
  [#{} = Opts] = proplists:get_value(key_cb_private, Opts0),
  SshKey = (catch public_key:ssh_encode(PublicKey,ssh2_pubkey)),
  UsersKeysDir = maps:get(user_keys, Opts),
  KeyPaths = filelib:wildcard(UsersKeysDir++"/*"),
  % io:format("key paths: ~p\n", [KeyPaths]),
  case search_key(SshKey, KeyPaths) of
    {ok, Name} ->
      case get(client_public_key_name) of
        undefined ->
          io:format("User ~s logged in to ~s in ~p\n", [Name, Username, self()]),
          put(client_public_key_name, Name),
          put(client_public_key, PublicKey);
        _ ->
          ok
      end,
      true;
    undefined ->
      io:format("Unknown attemp to login to ~s\n", [Username]),
      false
  end.


search_key(_, []) ->
  undefined;

search_key(SshKey, [Path|List]) ->
  case file:read_file(Path) of
    {error, _} ->
      io:format("Unreadable key file ~s\n", [Path]),
      search_key(SshKey, List);
    {ok, Text} ->
      case binary:split(Text, <<" ">>, [global]) of
        [<<"ssh-",_/binary>>, Key64 |_] ->
          case base64:decode(Key64) of
            SshKey -> {ok, filename:basename(Path)};
            _ -> search_key(SshKey, List)
          end;
        _ ->
          io:format("Unvalid key file ~s\n", [Path]),
          search_key(SshKey, List)
      end
  end.

user_key(A,B) ->
  io:format("user_key: ~p ~p\n",[A,B]),
  {ok,crypto:strong_rand_bytes(16)}.


add_host_key(A,B,C) ->
  io:format("add_host_key: ~p ~p ~p\n",[A,B,C]),
  ok.

is_host_key(A,B,C,D) ->
  io:format("is_host_key: ~p ~p ~p ~p\n",[A,B,C,D]),
  true.

host_key(Algo,Opts) ->
  try ssh_file:host_key(Algo, Opts) of
    {ok, Bin} ->
      % error_logger:info_msg("~s host_key requested\n",[Algo]),
      {ok, Bin};
    {error, E} ->
      % error_logger:info_msg("~s host_key error: ~p\n",[Algo, E]),
      {error, E}
  catch
    C:E ->
      error_logger:info_msg("~s host_key ~p: ~p\n~p",[Algo, C, E, erlang:get_stacktrace()]),
      {error, E}
  end.



on_connect(_Username,_B,_C) ->
  % io:format("~p on_connect: ~p ~p ~p\n",[self(), Username,B,C]),
  ok.

on_disconnect(_A) ->
  % io:format("~p on_disconnect: ~p\n",[self(), A]),
  ok.





init([#{} = Opts]) ->
  % io:format("INIT: ~p\n", [_Args]),
  PrivateKeyPath = maps:get(private_key_path, Opts),
  {ok, #cli{private_key_path = PrivateKeyPath}}.



handle_ssh_msg({ssh_cm, Conn, Msg}, #cli{} = State) ->
  % io:format("sshmsg(~p,~p,~p) ~300p\n",[Conn, State#cli.l_conn, State#cli.r_conn, Msg]),
  handle_ssh_msg2({ssh_cm, Conn, Msg}, State).


handle_msg(Msg, #cli{} = State) ->
  handle_msg2(Msg, State).






handle_ssh_msg2({ssh_cm, Conn, {data, _, Type, Data}}, #cli{r_conn = Conn, l_conn = Local, l_chan = LocChan} = State) ->
  ssh_connection:send(Local, LocChan, Type, Data, ?TIMEOUT),
  {ok, State};

handle_ssh_msg2({ssh_cm, _, {data, _, Type, Data}}, #cli{r_conn = Conn, r_chan = ChannelId} = State) ->
  ssh_connection:send(Conn, ChannelId, Type, Data, ?TIMEOUT),
  {ok, State};

handle_ssh_msg2({ssh_cm, Conn, {eof,_}}, #cli{r_conn = Conn, l_conn = Local, l_chan = LocChan} = State) ->
  ssh_connection:send_eof(Local, LocChan),
  {ok, State};

handle_ssh_msg2({ssh_cm, Conn, {exit_status,_,Status}}, #cli{r_conn = Conn, l_conn = Local, l_chan = LocChan} = State) ->
  ssh_connection:exit_status(Local, LocChan, Status),
  {ok, State};

handle_ssh_msg2({ssh_cm, Conn, {closed, _ChannelId}}, #cli{r_conn = Conn, l_chan = LocChan} = State) ->
  {stop, LocChan, State};

handle_ssh_msg2({ssh_cm, Conn, Msg}, #cli{r_conn = Conn} = State) ->
  io:format("REM2 ~p\n",[Msg]),
  {ok, State};


handle_ssh_msg2({ssh_cm, _, {pty, _Chan, _, Request}}, #cli{r_conn = Conn, r_chan = ChannelId} = State) ->
  {TermName, Width, Height, PixWidth, PixHeight, Modes} = Request,
  PtyOptions = [{term,TermName},{width,Width},{height,Height},
    {pixel_width,PixWidth},{pixel_height,PixHeight},{pty_opts,Modes}],
  ssh_connection:ptty_alloc(Conn, ChannelId, PtyOptions, ?TIMEOUT),
  {ok, State};

handle_ssh_msg2({ssh_cm, _, {env, _Chan, _, Var, Value}}, #cli{r_conn = Conn, r_chan = ChannelId} = State) ->
  ssh_connection:setenv(Conn, ChannelId, binary_to_list(Var), binary_to_list(Value), ?TIMEOUT),
  {ok, State};

handle_ssh_msg2({ssh_cm, Local, {shell,_LocChan,_}}, #cli{l_conn = Local, r_conn = Conn, r_chan = ChannelId} = State) ->
  ssh_connection:shell(Conn, ChannelId),
  {ok, State};

handle_ssh_msg2({ssh_cm, Local, {exec,_LocChan,_,Command}}, #cli{l_conn = Local, r_conn = Conn, r_chan = ChannelId} = State) ->
  ssh_connection:exec(Conn, ChannelId, Command, ?TIMEOUT),
  {ok, State};

handle_ssh_msg2({ssh_cm, Local, {eof,_LocChan}}, #cli{l_conn = Local, r_conn = Conn, r_chan = ChannelId} = State) ->
  ssh_connection:send_eof(Conn, ChannelId),
  {ok, State};

handle_ssh_msg2({ssh_cm, Local, Msg}, #cli{l_conn = Local} = State) ->
  io:format("LOC ~p\n",[Msg]),
  {ok, State};

handle_ssh_msg2(Msg, State) ->
  io:format("Unknown ~p\n",[Msg]),
  {ok, State}.






handle_msg2({ssh_channel_up,LocChan,Local}, #cli{private_key_path = PrivateKeyPath} = State) ->
  Dict = ssh:connection_info(Local,[user,peer]),
  RemoteSpec = proplists:get_value(user,Dict),
  [User,Host, Port] = case string:tokens(RemoteSpec, [$/]) of
    [User_,Host_, Port_] -> 
      [User_,Host_, list_to_integer(Port_)];
    [_] -> 
      ["root", RemoteSpec, 22];
    [User_,Host_] ->
      try list_to_integer(Host_) of
        Port_ -> ["root", User_, Port_]
      catch
        _:_ -> [User_,Host_, 22]
      end
  end,
  % io:format("~p Open proxy to ~s@~s\n", [self(), User,Host]),
  case ssh:connect(Host, Port, [{user,User},{user_dir,PrivateKeyPath},{silently_accept_hosts, true},{quiet_mode, true}]) of
    {ok, Conn} ->
      {ok, ChannelId} = ssh_connection:session_channel(Conn, ?TIMEOUT),
      {ok, State#cli{r_conn = Conn, r_chan = ChannelId, l_conn = Local, l_chan = LocChan}};
    {error, Error} ->
      ssh_connection:send(Local, LocChan, 1, [Error,"\n"]),
      {stop, LocChan, State}
  end;


handle_msg2(Msg, #cli{} = State) ->
  io:format("Msg ~p ~p\n",[Msg,State]),
  {ok, State}.

terminate(_,_) -> ok.




