#!/usr/bin/env escript
%%
%%!

-mode(compile).
-include_lib("eldap/include/eldap.hrl").


-define(TIMEOUT, 60000).
-record(cli, {
  user_addr,
  private_key_path,
  remote_spec,
  l_conn,
  l_chan,
  r_conn,
  r_chan,
  f_chan
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
  case Opts of
    #{ldap := Ldap} ->
      {ok,_} = application:ensure_all_started(ssl),
      {ok,_} = application:ensure_all_started(eldap),
      case ldap_fetch_keys(Ldap) of
        {ok, _} ->
          io:format("Ldap server is functioning\n");
        {error, LdapError} ->
          io:format("Ldap server is configured but not working: ~p\n",[LdapError])
      end;
    _ ->
      ok
  end,

  Options = [
    {auth_methods,"publickey"},
    {password, "defaultpassword"},
    % {user_interaction,false},
    % {io_cb, ssh_no_io},
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
"    -c config_file          - config file in erlang format\n"
"    -l ldaps://password@server:port/bind-dn/base - ldap search for ssh keys\n"
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
parse_args(["-l", Ldap|Args], Opts) ->
  case parse_ldap(Ldap) of
    #{} ->
      parse_args(Args, Opts#{ldap => Ldap});
    _ ->
      io:format("Error reading ldap address: ~s\n",[Ldap]),
      init:stop(5)
  end;
parse_args(["-c", ConfigFile|Args], Opts) ->
  case file:consult(ConfigFile) of
    {ok, Env} ->
      parse_args(Args, maps:merge(Opts, maps:from_list(Env)));
    {error, E} ->
      io:format("Error reading config file ~s: ~p\n",[ConfigFile, E]),
      init:stop(4)
  end;
parse_args([Opt|_], _Opts) ->
  io:format("Unknown key: ~s\n", [Opt]),
  init:stop(3).



parse_ldap(URL) ->
  case http_uri:parse(URL) of
    {ok, {Proto,Password,Server,Port,Path,_Query}} when Proto == ldap orelse Proto == ldaps ->
      case string:tokens(Path,"/") of
        [BindDn, Base] ->
          SSL = Proto == ldaps,
          #{ssl => SSL, password => Password, host => Server, port => Port, bind_dn => BindDn, base => Base};
        _ ->
          {error, invalid_path}
      end;
    _ ->
      {error, invalid_url}
  end.


ldap_fetch_keys(URL) ->
  #{host := Host, port := Port, ssl := SSL, bind_dn := BindDn, password := Password, base := Base} = parse_ldap(URL),
  case eldap:open([Host], [{port,Port},{ssl,SSL}]) of
    {ok,Handle} ->
      eldap:simple_bind(Handle,BindDn,Password),

      Filter = eldap:'and'([
        eldap:present("ipaSshPubKey"),
        eldap:present("uid")
      ]),
      case eldap:search(Handle,[{base,Base},{filter,Filter},{attributes,["ipaSshPubKey","uid"]}]) of
        {error, FetchError} ->
          {error, FetchError};
        {ok, Reply} ->
          eldap:close(Handle),
          #eldap_search_result{entries = Entries} = Reply,
          Keys = lists:flatmap(fun(#eldap_entry{attributes = A}) ->
            SshKeys = [_|_] = proplists:get_value("ipaSshPubKey", A),
            [Uid] = proplists:get_value("uid",A),
            lists:flatmap(fun(SshKey) ->
              case binary:split(iolist_to_binary(SshKey),<<" ">>, [global]) of
                [<<"ssh-",_/binary>>, Key64 |_] ->
                  [{iolist_to_binary(Key64),iolist_to_binary(Uid)}];
                _ ->
                  []
              end
            end, SshKeys)
          end, Entries),
          {ok, maps:from_list(Keys)}
      end;
    {error, ConnectError} ->
      {error, ConnectError}
  end.
  


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
  Ldap = maps:get(ldap, Opts, undefined),
  case search_key_on_disk_or_ldap(SshKey, KeyPaths, Ldap) of
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
      io:format("Unknown attemp to login to ~s with key: ~s\n", [Username, base64:encode(SshKey)]),
      false
  end.


search_key_on_disk_or_ldap(SshKey, KeyPaths, Ldap) ->
  case search_key(SshKey, KeyPaths) of
    undefined when Ldap =/= undefined ->
      search_key_in_ldap(SshKey, Ldap);
    {ok, Name} ->
      {ok, Name}
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



search_key_in_ldap(SshKey, Ldap) ->
  case ldap_fetch_keys(Ldap) of
    {ok, Keys} ->
      case maps:get(base64:encode(SshKey), Keys, undefined) of
        undefined ->
          io:format("Lookup '~p' in\n~p\n\n",[base64:encode(SshKey),Keys]),
          undefined;
        Name ->
          {ok, Name}
      end;
    {error, _} ->
      undefined
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

handle_ssh_msg2({ssh_cm, _, {data, _, Type, Data}}, #cli{r_conn = Conn, r_chan = ChannelId, f_chan = undefined} = State) ->
  ssh_connection:send(Conn, ChannelId, Type, Data, ?TIMEOUT),
  {ok, State};

handle_ssh_msg2({ssh_cm, _, {data, _, Type, Data}}, #cli{r_conn = Conn, f_chan = ChannelId} = State) ->
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
  % Strange workaround
  FilteredModes = lists:flatmap(fun
    ({41,V}) -> [{imaxbel,V}];
    ({K,V}) when is_atom(K) -> [{K,V}];
    (_) -> []
  end, Modes),
  PtyOptions = [{term,TermName},{width,Width},{height,Height},
    {pixel_width,PixWidth},{pixel_height,PixHeight},{pty_opts,FilteredModes}],
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






handle_msg2({ssh_channel_up, LocChan, Local}, #cli{private_key_path = PrivateKeyPath} = State) ->
  {[User, Host, Port], SshForward} = parse_proxy_request(Local),
  % io:format("~p Open proxy to ~s@~s\n", [self(), User,Host]),
  case 
    ssh:connect(Host, Port, [
      {user, User}, 
      {user_dir, PrivateKeyPath},
      {silently_accept_hosts, true},
      {user_interaction, false},
      {quiet_mode, true}
    ])
  of
    {ok, Conn} ->
      {ok, ChannelId} = ssh_connection:session_channel(Conn, ?TIMEOUT),
      case SshForward of
        undefined ->
          {ok, State#cli{r_conn = Conn, r_chan = ChannelId, l_conn = Local, l_chan = LocChan}};
        [ForwardHost, ForwardPort] ->
          {open, ForwardChannel} = direct_tcpip(Conn, 
            {<<"127.0.0.1">>, ForwardPort}, 
            {ForwardHost, ForwardPort}
          ),
          {ok, State#cli{r_conn = Conn, r_chan = ChannelId, f_chan = ForwardChannel, l_conn = Local, l_chan = LocChan}}
      end;
    {error, Error} ->
      ssh_connection:send(Local, LocChan, 1, [Error,"\n"]),
      {stop, LocChan, State}
  end;


handle_msg2(Msg, #cli{} = State) ->
  io:format("Msg ~p ~p\n",[Msg,State]),
  {ok, State}.

terminate(_,_) -> ok.


%%
%%
parse_proxy_request(SshConnection) ->
  Request = proplists:get_value(user, 
    ssh:connection_info(SshConnection, [user, peer])
  ),
  [SshHost | SshForward] = string:tokens(Request, [$~]),
  {parse_user_host_port(SshHost), parse_host_port(SshForward)}.

parse_host_port([]) ->
  undefined;
parse_host_port([Spec]) ->
  [Host, Port] = string:tokens(Spec, [$/]),
  [erlang:list_to_binary(Host), list_to_integer(Port)].

parse_user_host_port(Spec) ->
  case string:tokens(Spec, [$/]) of
    [User, Host, Port] -> 
      [User, Host, list_to_integer(Port)];
    [Host] -> 
      ["root", Host, 22];
    [User, Host] ->
      try list_to_integer(Host) of
        Port -> ["root", User, Port]
      catch
        _:_ -> [User, Host, 22]
      end
  end.

%%
%%
direct_tcpip(Conn, From, To) ->
  {OrigHost, OrigPort} = From,
  {RemoteHost, RemotePort} = To,

  RemoteLen = byte_size(RemoteHost),
  OrigLen = byte_size(OrigHost),

  Msg = <<
    RemoteLen:32,
    RemoteHost/binary,
    RemotePort:32,
    OrigLen:32,
    OrigHost/binary,
    OrigPort:32
  >>,

  ssh_connection_handler:open_channel(
    Conn,
    "direct-tcpip",
    Msg,
    1024 * 1024,
    32 * 1024,
    infinity
  ).
