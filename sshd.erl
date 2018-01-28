#!/usr/bin/env escript
%%
%%!

-mode(compile).

-define(TIMEOUT, 60000).

% key_cb callbacks
-export([user_key/2, is_auth_key/3, is_host_key/4, add_host_key/3, host_key/2]).


-export([init/1, handle_ssh_msg/2, handle_msg/2, terminate/2]).

main([]) ->
  crypto:start(),
  ssh:start(),
  error_logger:tty(true),
  Port = 2022,
  Options = [
    {auth_methods,"publickey"},
    {system_dir, "tmp"},
    {key_cb, ?MODULE},
    {ssh_cli, {?MODULE, []}},
    {connectfun, fun on_connect/3},
    {disconnectfun, fun on_disconnect/1},
    {ssh_msg_debug_fun, fun(A,B,C,D) -> io:format("~p ~p ~p ~p\n",[A,B,C,D]) end}
  ],
  {ok, Daemon} = ssh:daemon(any, Port, Options),
  {ok, Info} = ssh:daemon_info(Daemon),
  error_logger:info_msg("hi: ~p\n",[Info]),
  receive
    _ -> ok
  end.


is_auth_key(PublicKey,Username,_Opts) ->
  io:format("is_auth_key: ~s ~p\n",[element(1,PublicKey),Username]),
  io:format("PUB: ~p\n", [catch public_key:ssh_encode(PublicKey,ssh2_pubkey)]),
  true.


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



on_connect(Username,_B,_C) ->
  % io:format("~p on_connect: ~p ~p ~p\n",[self(), Username,B,C]),
  put(requested_hostname, Username),
  ok.

on_disconnect(_A) ->
  % io:format("~p on_disconnect: ~p\n",[self(), A]),
  ok.


% ssh_cli
% init(Args) ->
%   io:format("init ~p\n",[Args]),
%   {ok, State} = ssh_cli:init([proplists:get_value(shell,Args,{shell,start,[]})]),
%   {ok, State}.

% handle_ssh_msg(Msg, State) ->
%   io:format("IN ~p\n",[Msg]),
%   case ssh_cli:handle_ssh_msg(Msg, State) of
%     {ok, State1} ->
%       {ok, State1};
%     {stop, ChannelId, State1} ->
%       {stop, ChannelId, State1}
%   end.


% handle_msg(Msg, State) ->
%   io:format("IN2 ~p\n",[Msg]),
%   case ssh_cli:handle_msg(Msg, State) of
%     {ok, State1} ->
%       {ok, State1};
%     {stop, ChannelId, State1} ->
%       {stop, ChannelId, State1}
%   end.

% terminate(_,_) ->
%   ok.



init(_) ->
  {ok, #{}}.




handle_ssh_msg({ssh_cm, Conn, {data, _, Type, Data}}, #{conn := Conn, local_conn := Local, local_chan := LocChan} = State) ->
  ssh_connection:send(Local, LocChan, Type, Data, ?TIMEOUT),
  {ok, State};

handle_ssh_msg({ssh_cm, _, {data, _, Type, Data}}, #{conn := Conn, channel := ChannelId} = State) ->
  ssh_connection:send(Conn, ChannelId, Type, Data, ?TIMEOUT),
  {ok, State};

handle_ssh_msg({ssh_cm, Conn, {eof,_}}, #{conn := Conn, local_conn := Local, local_chan := LocChan} = State) ->
  ssh_connection:send_eof(Local, LocChan),
  {ok, State};

handle_ssh_msg({ssh_cm, Conn, {exit_status,_,Status}}, #{conn := Conn, local_conn := Local, local_chan := LocChan} = State) ->
  ssh_connection:exit_status(Local, LocChan, Status),
  {ok, State};

handle_ssh_msg({ssh_cm, Conn, {closed, _ChannelId}}, #{conn := Conn, local_chan := LocChan} = State) ->
  {stop, LocChan, State};

handle_ssh_msg({ssh_cm, Conn, Msg}, #{conn := Conn} = State) ->
  io:format("REM2 ~p\n",[Msg]),
  {ok, State};


handle_ssh_msg({ssh_cm, _, {pty, _Chan, _, Request}}, #{conn := Conn, channel := ChannelId} = State) ->
  {TermName, Width, Height, PixWidth, PixHeight, Modes} = Request,
  PtyOptions = [{term,TermName},{width,Width},{height,Height},
    {pixel_width,PixWidth},{pixel_height,PixHeight},{pty_opts,Modes}],
  ssh_connection:ptty_alloc(Conn, ChannelId, PtyOptions, ?TIMEOUT),
  {ok, State};

handle_ssh_msg({ssh_cm, _, {env, _Chan, _, Var, Value}}, #{conn := Conn, channel := ChannelId} = State) ->
  ssh_connection:setenv(Conn, ChannelId, binary_to_list(Var), binary_to_list(Value), ?TIMEOUT),
  {ok, State};

handle_ssh_msg({ssh_cm, Local, {shell,_LocChan,_}}, #{local_conn := Local, conn := Conn, channel := ChannelId} = State) ->
  ssh_connection:shell(Conn, ChannelId),
  {ok, State};

handle_ssh_msg({ssh_cm, Local, {exec,_LocChan,_,Command}}, #{local_conn := Local, conn := Conn, channel := ChannelId} = State) ->
  ssh_connection:exec(Conn, ChannelId, Command, ?TIMEOUT),
  {ok, State};

handle_ssh_msg({ssh_cm, Local, {eof,_LocChan}}, #{local_conn := Local, conn := Conn, channel := ChannelId} = State) ->
  ssh_connection:send_eof(Conn, ChannelId),
  {ok, State};

handle_ssh_msg({ssh_cm, _, Msg}, State) ->
  io:format("LOC ~p\n",[Msg]),
  {ok, State};

handle_ssh_msg(Msg, State) ->
  io:format("LOC ~p\n",[Msg]),
  {ok, State}.


handle_msg({ssh_channel_up,LocChan,Local}, #{} = State) ->
  {_,Dict} = process_info(Local, dictionary),
  RemoteSpec = proplists:get_value(requested_hostname,Dict),
  [User,Host] = case string:tokens(RemoteSpec, [$/]) of
    [User_,Host_] -> [User_,Host_];
    [_] -> ["root", RemoteSpec]
  end,
  io:format("~p Open proxy to ~s@~s\n", [self(), User,Host]),
  {ok, Conn} = ssh:connect(Host, 22, [{user,User},{silently_accept_hosts, true},{quiet_mode, true}]),
  {ok, ChannelId} = ssh_connection:session_channel(Conn, ?TIMEOUT),
  {ok, State#{conn => Conn, channel => ChannelId, local_conn => Local, local_chan => LocChan}};

handle_msg(Msg, State) ->
  io:format("REM ~p ~p\n",[Msg,State]),
  {ok, State}.

terminate(_,_) -> ok.




