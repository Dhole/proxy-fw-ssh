#![allow(unused_imports)]
#![allow(unused_variables)]
// use tokio::sync::Mutex;
use std::collections::HashMap;
use std::{cell::RefCell, rc::Rc, sync::OnceLock};

use gtk4::glib;
use std::{
    borrow::Cow,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs as StdToSocketAddrs},
    ops::Deref,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use std::{cell::Cell, io, os::fd::AsRawFd as _};

use async_channel::{Receiver, Sender};
use dashmap::{mapref::one::Ref, DashMap};
use fast_socks5::{
    server::{states, ErrorContext, Socks5ServerProtocol, SocksServerError},
    util::{
        stream::tcp_connect_with_timeout,
        target_addr::{AddrError, TargetAddr},
    },
    ReplyError, Result, Socks5Command, SocksError,
};
use log::{debug, error, info};
use russh::{
    client,
    keys::{Certificate, *},
    server::{self, run_stream, Server as _},
    Channel, ChannelId, Preferred,
};
use serde::{Deserialize, Serialize};
use ssh_key::private::{Ed25519Keypair, KeypairData};
use structopt::StructOpt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{self, TcpListener},
    // sync::mpsc::{self, Receiver, Sender},
    sync::{MappedMutexGuard, Mutex, MutexGuard, OnceCell, RwLock, RwLockReadGuard, SetOnce},
    task,
    time::sleep,
};

pub mod model;
pub mod rules;
pub mod ui;

use crate::model::Permission;
use rules::{RequestRules, RequestRulesExec, Rules};
use ui::main_ui;
use ui::messages::{ReplyPermission, RequestUi};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    inbound_server_address: String,
    inbound_server_identity_file: String,
    outbound_client_identity_file: String,
}

#[derive(Clone)]
struct Setup {
    ssh_server: Arc<russh::server::Config>,
    ssh_client: Arc<russh::client::Config>,
    outbound_client_key: PrivateKey,
    request_timeout: Duration,
    req_rules_tx: Sender<RequestRules>,
}

struct SessionState {
    //
    // Static
    //
    outbound_server_addr: TargetAddr,
    outbound_client_key: PrivateKey,
    inbound_client_auth: SetOnce<(String, ssh_key::PublicKey)>,
    inbound_client_pk_openssh: SetOnce<String>,
    // Requires mut
    outbound_session: SetOnce<Mutex<russh::client::Handle<Handler>>>,
    inbound_session: SetOnce<russh::server::Handle>,
    //
    // Actors
    //
    req_rules_tx: Sender<RequestRules>,
    //
    // Dynamic
    //
    outbound_inbound_chan_id_map: DashMap<u32, ChannelId>,
    inbound_outbound_chan_map: DashMap<u32, Channel<client::Msg>>,
}

#[derive(Clone)]
struct Handler(Arc<SessionState>);

impl Deref for Handler {
    type Target = SessionState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SessionState {
    fn new(
        outbound_server_addr: TargetAddr,
        outbound_client_key: PrivateKey,
        req_rules_tx: Sender<RequestRules>,
    ) -> Self {
        Self {
            outbound_server_addr,
            outbound_client_key,
            inbound_client_auth: SetOnce::new(),
            inbound_client_pk_openssh: SetOnce::new(),
            outbound_session: SetOnce::new(),
            inbound_session: SetOnce::new(),
            req_rules_tx: req_rules_tx,
            outbound_inbound_chan_id_map: DashMap::new(),
            inbound_outbound_chan_map: DashMap::new(),
        }
    }
    async fn outbound_handle(&self) -> MutexGuard<'_, russh::client::Handle<Handler>> {
        self.outbound_session.wait().await.lock().await
    }
    async fn inbound_handle(&self) -> &russh::server::Handle {
        self.inbound_session.wait().await
    }
    fn inbound_chan_id(&self, outbound_id: ChannelId) -> ChannelId {
        self.outbound_inbound_chan_id_map
            .get(&u32::from(outbound_id))
            .unwrap()
            .clone()
    }
    fn set_chan_map(&self, inbound_id: ChannelId, outbound_chan: Channel<client::Msg>) {
        self.outbound_inbound_chan_id_map
            .insert(u32::from(outbound_chan.id()), inbound_id);
        self.inbound_outbound_chan_map
            .insert(u32::from(inbound_id), outbound_chan);
    }
    fn outbound_chan(&self, inbound_id: ChannelId) -> Ref<'_, u32, Channel<client::Msg>> {
        self.inbound_outbound_chan_map
            .get(&u32::from(inbound_id))
            .unwrap()
    }
    // panics if called before auth
    fn inbound_client_pk_openssh(&self) -> &str {
        self.inbound_client_pk_openssh.get().expect("set at auth")
    }
    fn set_inbound_client_auth(&self, user: String, pk: ssh_key::PublicKey) {
        // TODO: Figure out when may this fail, considering that the pk has been authenticated
        // at this point
        let pk_openssh = pk.to_openssh().expect("TODO");
        self.inbound_client_auth
            .set((user, pk))
            .expect("auth not set");
        self.inbound_client_pk_openssh
            .set(pk_openssh)
            .expect("pk not set");
    }
    // async fn client_rules(&self) -> &ClientRules {
    //     if let Some(client_rules) = self.client_rules.get() {
    //         &client_rules
    //     } else {
    //         // Make a local copy of the client rules for this session
    //         let pk_ssh = self.inbound_client_pk_openssh();
    //         let client_rules = self
    //             .rules
    //             .read()
    //             .await
    //             .get(pk_ssh)
    //             .cloned()
    //             .unwrap_or_default();
    //         // This set could be raced but the value would be the same, so we ignore the error
    //         self.client_rules.set(client_rules).unwrap_or_default();
    //         self.client_rules.get().expect("just set")
    //     }
    // }
    // fn user_req_handler(&self) -> RequestUiHandler {
    //     RequestUiHandler {
    //         pk_openssh: self.inbound_client_pk_openssh().to_string(),
    //         tx: self.req_ui_tx.clone(),
    //     }
    // }
}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // TODO: TOFU like OpenSSH
        Ok(true)
    }

    #[allow(unused_variables)]
    async fn channel_success(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        debug!("client: channel success");
        Ok(())
    }

    #[allow(unused_variables)]
    async fn channel_failure(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        debug!("client: channel failure");
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let inbound_channel_id = self.inbound_chan_id(channel);
        self.inbound_handle()
            .await
            .eof(inbound_channel_id)
            .await
            .unwrap();
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let inbound_channel_id = self.inbound_chan_id(channel);
        self.inbound_handle()
            .await
            .close(inbound_channel_id)
            .await
            .unwrap();
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        debug!(
            "DBG outbound server data: {}",
            String::from_utf8_lossy(data)
        );
        let inbound_channel_id = self.inbound_chan_id(channel);
        self.inbound_handle()
            .await
            .data(inbound_channel_id, data.to_vec())
            .await
            .unwrap();
        Ok(())
    }

    async fn exit_status(
        &mut self,
        channel: ChannelId,
        exit_status: u32,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        debug!("DBG outbound server exit_status: {}", exit_status);
        let inbound_channel_id = self.inbound_chan_id(channel);
        self.inbound_handle()
            .await
            .exit_status_request(inbound_channel_id, exit_status)
            .await
            .unwrap();
        Ok(())
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        debug!("DBG channel_open_session {}", channel.id());
        let outbound_channel = self.outbound_handle().await.channel_open_session().await?;
        self.set_chan_map(channel.id(), outbound_channel);
        Ok(true)
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let outbound_channel = self.outbound_chan(channel);
        outbound_channel.eof().await.unwrap();
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let outbound_channel = self.outbound_chan(channel);
        outbound_channel.close().await.unwrap();
        Ok(())
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        debug!(
            "DBG auth_publickey user={}, key={}",
            user,
            key.to_openssh().unwrap()
        );
        let hash_alg = self
            .outbound_handle()
            .await
            .best_supported_rsa_hash()
            .await?
            .flatten();
        let auth_res = self
            .outbound_handle()
            .await
            .authenticate_publickey(
                user,
                PrivateKeyWithHashAlg::new(Arc::new(self.outbound_client_key.clone()), hash_alg),
            )
            .await?;

        if !auth_res.success() {
            panic!("Authentication (with publickey) failed");
        } else {
            debug!("Authentication success");
        }
        self.set_inbound_client_auth(user.to_string(), key.clone());
        Ok(server::Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<server::Auth, Self::Error> {
        info!("DBG auth_openssh_certificate");
        Ok(server::Auth::UnsupportedMethod)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        let (user, pk) = self.inbound_client_auth.get().unwrap();
        info!(
            "DBG exec_request auth: ({}, {}) chan {}: {} - {}",
            user,
            pk.to_openssh().unwrap(),
            channel,
            self.outbound_server_addr,
            String::from_utf8_lossy(data)
        );
        let server_addr = format!("{}", self.outbound_server_addr);
        let data = str::from_utf8(data).expect("TODO");
        match (RequestRulesExec {
            pk_openssh: self.inbound_client_pk_openssh().to_string(),
            server_addr,
            user: user.clone(),
            data: data.to_string(),
        })
        .request(&self.req_rules_tx)
        .await
        {
            Ok(()) => info!("approved exec"),

            Err(e) => {
                info!("denied exec: {}", e);
                panic!("TODO");
            }
        }
        // TODO: Allow or deny based on config
        let outbound_channel = self.outbound_chan(channel);
        outbound_channel.exec(true, data).await?;
        // TODO: sync with client channel success/failure
        session.channel_success(channel)?;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        debug!("DBG inbound client data: {}", String::from_utf8_lossy(data));
        let outbound_channel = self.outbound_chan(channel);
        outbound_channel.data(data).await?;
        // let data = format!("Got data: {}\r\n", String::from_utf8_lossy(data)).into_bytes();
        // self.post(data.clone()).await;
        // session.data(channel, data)?;
        Ok(())
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "ssh-git-fw", about = "git over ssh proxy firewall")]
struct Opt {
    #[structopt(short = "c", long)]
    pub config: PathBuf,

    #[structopt(short = "r", long)]
    pub rules: PathBuf,
}

use tokio::runtime::Runtime;

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| Runtime::new().expect("tokio runtime setup failed"))
}

fn main() -> glib::ExitCode {
    env_logger::init();

    let (req_ui_tx, req_ui_rx) = async_channel::bounded::<RequestUi>(16);
    let (req_rules_tx, req_rules_rx) = async_channel::bounded::<RequestRules>(16);

    let opt = Opt::from_args();
    let config_toml = fs::read(opt.config).expect("TODO");
    let config: Config = toml::from_slice(&config_toml).unwrap();
    let rules = Rules::new(opt.rules.as_path(), req_rules_rx, req_ui_tx).expect("TODO");

    let addr = config.inbound_server_address.clone();

    info!("Listen for socks connections @ {}", addr);

    // Testing hardcoded key
    let inbound_server_identity_file = shellexpand::tilde(&config.inbound_server_identity_file);
    let inbound_server_key =
        PrivateKey::read_openssh_file(inbound_server_identity_file.as_ref()).unwrap();
    info!(
        "inbound server key: {}",
        inbound_server_key.public_key().to_openssh().unwrap()
    );
    if inbound_server_key.is_encrypted() {
        panic!("encrypted openssh inbound server key not yet supported");
    }
    let outbound_client_identity_file = shellexpand::tilde(&config.outbound_client_identity_file);
    let outbound_client_key =
        PrivateKey::read_openssh_file(outbound_client_identity_file.as_ref()).unwrap();
    info!(
        "outbound client key: {}",
        outbound_client_key.public_key().to_openssh().unwrap()
    );
    if outbound_client_key.is_encrypted() {
        panic!("encrypted openssh inbound server key not yet supported");
    }

    let config_ssh_server = russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![inbound_server_key],
        preferred: Preferred {
            // kex: std::borrow::Cow::Owned(vec![russh::kex::DH_GEX_SHA256]),
            ..Preferred::default()
        },
        ..Default::default()
    };
    let config_ssh_client = client::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(2)),
        preferred: Preferred {
            kex: Cow::Owned(vec![
                russh::kex::CURVE25519_PRE_RFC_8731,
                russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
            ]),
            ..Default::default()
        },
        ..<_>::default()
    };

    let local = task::LocalSet::new();

    let setup = Setup {
        ssh_server: Arc::new(config_ssh_server),
        ssh_client: Arc::new(config_ssh_client),
        outbound_client_key,
        request_timeout: Duration::from_secs(5),
        req_rules_tx,
    };

    // Proxy server main loop
    runtime().spawn(async move {
        let listener = TcpListener::bind(addr).await.unwrap();
        loop {
            match listener.accept().await {
                Ok((socket, _client_addr)) => {
                    let setup = setup.clone();
                    task::spawn(async move {
                        match serve_socks5(socket, setup).await {
                            Ok(()) => {}
                            Err(err) => error!("{:#}", &err),
                        }
                    });
                }
                Err(err) => {
                    error!("accept error = {:?}", err);
                }
            }
        }
    });
    // Rules actor main loop
    runtime().spawn(async move { rules.run().await });

    main_ui(req_ui_rx)
}

async fn serve_socks5(socket: tokio::net::TcpStream, setup: Setup) -> Result<(), SocksError> {
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?;
    debug!("DBG accept socks5 to {}", target_addr);

    match cmd {
        Socks5Command::TCPConnect => {
            // TODO: Duration from config
            run_tcp_proxy(proto, target_addr, setup).await?;
        }
        _ => {
            proto.reply_error(&ReplyError::CommandNotSupported).await?;
            return Err(ReplyError::CommandNotSupported.into());
        }
    };
    Ok(())
}

macro_rules! try_notify {
    ($proto:expr, $e:expr) => {
        match $e {
            Ok(res) => res,
            Err(err) => {
                if let Err(rep_err) = $proto.reply_error(&err.to_reply_error()).await {
                    error!(
                        "extra error while reporting an error to the client: {}",
                        rep_err
                    );
                }
                return Err(err.into());
            }
        }
    };
}

/// Handle the connect command by running a TCP proxy until the connection is done.
async fn run_tcp_proxy<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    proto: Socks5ServerProtocol<T, states::CommandRead>,
    target_addr: TargetAddr,
    setup: Setup,
    // nodelay: bool,
) -> Result<(), SocksServerError> {
    let addrs = match &target_addr {
        TargetAddr::Ip(ip) => vec![*ip],
        TargetAddr::Domain(domain, port) => {
            debug!("Attempt to DNS resolve the domain {}...", &domain);

            let socket_addrs: Vec<_> = net::lookup_host((&domain[..], *port))
                .await
                .map_err(|err| AddrError::DNSResolutionFailed(err))?
                .collect();
            if socket_addrs.is_empty() {
                return Err(AddrError::NoDNSRecords)?;
            }
            debug!("domain name resolved to {:?}", socket_addrs);
            socket_addrs
        }
    };

    // let _addr = try_notify!(
    //     proto,
    //     addr.to_socket_addrs()
    //         .err_when("converting to socket addr")
    //         .and_then(|mut addrs| addrs.next().ok_or(SocksServerError::Bug("no socket addrs")))
    // );

    // TCP connect with timeout, to avoid memory leak for connection that takes forever
    // TODO: Use the other addrs if the first one fails
    let outbound_stream = try_notify!(
        proto,
        tcp_connect_with_timeout(addrs[0], setup.request_timeout).await
    );

    // // Disable Nagle's algorithm if config specifies to do so.
    // try_notify!(
    //     proto,
    //     outbound.set_nodelay(nodelay).err_when("setting nodelay")
    // );

    // debug!("Connected to remote destination");

    let inbound_stream = proto
        .reply_success(outbound_stream.local_addr().expect("ok"))
        .await?;

    let handler = Handler(Arc::new(SessionState::new(
        target_addr,
        setup.outbound_client_key,
        setup.req_rules_tx,
    )));
    let outbound_session =
        match russh::client::connect_stream(setup.ssh_client, outbound_stream, handler.clone())
            .await
        {
            Ok(s) => s,
            Err(e) => {
                panic!("Connection setup failed: {}", e);
            }
        };
    handler
        .outbound_session
        .set(Mutex::new(outbound_session))
        .unwrap_or_else(|_| panic!("todo"));

    let inbound_session = match run_stream(setup.ssh_server, inbound_stream, handler.clone()).await
    {
        Ok(s) => s,
        Err(e) => {
            panic!("Connection setup failed: {}", e);
        }
    };
    handler
        .inbound_session
        .set(inbound_session.handle())
        .unwrap_or_else(|_| panic!("todo"));

    tokio::select! {
        result = inbound_session => {
            if let Err(e) = result {
                panic!("Connection closed with error: {}", e);
            } else {
                debug!("Connection closed");
            }
        }
    }
    // russh doesn't expose the (reason, description, language_tag) of a client disconnect, so we
    // can't propagate those values when we disconnect the outbound session.
    handler
        .outbound_handle()
        .await
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .unwrap();

    Ok(())
}
