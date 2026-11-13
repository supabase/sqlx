use crate::error::Error;
use crate::{PgConnectOptions, PgSslMode};
use sqlx_core::percent_encoding::{percent_decode_str, utf8_percent_encode, NON_ALPHANUMERIC};
use sqlx_core::Url;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
#[cfg(test)]
use std::{env, process::Command};
#[cfg(test)]
use {futures_util::FutureExt, sqlx_core::connection::ConnectOptions};

impl PgConnectOptions {
    pub(crate) fn parse_from_url(url: &Url) -> Result<Self, Error> {
        let mut options = Self::new_without_pgpass();

        if let Some(host) = url.host_str() {
            let host_decoded = percent_decode_str(host);
            options = match host_decoded.clone().next() {
                Some(b'/') => options.socket(&*host_decoded.decode_utf8().map_err(Error::config)?),
                _ => options.host(
                    host.strip_prefix('[')
                        .and_then(|host| host.strip_suffix(']'))
                        .filter(|host| host.parse::<Ipv6Addr>().is_ok())
                        .unwrap_or(host),
                ),
            }
        }

        if let Some(port) = url.port() {
            options = options.port(port);
        }

        let username = url.username();
        if !username.is_empty() {
            options = options.username(
                &percent_decode_str(username)
                    .decode_utf8()
                    .map_err(Error::config)?,
            );
        }

        if let Some(password) = url.password() {
            options = options.password(
                &percent_decode_str(password)
                    .decode_utf8()
                    .map_err(Error::config)?,
            );
        }

        let path = url.path().trim_start_matches('/');
        if !path.is_empty() {
            options = options.database(
                &percent_decode_str(path)
                    .decode_utf8()
                    .map_err(Error::config)?,
            );
        }

        for (key, value) in url.query_pairs().into_iter() {
            match &*key {
                "sslmode" | "ssl-mode" => {
                    options = options.ssl_mode(value.parse().map_err(Error::config)?);
                }

                "sslrootcert" | "ssl-root-cert" | "ssl-ca" => {
                    options = options.ssl_root_cert(&*value);
                }

                "sslcert" | "ssl-cert" => options = options.ssl_client_cert(&*value),

                "sslkey" | "ssl-key" => options = options.ssl_client_key(&*value),

                "statement-cache-capacity" => {
                    options =
                        options.statement_cache_capacity(value.parse().map_err(Error::config)?);
                }

                "host" => {
                    if value.starts_with('/') {
                        options = options.socket(&*value);
                    } else {
                        options = options.host(&value);
                    }
                }

                "hostaddr" => {
                    options = options.hostaddr(value.parse::<IpAddr>().map_err(Error::config)?);
                }

                "port" => options = options.port(value.parse().map_err(Error::config)?),

                "dbname" => options = options.database(&value),

                "user" => options = options.username(&value),

                "password" => options = options.password(&value),

                "application_name" => options = options.application_name(&value),

                "options" => {
                    if let Some(options) = options.options.as_mut() {
                        options.push(' ');
                        options.push_str(&value);
                    } else {
                        options.options = Some(value.to_string());
                    }
                }

                k if k.starts_with("options[") => {
                    if let Some(key) = k.strip_prefix("options[").unwrap().strip_suffix(']') {
                        options = options.options([(key, &*value)]);
                    }
                }

                _ => tracing::warn!(%key, %value, "ignoring unrecognized connect parameter"),
            }
        }

        let options = options.apply_pgpass();

        Ok(options)
    }

    pub(crate) fn build_url(&self) -> Url {
        let host = match &self.socket {
            Some(socket) if self.hostaddr.is_none() => {
                utf8_percent_encode(&socket.to_string_lossy(), NON_ALPHANUMERIC).to_string()
            }
            _ if self.get_host().starts_with('/') => {
                utf8_percent_encode(self.get_host(), NON_ALPHANUMERIC).to_string()
            }
            _ if self.get_host().parse::<Ipv6Addr>().is_ok() => format!("[{}]", self.get_host()),
            _ => self.get_host().to_owned(),
        };

        let mut url = Url::parse(&format!(
            "postgres://{}@{}:{}",
            self.username, host, self.port
        ))
        .expect("BUG: generated un-parseable URL");

        if let Some(password) = &self.password {
            let password = utf8_percent_encode(password, NON_ALPHANUMERIC).to_string();
            let _ = url.set_password(Some(&password));
        }

        if let Some(database) = &self.database {
            url.set_path(database);
        }

        let ssl_mode = match self.ssl_mode {
            PgSslMode::Allow => "allow",
            PgSslMode::Disable => "disable",
            PgSslMode::Prefer => "prefer",
            PgSslMode::Require => "require",
            PgSslMode::VerifyCa => "verify-ca",
            PgSslMode::VerifyFull => "verify-full",
        };
        url.query_pairs_mut().append_pair("sslmode", ssl_mode);

        if let Some(host_addr) = &self.hostaddr {
            url.query_pairs_mut().append_pair("hostaddr", host_addr);
        }

        if let Some(ssl_root_cert) = &self.ssl_root_cert {
            url.query_pairs_mut()
                .append_pair("sslrootcert", &ssl_root_cert.to_string());
        }

        if let Some(ssl_client_cert) = &self.ssl_client_cert {
            url.query_pairs_mut()
                .append_pair("sslcert", &ssl_client_cert.to_string());
        }

        if let Some(ssl_client_key) = &self.ssl_client_key {
            url.query_pairs_mut()
                .append_pair("sslkey", &ssl_client_key.to_string());
        }

        url.query_pairs_mut().append_pair(
            "statement-cache-capacity",
            &self.statement_cache_capacity.to_string(),
        );

        url
    }
}

impl FromStr for PgConnectOptions {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let url: Url = s.parse().map_err(Error::config)?;

        Self::parse_from_url(&url)
    }
}

#[test]
fn it_parses_socket_correctly_from_parameter() {
    let url = "postgres:///?host=/var/run/postgres/";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(Some("/var/run/postgres/".into()), opts.socket);
}

#[test]
fn it_parses_host_correctly_from_parameter() {
    let url = "postgres:///?host=google.database.com";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(None, opts.socket);
    assert_eq!("google.database.com", &opts.host);
}

#[test]
fn it_parses_hostaddr_correctly_from_parameter() {
    let url = "postgres://example.com/?hostaddr=192.0.2.10";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(None, opts.socket);
    assert_eq!("example.com", &opts.host);
    assert_eq!(Some("192.0.2.10"), opts.hostaddr.as_deref());
}

#[test]
fn hostaddr_preserves_identity_and_round_trips() {
    for address in ["192.0.2.10", "2001:db8::10"] {
        for parameters in [
            format!("host=example.com&hostaddr={address}"),
            format!("hostaddr={address}&host=example.com"),
        ] {
            let options: PgConnectOptions = format!("postgres://other.example/?{parameters}")
                .parse()
                .unwrap();
            let restored = PgConnectOptions::parse_from_url(&options.build_url()).unwrap();
            assert_eq!(restored.get_host(), "example.com");
            assert_eq!(restored.hostaddr.as_deref(), Some(address));
        }
    }
    assert!("postgres://example.com/?hostaddr=invalid.example"
        .parse::<PgConnectOptions>()
        .is_err());
}

#[test]
fn hostaddr_overrides_sockets_and_can_be_cleared() {
    let options = PgConnectOptions::new_without_pgpass()
        .host("example.com")
        .socket("/tmp")
        .hostaddr("192.0.2.10".parse::<IpAddr>().unwrap());
    assert_eq!(options.make_socket_path(), None);
    let restored = PgConnectOptions::parse_from_url(&options.build_url()).unwrap();
    assert_eq!(restored.get_host(), "example.com");
    assert_eq!(restored.hostaddr.as_deref(), Some("192.0.2.10"));
    assert!(options.clear_hostaddr().make_socket_path().is_some());
}

#[test]
fn hostaddr_environment_is_independent() {
    if env::var_os("SQLX_HOSTADDR_TEST_CHILD").is_none() {
        for address in ["192.0.2.10", "2001:db8::10", "invalid.example"] {
            for host in [None, Some(""), Some("example.com"), Some("/private/tmp")] {
                let mut child = Command::new(env::current_exe().unwrap());
                child
                    .args([
                        "--exact",
                        "options::parse::hostaddr_environment_is_independent",
                    ])
                    .env("SQLX_HOSTADDR_TEST_CHILD", "1")
                    .env("PGHOSTADDR", address);
                if let Some(host) = host {
                    child.env("PGHOST", host);
                } else {
                    child.env_remove("PGHOST");
                }
                let output = child.output().unwrap();
                assert!(output.status.success());
                assert!(String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("1 passed;"));
            }
        }
        return;
    }
    let address = env::var("PGHOSTADDR").unwrap();
    let options = PgConnectOptions::new_without_pgpass();
    let expected = match env::var("PGHOST").as_deref() {
        Ok("example.com") => "example.com",
        _ => &address,
    };
    assert_eq!(options.get_host(), expected);
    assert_eq!(options.hostaddr.as_deref(), Some(address.as_str()));
    if address == "invalid.example" {
        let error = options.connect().now_or_never().unwrap().unwrap_err();
        assert!(matches!(error, Error::Configuration(_)));
    } else {
        let restored = PgConnectOptions::parse_from_url(&options.build_url()).unwrap();
        assert_eq!(restored.get_host(), expected);
        assert_eq!(restored.hostaddr.as_deref(), Some(address.as_str()));
        let from_url: PgConnectOptions =
            format!("postgres:///?hostaddr={address}").parse().unwrap();
        assert_eq!(from_url.get_host(), expected);
        let from_setter = options.clone().hostaddr(address.parse::<IpAddr>().unwrap());
        assert_eq!(from_setter.get_host(), expected);
    }
    assert_eq!(options.clone().clear_hostaddr().hostaddr.as_deref(), None);
    let options: PgConnectOptions = "postgres://other.example/?hostaddr=192.0.2.20"
        .parse()
        .unwrap();
    assert_eq!(options.get_host(), "other.example");
    assert_eq!(options.hostaddr.as_deref(), Some("192.0.2.20"));
}

#[test]
fn it_parses_port_correctly_from_parameter() {
    let url = "postgres:///?port=1234";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(None, opts.socket);
    assert_eq!(1234, opts.port);
}

#[test]
fn it_parses_dbname_correctly_from_parameter() {
    let url = "postgres:///?dbname=some_db";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(None, opts.socket);
    assert_eq!(Some("some_db"), opts.database.as_deref());
}

#[test]
fn it_parses_user_correctly_from_parameter() {
    let url = "postgres:///?user=some_user";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(None, opts.socket);
    assert_eq!("some_user", opts.username);
}

#[test]
fn it_parses_password_correctly_from_parameter() {
    let url = "postgres:///?password=some_pass";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(None, opts.socket);
    assert_eq!(Some("some_pass"), opts.password.as_deref());
}

#[test]
fn it_parses_application_name_correctly_from_parameter() {
    let url = "postgres:///?application_name=some_name";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(Some("some_name"), opts.application_name.as_deref());
}

#[test]
fn it_parses_username_with_at_sign_correctly() {
    let url = "postgres://user@hostname:password@hostname:5432/database";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!("user@hostname", &opts.username);
}

#[test]
fn it_parses_password_with_non_ascii_chars_correctly() {
    let url = "postgres://username:p@ssw0rd@hostname:5432/database";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(Some("p@ssw0rd".into()), opts.password);
}

#[test]
fn it_parses_socket_correctly_percent_encoded() {
    let url = "postgres://%2Fvar%2Flib%2Fpostgres/database";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(Some("/var/lib/postgres/".into()), opts.socket);
}
#[test]
fn it_parses_socket_correctly_with_username_percent_encoded() {
    let url = "postgres://some_user@%2Fvar%2Flib%2Fpostgres/database";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!("some_user", opts.username);
    assert_eq!(Some("/var/lib/postgres/".into()), opts.socket);
    assert_eq!(Some("database"), opts.database.as_deref());
}
#[test]
fn it_parses_libpq_options_correctly() {
    let url = "postgres:///?options=-c%20synchronous_commit%3Doff%20--search_path%3Dpostgres";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(
        Some("-c synchronous_commit=off --search_path=postgres".into()),
        opts.options
    );
}
#[test]
fn it_parses_sqlx_options_correctly() {
    let url = "postgres:///?options[synchronous_commit]=off&options[search_path]=postgres";
    let opts = PgConnectOptions::from_str(url).unwrap();

    assert_eq!(
        Some("-c synchronous_commit=off -c search_path=postgres".into()),
        opts.options
    );
}

#[test]
fn it_returns_the_parsed_url_when_socket() {
    let url = "postgres://username@%2Fvar%2Flib%2Fpostgres/database";
    let opts = PgConnectOptions::from_str(url).unwrap();

    let mut expected_url = Url::parse(url).unwrap();
    // PgConnectOptions defaults
    let query_string = "sslmode=prefer&statement-cache-capacity=100";
    let port = 5432;
    expected_url.set_query(Some(query_string));
    let _ = expected_url.set_port(Some(port));

    assert_eq!(expected_url, opts.build_url());
}

#[test]
fn it_returns_the_parsed_url_when_host() {
    let url = "postgres://username:p@ssw0rd@hostname:5432/database";
    let opts = PgConnectOptions::from_str(url).unwrap();

    let mut expected_url = Url::parse(url).unwrap();
    // PgConnectOptions defaults
    let query_string = "sslmode=prefer&statement-cache-capacity=100";
    expected_url.set_query(Some(query_string));

    assert_eq!(expected_url, opts.build_url());
}

#[test]
fn built_url_can_be_parsed() {
    let url = "postgres://username:p@ssw0rd@hostname:5432/database";
    let opts = PgConnectOptions::from_str(url).unwrap();

    let parsed = PgConnectOptions::from_str(opts.build_url().as_ref());

    assert!(parsed.is_ok());
}
