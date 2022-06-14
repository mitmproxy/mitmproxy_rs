use std::str::FromStr;

use super::error::WireguardConfError;
use super::server::{generate_default_configs, WireguardServerConf};

// example configurations are derived from the wg(8) and wg-quick(8) manpages

#[test]
fn valid_one_peer() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

    let conf = WireguardServerConf::from_str(string).unwrap();

    assert_eq!(conf.interface.listen_port, 51820);
    assert_eq!(
        conf.interface.private_key.as_bytes(),
        base64::decode("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").unwrap(),
    );

    assert_eq!(conf.peers.len(), 1);
    assert_eq!(
        conf.peers[0].public_key.as_bytes(),
        base64::decode("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap(),
    );
    assert!(conf.peers[0].preshared_key.is_none());
}

#[test]
fn valid_two_peers() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
PresharedKey = sN7qr4ejf5jdc+Z25FFmEiVrGwyPM0d1FaSca/JaIHQ=
";

    let conf = WireguardServerConf::from_str(string).unwrap();

    assert_eq!(conf.interface.listen_port, 51820);
    assert_eq!(
        conf.interface.private_key.as_bytes(),
        base64::decode("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").unwrap(),
    );

    assert_eq!(conf.peers.len(), 2);
    assert_eq!(
        conf.peers[0].public_key.as_bytes(),
        base64::decode("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap(),
    );
    assert!(conf.peers[0].preshared_key.is_none());

    assert_eq!(
        conf.peers[1].public_key.as_bytes(),
        base64::decode("TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=").unwrap(),
    );
    assert_eq!(
        conf.peers[1].preshared_key.unwrap().to_vec(),
        base64::decode("sN7qr4ejf5jdc+Z25FFmEiVrGwyPM0d1FaSca/JaIHQ=").unwrap(),
    );
}

#[test]
fn invalid_empty() {
    let string = "";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::NoInterface)
    ));
}

#[test]
fn invalid_missing_interface() {
    let string = "\
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::NoInterface)
    ));
}

#[test]
fn invalid_multiple_interfaces() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Interface]
PrivateKey = SA7v+rddcb/KJAD41Jb12tHEpLMN1XsovpbBeqOD+Fg=
ListenPort = 51821
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::MultipleInterfaces)
    ));
}

#[test]
fn invalid_no_peers() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::NoPeers)
    ));
}

#[test]
fn invalid_missing_private_key() {
    let string = "\
[Interface]
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::MissingKeys { section, names }) if section == "Interface" && names == "PrivateKey"),);
}

#[test]
fn invalid_missing_port() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::MissingKeys { section, names }) if section == "Interface" && names == "ListenPort"),);
}

#[test]
fn invalid_missing_public_key() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PresharedKey = sN7qr4ejf5jdc+Z25FFmEiVrGwyPM0d1FaSca/JaIHQ=
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::MissingKeys { section, names }) if section == "Peer" && names == "PublicKey"),);
}

#[test]
fn invalid_private_key() {
    let string = "\
[Interface]
PrivateKey = HELLOWORLD
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::InvalidPrivateKey { .. })
    ));
}

#[test]
fn invalid_port() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = HELLOWORLD

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::InvalidPort { .. })
    ));
}

#[test]
fn invalid_port_overflow() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 518202938293829839293829382

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::InvalidPort { .. })
    ));
}

#[test]
fn invalid_public_key() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = HELLOWORLD
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::InvalidPublicKey { .. })
    ));
}

#[test]
fn invalid_preshared_key() {
    let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
PresharedKey = HELLOWORLD
";

    assert!(matches!(
        WireguardServerConf::from_str(string),
        Err(WireguardConfError::InvalidPresharedKey { .. })
    ));
}

#[test]
fn generate_no_peers() {
    assert!(matches!(generate_default_configs(0), Err(WireguardConfError::NoPeers)));
}

#[test]
fn generate_with_peers() {
    // none of these should fail
    for i in 1..=10 {
        generate_default_configs(i).unwrap();
    }
}

#[test]
fn generate_and_read_one_peer() {
    let (server_conf, _peer_confs) = generate_default_configs(1).unwrap();

    let string = server_conf.to_string();
    let parsed = WireguardServerConf::from_str(&string).unwrap();

    assert_eq!(server_conf, parsed);
}

#[test]
fn generate_and_read_two_peers() {
    let (server_conf, _peer_confs) = generate_default_configs(2).unwrap();

    let string = server_conf.to_string();
    let parsed = WireguardServerConf::from_str(&string).unwrap();

    assert_eq!(server_conf, parsed);
}
