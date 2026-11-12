mod socket;
pub mod tls;

pub use socket::{
    connect_tcp, connect_tcp_staggered, connect_uds, BufferedSocket, Socket, SocketIntoBox,
    WithSocket, WriteBuffer,
};
