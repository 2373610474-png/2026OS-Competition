use core::{any::Any, clone, mem, option, panic, ptr};

use alloc::{ffi::CString, sync::Arc, task, vec::Vec,vec};
use fatfs::{info, warn};
use hal::{addr, instruction::{Instruction, InstructionHal}, println};
use lwext4_rust::bindings::EXT4_SUPERBLOCK_FLAGS_TEST_FILESYS;
use smoltcp::socket::dns::Socket;

use crate::{config::PAGE_SIZE, fs::{pipefs, OpenFlags}, mm::{UserPtr, UserPtrRaw, UserSliceRaw}, net::{addr::{SockAddr, SockAddrIn4, SockAddrIn6, SockAddrUn}, socket::{self, Sock, SockResult}, tcp::TcpSocket, SaFamily}, signal::SigSet, task::{current_task, fs::{FdFlags, FdInfo}, task::TaskControlBlock}, utils::yield_now};

use super::{IoVec, SysError, SysResult};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Socket types
pub enum SocketType {
    /// TCP
    STREAM = 1,
    /// UDP
    DGRAM = 2,
    /// Raw IP
    RAW = 3,
    /// RDM
    RDM = 4,
    /// Seq Packet
    SEQPACKET = 5,
    /// DCCP
    DCCP = 6,
    /// Packet
    PACKET = 10,
}

impl TryFrom<i32> for SocketType {
    type Error = SysError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::STREAM),
            2 => Ok(Self::DGRAM),
            3 => Ok(Self::RAW),
            4 => Ok(Self::RDM),
            5 => Ok(Self::SEQPACKET),
            6 => Ok(Self::DCCP),
            10 => Ok(Self::PACKET),
            _ => Err(Self::Error::EINVAL),
        }
    }
}

/// Set O_NONBLOCK flag on the open fd
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set FD_CLOEXEC flag on the new fd
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// create an endpoint for communication and returns a file decriptor refers to the endpoint
/// Since Linux 2.6.27, the type argument serves a second purpose: in
///addition to specifying a socket type, it may include the bitwise
///OR of any of the following values, to modify the behavior of
///socket():
// SOCK_NONBLOCK
//        Set the O_NONBLOCK file status flag on the open file
//        description (see open(2)) referred to by the new file
//        descriptor.  Using this flag saves extra calls to fcntl(2)
//        to achieve the same result.

// SOCK_CLOEXEC
//        Set the close-on-exec (FD_CLOEXEC) flag on the new file
//        descriptor.  See the description of the O_CLOEXEC flag in
//        open(2) for reasons why this may be useful.
pub fn sys_socket(domain: usize, types: i32, _protocol: usize) -> SysResult {
    if domain <= 0 || domain > 255 {
        return Err(SysError::EAFNOSUPPORT);
    }
    log::info!("[sys_socket] domain: {:?}, types: {:?}, protocol: {:?}", domain, types, _protocol);
    let domain = SaFamily::try_from(domain as u16)?;
    let mut types = types as i32;
    let mut nonblock = false;
    // file descriptor flags
    let mut flags = OpenFlags::empty();
    if types & SOCK_NONBLOCK != 0 {
        nonblock = true;
        types &= !SOCK_NONBLOCK;
        flags |= OpenFlags::O_NONBLOCK;
    } 
    if types & SOCK_CLOEXEC != 0 {
        types &= !SOCK_CLOEXEC;
        flags |= OpenFlags::O_CLOEXEC;
    }

    let types = SocketType::try_from(types as i32)?;
    // NOTE: was `||`, which is always true (a value cannot be both STREAM and
    // DGRAM), so every socket() failed with EPROTONOSUPPORT. Correct form is `&&`.
    if types != SocketType::STREAM && types != SocketType::DGRAM {
        return Err(SysError::EPROTONOSUPPORT);
    }
    let socket = socket::Socket::new(domain,types, nonblock);
    let fd_info = FdInfo {
        file: Arc::new(socket),
        flags: flags.into(),
    };
    let task = current_task().unwrap();
    let fd = task.with_mut_fd_table(|t|t.alloc_fd())?;
    task.with_mut_fd_table(|t| {
        t.put_file(fd, fd_info).or_else(|e|Err(e))
    })?;
    log::info!("[sys_socket]socket types:{:?}, fd: {}", types,fd);
    Ok(fd as isize)
}
/// “assigning a name to a socket”
pub fn sys_bind(fd: usize, addr: usize, addr_len: usize) -> SysResult {
    log::info!("[sys_bind] fd: {}, addr: {:#?}, addr_len: {}", fd, addr, addr_len);
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    let task = current_task().unwrap();
    let local_addr = sockaddr_reader(addr, addr_len, task)?;
    log::info!("[sys_bind] local_addr's port is: {}",unsafe {
        local_addr.ipv4
    });
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    log::info!("[sys_bind] socket_file_type {:#?}, fd_type {:#?}", socket_file.sk_type, fd);
    socket_file.sk.bind(fd, local_addr)?;
    Ok(0)
}

/// Mark the stream socket referenced by the file descriptor `sockfd` as
/// passive. This socket will be used later to accept connections from other
/// (active) sockets
pub fn sys_listen(fd: usize, _backlog: usize) -> SysResult {
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    let current_task = current_task().unwrap();
    let socket_file = current_task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    socket_file.sk.listen()?;
    Ok(0)
}

/// Connect the active socket refrenced by the file descriptor `sockfd` to the
/// address specified by `addr`. The `addr` argument is a pointer to a
/// `sockaddr` structure that contains the address of the remote socket.
/// The `addrlen` argument specifies the size of this structure.
pub async fn sys_connect(fd: usize, addr: usize, addr_len: usize) -> SysResult {
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    let task = current_task().unwrap().clone();
    let remote_addr = sockaddr_reader(addr, addr_len, &task)?;
    log::info!("[sys_connect] remote_addr is: {}",
        unsafe {
            remote_addr.ipv4
    });
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    log::info!("[sys_connect] socket_file_type {:#?}", socket_file.sk_type);
    socket_file.sk.connect(remote_addr.into_endpoint()).await?;
    // yield_now().await;
    Ok(0)
}

/// Accept a connection on the socket `sockfd` that is ready to be accepted.
/// The `addr` argument is a pointer to a `sockaddr` structure that will
/// hold the address of the peer socket, and `addrlen` is a pointer to
/// an integer that will hold the size of this structure.
///
/// The `sockfd` argument is a socket that has been created with the
/// `SOCK_STREAM` type, has been bound to a local address with `bind`,
/// and is listening for connections after a `listen` system call.
///
/// The `accept` system call is used on a socket that is listening for
/// incoming connections. It extracts the first connection request on
/// the queue of pending connections, creates a new socket for the
/// connection, and returns a new file descriptor referring to that
/// socket. The newly created socket is usually in the `ESTABLISHED`

pub async fn sys_accept(fd: usize, addr: usize, addr_len: usize) -> SysResult {
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    let task = current_task().unwrap();
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    // moniter accept, allow sig_kill and sig_stop to interrupt
    task.set_interruptable();
    let old_mask = task.sig_manager.lock().blocked_sigs;
    task.set_wake_up_sigs(!old_mask);
    let accept_sk = socket_file.sk.accept().await?;
    task.set_running();
    log::info!("get accept correct");
    let peer_addr_endpoint = accept_sk.peer_addr().unwrap();
    let peer_addr = SockAddr::from_endpoint(peer_addr_endpoint);
    // log::info!("Accept a connection from {:?}", peer_addr);
    // write to pointer
   sockaddr_writer(task,addr, addr_len, peer_addr)?;

    let accept_socket = Arc::new(socket::Socket::from_another(&socket_file, Sock::TCP(accept_sk)));
    let fd_info = FdInfo {
        file: accept_socket,
        flags: OpenFlags::empty().into(),
    };
    let new_fd = task.with_mut_fd_table(|t|t.alloc_fd())?;
    task.with_mut_fd_table(|t| {
        t.put_file(new_fd, fd_info)
    })?;
    Ok(new_fd as isize)
}

/// The system calls send(), sendto(), and sendmsg() are used to
/// transmit a message to another socket.
pub async fn sys_sendto(
    fd: usize,
    buf: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addr_len: usize,
)-> SysResult {
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    // log::info!("addr is {}, addr_len is {}", addr, addr_len);
    let task = current_task().unwrap().clone();
    let buf_slice = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, len)
    };
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    task.set_interruptable();
    let bytes = match socket_file.sk_type {
        SocketType::DGRAM => {
            let remote_addr = if addr != 0 {  Some(sockaddr_reader(addr, addr_len, &task)?
            .into_endpoint())}else {
                None
            };
            socket_file.sk.send(&buf_slice, remote_addr).await?    
        }
        SocketType::STREAM => {
            if addr != 0 {
                return Err(SysError::EISCONN);
            }
            socket_file.sk.send(&buf_slice, None).await?
        },
        _ => todo!(),
    };
    task.set_running();
    Ok(bytes as isize)
}

/// The recvfrom() function shall receive a message from a connection-
/// mode or connectionless-mode socket. It is normally used with
/// connectionless-mode sockets because it permits the application to
/// retrieve the source address of received data.
pub async fn sys_recvfrom(
    sockfd: usize,
    buf: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> SysResult {
    if (sockfd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    // log::info!("sys_recvfrom sockfd: {}, buf: {:#x}, len: {}, flags: {:#x}, addr: {:#x}, addrlen: {}", sockfd, buf, len, _flags, addr, addrlen);
    let task = current_task().unwrap().clone();
    let socket_file = task.with_fd_table(|table| {
        table.get_file(sockfd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    let mut inner_vec = Vec::with_capacity(len);
    unsafe {
        inner_vec.set_len(len);
    }
    task.set_interruptable();
    let (bytes, remote_endpoint) = socket_file.sk.recv(&mut inner_vec).await?;
    // log::info!("recvfrom: bytes: {}, remote_endpoint: {:?}", bytes, remote_endpoint);
    let remote_addr = SockAddr::from_endpoint(remote_endpoint);
    task.set_running();
    // write to pointer
    // log::info!("now set running");
    let buf_slice = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, bytes)
    };
    buf_slice[..bytes].copy_from_slice(&inner_vec[..bytes]);
    // write to sockaddr_in
    if addr == 0 {
        return Ok(bytes as isize);  
    }
    
    sockaddr_writer(&task,addr, addrlen, remote_addr)?;
    // log::info!("now return bytes: {}",bytes);
    Ok(bytes as isize)
}
/// Returns the local address of the Socket corresponding to `sockfd`.
pub fn sys_getsockname(fd: usize, addr: usize, addr_len: usize) -> SysResult {
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    log::info!("sys_getsockname fd: {}, addr: {:#x}, addr_len: {}", fd, addr, addr_len);
    let task = current_task().unwrap();
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    let local_addr = socket_file.sk.local_addr()?;
    // log::info!("Get local address of socket: {:?}", local_addr);
    // write to pointer
    sockaddr_writer(&task, addr, addr_len, local_addr)?;
    Ok(0)
}

/// returns the peer address of the socket corresponding to the file descriptor `sockfd`
pub fn sys_getpeername(fd: usize, addr: usize, addr_len: usize) -> SysResult {
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    let task = current_task().unwrap();
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    let peer_addr = socket_file.sk.peer_addr().unwrap();
    log::info!("Get peer address of socket: {:?}", peer_addr);
    // write to pointer
    sockaddr_writer(task,addr, addr_len, peer_addr)?;
    Ok(0)
}
#[allow(missing_docs)]
pub enum SocketLevel {
    /// Dummy protocol for TCP
    IpprotoIp = 0,
    /// S
    SolSocket = 1,
    IpprotoTcp = 6,
    /// IPv6-in-IPv4 tunnelling
    IpprotoIpv6 = 41,
}

impl TryFrom<usize> for SocketLevel {
    type Error = SysError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SocketLevel::IpprotoIp),
            1 => Ok(SocketLevel::SolSocket),
            6 => Ok(SocketLevel::IpprotoTcp),
            41 => Ok(SocketLevel::IpprotoIpv6),
            _ => Err(SysError::EINVAL),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(missing_docs)]
pub enum SocketOption {
    DEBUG = 1,
    REUSEADDR = 2,
    TYPE = 3,
    ERROR = 4,
    DONTROUTE = 5,
    BROADCAST = 6,
    SNDBUF = 7,
    RCVBUF = 8,
    KEEPALIVE = 9,
    OOBINLINE = 10,
    NoCheck = 11,
    PRIORITY = 12,
    LINGER = 13,
    BSDCOMPAT = 14,
    REUSEPORT = 15,
    PASSCRED = 16,
    PEERCRED = 17,
    RCVLOWAT = 18,
    SNDLOWAT = 19,
    RcvtimeoOld = 20,
    SndtimeoOld = 21,
    SecurityAuthentication = 22,
    SecurityEncryptionTransport = 23,
    SecurityEncryptionNetwork = 24,
    BINDTODEVICE = 25,
    AttachFilter = 26,
    DetachFilter = 27,
    SNDBUFFORCE = 32,
    RCVBUFFORCE = 33,
}

impl TryFrom<usize> for SocketOption {
    type Error = SysError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SocketOption::DEBUG),
            2 => Ok(SocketOption::REUSEADDR),
            3 => Ok(SocketOption::TYPE),
            4 => Ok(SocketOption::ERROR),
            5 => Ok(SocketOption::DONTROUTE),
            6 => Ok(SocketOption::BROADCAST),
            7 => Ok(SocketOption::SNDBUF),
            8 => Ok(SocketOption::RCVBUF),
            9 => Ok(SocketOption::KEEPALIVE),
            10 => Ok(SocketOption::OOBINLINE),
            11 => Ok(SocketOption::NoCheck),
            12 => Ok(SocketOption::PRIORITY),
            13 => Ok(SocketOption::LINGER),
            14 => Ok(SocketOption::BSDCOMPAT),
            15 => Ok(SocketOption::REUSEPORT),
            16 => Ok(SocketOption::PASSCRED),
            17 => Ok(SocketOption::PEERCRED),
            18 => Ok(SocketOption::RCVLOWAT),
            19 => Ok(SocketOption::SNDLOWAT),  
            20 => Ok(Self::RcvtimeoOld),
            21 => Ok(Self::SndtimeoOld),
            22 => Ok(Self::SecurityAuthentication),
            23 => Ok(Self::SecurityEncryptionTransport),
            24 => Ok(Self::SecurityEncryptionNetwork),
            25 => Ok(Self::BINDTODEVICE),
            26 => Ok(Self::AttachFilter),
            27 => Ok(Self::DetachFilter),
            32 => Ok(Self::SNDBUFFORCE),
            33 => Ok(Self::RCVBUFFORCE), 
            opt => {
                log::warn!("[SocketOpt] unsupported option: {opt}");
                Ok(Self::DEBUG)
                // Err(Self::Error::EINVAL)
            }
        }
    }
}

#[derive(Debug,PartialEq,Eq,Clone,Copy)]
#[allow(missing_docs)]
pub enum TcpSocketOption {
    NODELAY = 1, // disable nagle algorithm and flush
    MAXSEG = 2,
    INFO = 11,
    CONGESTION = 13,
}

impl TryFrom<usize> for TcpSocketOption {
    type Error = SysError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TcpSocketOption::NODELAY),
            2 => Ok(TcpSocketOption::MAXSEG),
            11 => Ok(TcpSocketOption::INFO),
            13 => Ok(TcpSocketOption::CONGESTION),
            opt => {
                log::warn!("[TcpSocketOpt] unsupported option: {opt}");
                Err(Self::Error::EINVAL)
            }
        }
    }
}
// ============================== 
/// socket configure interface for user
/// level: protocel level at which the option resides,
/// option name
pub fn sys_setsockopt  (
    _fd: usize,
    _level: usize,
    _option_name: usize,
    _option_value: usize,
    _option_len: usize,
) -> SysResult {
    Ok(0)
}
/// get socket configure interface for user
pub fn sys_getsockopt (
    _fd: usize,
    level: usize,
    option_name: usize,
    option_value: usize,
    option_len: usize,
) -> SysResult {
    fn write_string_to_ptr(mut optval_ptr: *mut u8, str:&str) {
        let c_str = CString::new(str).expect("CString::new failed");
        let bytes = c_str.as_bytes();
        for byte in bytes {
            unsafe {
                optval_ptr.write(*byte);
                optval_ptr = optval_ptr.offset(1);
            }
        }
        unsafe {
            optval_ptr.write(0);
        }
    }
    match SocketLevel::try_from(level)? {
        SocketLevel::SolSocket => {
            const SEND_BUFFER_SIZE: usize = 64 * 1024; // 64KB
            const RECV_BUFFER_SIZE: usize = 64 * 1024; // 64KB
            match SocketOption::try_from(option_name)?{
                SocketOption::SNDBUF => {
                    let optval_ptr = option_value as *mut u32;
                    let optlen_ptr = option_len as *mut u32;
                    unsafe {
                        optval_ptr.write_volatile(SEND_BUFFER_SIZE as u32);
                        optlen_ptr.write_volatile(size_of::<u32>() as u32);
                    }
                },
                SocketOption::RCVBUF => {
                    let optval_ptr = option_value as *mut u32;
                    let optlen_ptr = option_len as *mut u32;
                    unsafe {
                        optval_ptr.write_volatile(RECV_BUFFER_SIZE as u32);
                        optlen_ptr.write_volatile(size_of::<u32>() as u32);
                    }
                },
                SocketOption::ERROR => {
                    let optval_ptr = option_value as *mut u32;
                    let optlen_ptr = option_len as *mut u32;
                    unsafe {
                        optval_ptr.write_volatile(0 as u32);
                        optlen_ptr.write_volatile(size_of::<u32>() as u32);
                    }
                }
                _ =>{
                    todo!()
                } 
            }
        },
        SocketLevel::IpprotoTcp | SocketLevel::IpprotoIp  => {
            const MAX_SEGMENT: usize = 1460; // 1460 byte susually MTU
            let optlen_ptr = option_len as *mut u32;
            match TcpSocketOption::try_from(option_name)? {
                TcpSocketOption::NODELAY => {
                    unsafe {
                        let optval_ptr = option_value as *mut u32;
                        optval_ptr.write_volatile(0 as u32);
                        optlen_ptr.write_volatile(size_of::<u32>() as u32);
                    }
                },
                TcpSocketOption::MAXSEG => {
                    unsafe {
                        let optval_ptr = option_value as *mut u32;
                        optval_ptr.write_volatile(MAX_SEGMENT as u32);
                        optlen_ptr.write_volatile(size_of::<u32>() as u32);
                    } 
                },
                TcpSocketOption::INFO => {},
                TcpSocketOption::CONGESTION => {
                    log::warn!("[sys_getsockopt], TcpSocketOption::CONGESTION");
                    unsafe {
                        let str = "reno";
                        let optval_ptr = option_value as *mut u8;
                        write_string_to_ptr(optval_ptr, str);
                        optlen_ptr.write_volatile(4);
                    }
                },
            }
        },
        SocketLevel::IpprotoIpv6 => {},
    }
    Ok(0)
}

/// sys_shutdown() allows a greater control over the behaviour of connection-oriented sockets.
/// todo : how used for indicate read is shut down, write is shut down, or both 
pub fn sys_shutdown(fd: usize, how: usize) -> SysResult {
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    let task = current_task().unwrap();
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    socket_file.sk.shutdown(how as u8)?;
    log::info!("shutdown: fd: {}, how: {}", fd, how);
    Ok(0)
}
/// create a pair of connected sockets
pub fn sys_socketpair(_domain: usize, _types: usize, _protocol: usize, sv: usize) -> SysResult {
    let task = current_task().unwrap();
    let (pipe_read, pipe_write) = pipefs::make_pipe(PAGE_SIZE);
    let pipe = task.with_mut_fd_table(|table| {
        let fd_read = table.alloc_fd()?;
        let fd_info_read = FdInfo {
            file: pipe_read,
            flags: FdFlags::empty(),
        };
        table.put_file(fd_read, fd_info_read)?;
        let fd_write = table.alloc_fd()?;
        let fd_info_write = FdInfo {
            file: pipe_write,
            flags: FdFlags::empty(),    
        };
        table.put_file(fd_write, fd_info_write)?;
        Ok([fd_read as u32, fd_write as u32])
    })?;
    let sv = UserPtrRaw::new(sv as *mut [u32;2])
    .ensure_write(&mut task.get_vm_space().lock())
    .ok_or(SysError::EFAULT)?;
    sv.write(pipe);
    Ok(0)
}

/// msghdr structure for recvmsg() and sendmsg() system calls
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MsgHdr {
    /// ptr points to peer address
    pub msg_name: usize,
    /// addr len
    pub msg_namelen: u32,
    /// iovecs ptr
    pub msg_iov: usize,
    /// iovecs len
    pub msg_iovlen: u32,
    /// ancillary data ptr
    pub msg_control: usize,
    /// ancillary data len
    pub msg_controllen: u32,
    /// flags
    pub msg_flags: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
/// accillary data object information for recvmsg() and sendmsg() system calls
pub struct CmsgHdr {
    /// level
    pub cmsg_level: u32,
    /// type
    pub cmsg_type: u32,
    /// data len
    pub cmsg_len: u32,
}
/// send a message through a connection-mode or connectionless-mode socket. 
pub async fn sys_sendmsg(
    fd: usize,
    msg: usize,
    flags: usize,
)-> SysResult {
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    let task = current_task().unwrap();
    if flags != 0 {
        log::warn!("unsupported flags: {}", flags);
    }
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    // let msg_ptr = msg as *const MsgHdr;
    // let msg = unsafe { msg_ptr.read() };
    let msg = *UserPtrRaw::new(msg as *const MsgHdr)
        .ensure_read(&mut task.get_vm_space().lock())
        .ok_or(SysError::EFAULT)?
        .to_ref();
    if msg.msg_controllen != 0 {
        log::warn!("unsupported control data");
    }
    let addr = sockaddr_reader(msg.msg_name, msg.msg_namelen as usize, task)?
        .into_endpoint();
    // let addr = match SaFamily::try_from(unsafe {
    //     Instruction::set_sum();
    //     *(msg.msg_name as *const u16)
    // })? {
    //     SaFamily::AfInet => {
    //         if msg.msg_namelen < mem::size_of::<SockAddrIn4>() as u32 {
    //             log::error!("[sendmsg] invalid address length: {}", msg.msg_namelen);
    //             return Err(SysError::EINVAL);
    //         }
    //         Ok(SockAddr{
    //             ipv4: unsafe { *(msg.msg_name as *const SockAddrIn4) },
    //         }.into_endpoint())
    //     },
    //     SaFamily::AfInet6 => {
    //         if msg.msg_namelen < mem::size_of::<SockAddrIn6>() as u32 {
    //             log::error!("[sendmsg] invalid address length: {}", msg.msg_namelen);
    //             return Err(SysError::EINVAL);
    //         }
    //         Ok(SockAddr{
    //             ipv6: unsafe {
    //                 *(msg.msg_name as *const SockAddrIn6)
    //             }
    //         }.into_endpoint())
    //     },
    //     SaFamily::AfUnix => {
    //         if msg.msg_namelen < mem::size_of::<SockAddrUn>() as u32 {
    //             log::error!("[sendmsg] invalid address length: {}", msg.msg_namelen);
    //             return Err(SysError::EINVAL);
    //         }
    //         Ok(SockAddr{
    //             ipv6: unsafe {
    //                 *(msg.msg_name as *const _)
    //             }
    //         }.into_endpoint())
    //     },
    //     _ => todo!()
    // }?;
    // let iovs = unsafe {
    //     Instruction::set_sum();
    //     core::slice::from_raw_parts(msg.msg_iov as *const IoVec, msg.msg_iovlen as usize)
    // };
    let iovs_slice = UserSliceRaw::new(msg.msg_iov as *const IoVec, msg.msg_iovlen as usize)
        .ensure_read(&mut task.get_vm_space().lock())
        .ok_or(SysError::EFAULT)?;
    let iovs = iovs_slice.to_ref();
    let mut total_len = 0;
    for (_i, iov) in iovs.iter().enumerate() {
        if iov.len == 0 {
            continue;
        }
        let ptr = iov.base as *const u8;
        // let buf_slice = unsafe {
        //     core::slice::from_raw_parts(ptr, iov.len as usize)
        // };
        let buf_slice = UserSliceRaw::new(ptr, iov.len as usize)
            .ensure_read(&mut task.get_vm_space().lock())
            .ok_or(SysError::EFAULT)?;
        let buf_slice = buf_slice.to_ref();
        let send_len = socket_file.sk.send(buf_slice, Some(addr)).await?;
        total_len += send_len;
    }
    Ok(total_len as isize)
}

/// receive a message from a connection-mode or connectionless-mode socket.
pub async fn sys_recvmsg(
    fd: usize,
    msg: usize,
    flags: usize,
) -> SysResult {
    log::warn!("[sys_recvmsg] into sys_recvmsg");
    if (fd as isize) < 0 {
        return Err(SysError::EBADF);
    }
    if flags != 0 {
        log::warn!("unsupported flags: {}", flags);
    }
    let task = current_task().unwrap();
    let socket_file = task.with_fd_table(|table| {
        table.get_file(fd)})?
        .downcast_arc::<socket::Socket>()
        .map_err(|_| SysError::ENOTSOCK)?;
    let inner_msg = *UserPtrRaw::new(msg as *const MsgHdr)
        .ensure_read(&mut task.get_vm_space().lock())
        .ok_or(SysError::EFAULT)?
        .to_ref();
    if inner_msg.msg_controllen != 0 {
        log::warn!("unsupported control data");
    }
    // let iovs = unsafe {
    //     Instruction::set_sum();
    //     core::slice::from_raw_parts(inner_msg.msg_iov as *const IoVec, inner_msg.msg_iovlen as usize)
    // };
    let iovs_slice = UserSliceRaw::new(inner_msg.msg_iov as *const IoVec, inner_msg.msg_iovlen as usize)
        .ensure_read(&mut task.get_vm_space().lock())
        .ok_or(SysError::EFAULT)?;
    let iovs = iovs_slice.to_ref();
    let mut tmp_buf = vec![0u8; 64 * 1024];
    let (recv_len,src_addr) = socket_file.sk.recv(&mut tmp_buf).await?;
    let mut copied = 0;
    let data = tmp_buf[..recv_len].to_vec();
    for iov in iovs {
        if copied >= recv_len {
            break;
        }
        let to_copy = (iov.len as usize).min(recv_len - copied);
        let dst = iov.base as *mut u8;
        unsafe  {
            core::ptr::copy_nonoverlapping(data[copied..].as_ptr(), dst, to_copy)
        };
        copied += to_copy;
    }

    if inner_msg.msg_name != 0 {
        let addr = SockAddr::from_endpoint(src_addr);
        // unsafe {
        //     match SaFamily::try_from(addr.family)? {
        //         SaFamily::AfInet => {
        //             let addr_ptr = inner_msg.msg_name as *mut SockAddrIn4;
        //             addr_ptr.write_volatile(addr.ipv4);
        //             let addr_len_ptr = inner_msg.msg_namelen as *mut u32;
        //             addr_len_ptr.write_volatile(size_of::<SockAddrIn4>() as u32);
        //         },
        //         SaFamily::AfInet6 => {
        //             let addr_ptr = inner_msg.msg_name as *mut SockAddrIn6;
        //             addr_ptr.write_volatile(addr.ipv6);
        //             let addr_len_ptr = inner_msg.msg_namelen as *mut u32;
        //             addr_len_ptr.write_volatile(size_of::<SockAddrIn6>() as u32);
        //         },
        //         SaFamily::AfUnix => {
        //             let addr_ptr = inner_msg.msg_name as *mut SockAddrUn;
        //             addr_ptr.write_volatile(addr.unix);
        //             let addr_len_ptr = inner_msg.msg_namelen as *mut u32;
        //             addr_len_ptr.write_volatile(size_of::<SockAddrUn>() as u32);
        //         },
        //         _ => todo!()
        //     }
        // }
        sockaddr_writer(task, inner_msg.msg_name, inner_msg.msg_namelen as usize, addr)?;
    }      
    Ok(copied as isize)
}

pub fn sockaddr_reader(addr: usize, addr_len: usize, task: &Arc<TaskControlBlock>) -> Result<SockAddr, SysError> {
    if addr == 0 {
        return Err(SysError::EFAULT);
    }
    // 先只读前两个字节拿到 family。
    // 注意：SockAddr 是 union，sizeof 等于最大的 SockAddrUn（110 字节）。
    // 若直接按 union 大小去读，会把用户 16 字节的 sockaddr_in 之后的内存一并读进来
    // （越界读，缓冲区正好在页尾时还会误报 EFAULT）。所以先读 family，再按类型读。
    let family_raw = unsafe {
        *(UserPtrRaw::new(addr as *const u16)
            .ensure_read(&mut task.get_vm_space().lock())
            .ok_or(SysError::EFAULT)?)
        .to_ref()
    };
    let family = SaFamily::try_from(family_raw)?;
    log::info!("[sockaddr_reader] family: {:?}, addr_len: {}", family, addr_len);
    match family {
        SaFamily::AfInet => {
            if addr_len < size_of::<SockAddrIn4>() {
                return Err(SysError::EINVAL);
            }
            let sin = unsafe {
                *(UserPtrRaw::new(addr as *const SockAddrIn4)
                    .ensure_read(&mut task.get_vm_space().lock())
                    .ok_or(SysError::EFAULT)?)
                .to_ref()
            };
            Ok(SockAddr { ipv4: sin })
        }
        SaFamily::AfInet6 => {
            if addr_len < size_of::<SockAddrIn6>() {
                return Err(SysError::EINVAL);
            }
            let sin6 = unsafe {
                *(UserPtrRaw::new(addr as *const SockAddrIn6)
                    .ensure_read(&mut task.get_vm_space().lock())
                    .ok_or(SysError::EFAULT)?)
                .to_ref()
            };
            Ok(SockAddr { ipv6: sin6 })
        },
        SaFamily::AfUnix => {
            if addr_len < size_of::<SockAddrUn>() {
                log::info!("in this, size of SockAddrUn: {}",size_of::<SockAddrUn>());
                return Err(SysError::EINVAL);
            }
            let sun = unsafe {
                *(UserPtrRaw::new(addr as *const SockAddrUn)
                    .ensure_read(&mut task.get_vm_space().lock())
                    .ok_or(SysError::EFAULT)?)
                .to_ref()
            };
            Ok(SockAddr { unix: sun })
        },
        _ => Err(SysError::EAFNOSUPPORT)
    }
}

pub fn sockaddr_writer(task: &Arc<TaskControlBlock>, addr: usize, addr_len: usize, sock_addr: SockAddr) -> SockResult<()>{
    if addr == 0 {
        return Err(SysError::EFAULT);
    }
    // Linux 语义：*addr_len 是入参（用户缓冲区大小）+ 出参（回写实际结构体长度）
    let len_ptr = UserPtrRaw::new(addr_len as *const u32)
        .ensure_write(&mut task.get_vm_space().lock())
        .ok_or(SysError::EFAULT)?;
    let user_len = unsafe { *len_ptr.to_ref() } as usize;

    // 修复：SockAddr 是 union，sizeof 等于最大的 SockAddrUn（110 字节）。
    // 之前无条件 `write(sock_addr)` 会把整个 union 写回用户缓冲区，
    // 在用户只提供 16 字节 struct sockaddr_in 时溢出 94 字节，
    // 直接踩坏用户栈（libctest 的 socket 用例里被覆盖的正是 buf[0]），
    // 同时把内核栈上的残留字节泄露给用户态。
    // 这里先按 family 序列化出精确大小，再按 min(*addr_len, size) 拷出。
    let mut tmp = [0u8; size_of::<SockAddrUn>()];
    let size = unsafe {
        match SaFamily::try_from(sock_addr.family)? {
            SaFamily::AfInet => {
                let v = sock_addr.ipv4;
                let n = size_of::<SockAddrIn4>();
                tmp[..n].copy_from_slice(core::slice::from_raw_parts(
                    &v as *const SockAddrIn4 as *const u8, n));
                n
            }
            SaFamily::AfInet6 => {
                let v = sock_addr.ipv6;
                let n = size_of::<SockAddrIn6>();
                tmp[..n].copy_from_slice(core::slice::from_raw_parts(
                    &v as *const SockAddrIn6 as *const u8, n));
                n
            },
            SaFamily::AfUnix => {
                let v = sock_addr.unix;
                let n = size_of::<SockAddrUn>();
                tmp[..n].copy_from_slice(core::slice::from_raw_parts(
                    &v as *const SockAddrUn as *const u8, n));
                n
            },
            _ => return Err(SysError::EAFNOSUPPORT)
        }
    };
    let copy_len = if user_len < size { user_len } else { size };
    if copy_len > 0 {
        unsafe {
            let out = UserSliceRaw::new(addr as *const u8, copy_len)
                .ensure_write(&mut task.get_vm_space().lock())
                .ok_or(SysError::EFAULT)?;
            out.to_mut().copy_from_slice(&tmp[..copy_len]);
        }
    }
    unsafe {
        len_ptr.write(size as u32);
    }
    Ok(())
}

