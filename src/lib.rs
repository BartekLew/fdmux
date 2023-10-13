extern crate libc;
extern crate termios;

use libc::{poll,pollfd,POLLIN,read,unlink,close,mkfifo,
           open,O_RDWR,c_void,posix_openpt, O_NOCTTY,
           grantpt, unlockpt, ptsname, fork, setsid,
           dup2, execvp, write, pid_t, kill, SIGKILL,
           ioctl, TIOCSCTTY, fsync, POLLHUP, pipe, waitpid };
use termios::*;
use std::os::unix::prelude::{RawFd, AsRawFd};
use std::io::{Error,ErrorKind, Stdin, Write, Read};
use std::mem;

type CStr = *const i8;

#[derive(Debug)]
pub enum StreamEvent {
    Eof, Interrupt, TermStop, Error(String)
}

pub type Fd = i32;
pub trait Muxable {
    fn get_fds(&self) -> Vec<Fd>;
    fn read_str(&mut self, fd: i32) -> Result<Vec<u8>, StreamEvent>;
}

pub struct NamedReadPipe {
    pub fd: RawFd,
    pub name: String
}

impl NamedReadPipe {
    pub fn new(name: String) -> Result<Self,StreamEvent> {
        unsafe {
            unlink(name.as_ptr() as *const i8);
            let ret = mkfifo(name.as_ptr() as *const i8, 0o666);
            if ret == 0 {
                // I use RDWR, because opening in O_RDONLY would block
                // on open until someone open another end of pipe.
                let fd = open(name.as_ptr() as *const i8, O_RDWR);
                if fd > 0 {
                    return Ok(NamedReadPipe{fd: fd, name: name});
                }
            }
    
            return Err(StreamEvent::Error("Can't open fifo".to_string()));
        }
    }
}

impl Muxable for NamedReadPipe {
    fn get_fds(&self) -> Vec<i32> { vec![self.fd] }
    fn read_str(&mut self, _: i32) -> Result<Vec<u8>, StreamEvent> {
        let mut buff: [u8;1024] = [0;1024];
        unsafe {
            let n = read(self.fd, buff.as_mut_ptr() as *mut c_void, buff.len());
            if n > 0 {
                return Ok(Vec::from(&buff[0..n as usize]));
            }
            return Err(StreamEvent::Error("Can't read named pipe".to_string()));
        }
    }
}

pub struct NamedWritePipe {
    pub fd: RawFd,
    pub name: String
}

impl NamedWritePipe {
    pub fn new(name: String) -> Result<Self,StreamEvent> {
        unsafe {
            let cs = format!("{}\0", name);
            let csptr = cs.as_bytes().as_ptr() as CStr;

            unlink(csptr);
            let ret = mkfifo(csptr, 0o666);
            if ret == 0 {
                // I use RDWR, because opening in O_RDONLY would block
                // on open until someone open another end of pipe.
                let fd = open(csptr, O_RDWR);
                if fd > 0 {
                    return Ok(NamedWritePipe{fd: fd, name: name});
                }
            }
    
            return Err(StreamEvent::Error("Can't open fifo".to_string()));
        }
    }
}

impl Write for NamedWritePipe {
    fn write(&mut self, buff: &[u8]) -> Result<usize, Error> {
        unsafe {
            let n = write(self.fd, buff.as_ptr() as *const c_void, buff.len());
            if n >= 0 {
                Ok(n as usize)
            } else {
                Err(Error::new(ErrorKind::Other, format!("Can't write to {}", self.name)))
            }
        }
    }
    
    fn flush(&mut self) -> Result<(), Error> {
        if unsafe { fsync(self.fd) } == 0 {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "Can't fsync"))
        }
    }
}
impl Muxable for std::io::Stdin {
    fn get_fds(&self) -> Vec<i32> { vec![0] }
    fn read_str(&mut self, _:i32) -> Result<Vec<u8>, StreamEvent> {
        let mut buff: [u8; 256] = [0;256];
        match self.read(&mut buff) {
            Ok(n) => Ok(Vec::from(&buff[0..n])),
            Err(e) => Err(StreamEvent::Error(e.to_string()))
        }
    }
}

impl Drop for NamedReadPipe {
    fn drop(&mut self) {
        unsafe {
            unlink(self.name.as_bytes().as_ptr() as *const i8);
            close(self.fd);
        }
    }
}

extern "C" {
    fn signalfd(fd: i32, mask: *const i64, flags: i32) -> i32;
    fn sigemptyset(mask: *mut i64) -> i32;
    fn sigaddset(mask: *mut i64, sig: i32) -> i32;
    fn sigprocmask(how: i32, mask: *const i64, oldmask: *mut i32) -> i32;
}

#[repr(C)]
struct SigInfo {
    signo: i32,
    _errno: i32,
    sigcode: i32,
    _pid: u32,
    _uid: u32,
    _fd: i32,        // for SIGIO
    _tid: u32,       // Kernel Timer ID
    _band: u32,      // for SIGIO
    _overrun: u32,   // For timers
    _trapno: u32,
    _child_exit: i32,     // SIGCHLD
    _int : i32,           // sigqueue(3)
    _ptr : u64,           // sigqueue(3)
    _child_utime : u64,   // SIGCHLD
    _child_stime : u64,
    _padding : [u8; 56]  // Pad to 128 bytes for future fields
}

pub struct SigMask {
    mask: i64
}

const NULL : *mut i32 = 0 as *mut i32;
const SIG_BLOCK : i32 = 0;
const SIGINT : i32 = 2;
const SIGTSTP : i32 = 20;

impl SigMask {
    fn new() -> Self {
        let mut mask : i64 = 0;
        unsafe {
            sigemptyset(&mut mask);
            SigMask { mask }
        }
    }

    fn add(mut self, signal: i32) -> Self {
        unsafe {
            sigaddset(&mut self.mask, signal);
        }

        self
    }

    fn open(self) -> SigPipe {
        unsafe { 
            if sigprocmask(SIG_BLOCK, &self.mask, NULL) == -1 {
                panic!("Can't block signals {}: {:?}",
                       self.mask, std::io::Error::last_os_error());
            }

            let fd = signalfd(-1, &self.mask, 0);
            if fd < 0 {
                panic!("Can't open signalfd for {} @ {:?}",
                       self.mask, std::io::Error::last_os_error());
            } else {
                SigPipe { fd }
            }
        }
    }
}

struct SigPipe {
    fd: i32
}

impl Muxable for SigPipe {
    fn get_fds(&self) -> Vec<i32> { vec![self.fd] }
    fn read_str(&mut self, _:i32) -> Result<Vec<u8>,StreamEvent> {
        unsafe {
            let mut nfo : SigInfo = mem::zeroed();
            let nfo_ptr = &mut nfo as *mut SigInfo as *mut c_void;
            let n = read(self.fd, nfo_ptr, 128);
            if n < 128 {
                panic!("Wrong read from sigpipe of size {}", n);
            }

            match nfo.signo {
                SIGTSTP => Err(StreamEvent::TermStop),
                SIGINT => Err(StreamEvent::Interrupt),
                _ => { panic!("Unexpected sigcode = {}", nfo.sigcode) }
            }
        }
    }
}

impl Drop for SigPipe {
    fn drop(&mut self) {
        unsafe { close(self.fd); }
    }
}

pub struct EchoPipe <I: Muxable> {
    pub input: I
}

impl<I:Muxable> Muxable for EchoPipe<I> {
    fn get_fds(&self) -> Vec<i32> { self.input.get_fds() }
    fn read_str(&mut self, fd:i32) -> Result<Vec<u8>,StreamEvent> {
        self.input.read_str(fd).map(|s| {
                                print!("{}", String::from(std::str::from_utf8(s.as_ref()).unwrap()));
                                s
                            })
    }
}

pub struct StdinReadKey {
    tos: Termios,
    handle: Stdin,
    sig_stream: SigPipe
}

impl StdinReadKey {
    pub fn new() -> Self {
        let handle = std::io::stdin();
        let mut tos = Termios::from_fd(handle.as_raw_fd())
                              .expect("This program can't be piped");
        tos.c_lflag &= !(ECHO | ICANON);
        tcsetattr(handle.as_raw_fd(), TCSAFLUSH, &tos).unwrap();

        StdinReadKey { tos: tos, handle: handle,
                       sig_stream: SigMask::new()
                                          .add(SIGINT)
                                          .add(SIGTSTP)
                                          .open()}
    }
}

impl Muxable for StdinReadKey {
    fn get_fds(&self) -> Vec<i32> { vec![0, self.sig_stream.fd] }
    fn read_str(&mut self, fd: i32) -> Result<Vec<u8>, StreamEvent> {
        if fd == 0 {
            self.handle.read_str(fd)  
        } else {
            self.sig_stream.read_str(fd)
        }
    }
}

impl Drop for StdinReadKey {
    fn drop(&mut self) {
        self.tos.c_lflag |= ECHO | ICANON;
        tcsetattr(self.handle.as_raw_fd(), TCSAFLUSH, &self.tos).unwrap();
    }
}

#[derive(Clone)]
pub struct IOPipe {
    fd: RawFd,
    pid: Option<pid_t>
}

impl IOPipe {
    pub fn new(fd: RawFd, pid: Option<pid_t>) -> Self {
        IOPipe { fd: fd, pid: pid }
    }
}

impl Drop for IOPipe {
    fn drop(&mut self) {
        unsafe { close(self.fd); };
        match self.pid {
            Some(pid) => unsafe {
                kill(pid, SIGKILL);
            },
            None => {}
        }
    }
}

impl Muxable for IOPipe {
    fn get_fds(&self) -> Vec<i32> { vec![self.fd] }
    fn read_str(&mut self, _:i32) -> Result<Vec<u8>, StreamEvent> {
        let mut buff: [u8;1024] = [0;1024];
        let n = unsafe { read(self.fd, buff.as_mut_ptr() as *mut c_void, 1024) };
        match n > 0 {
            true => Ok(Vec::from(&buff[0..n as usize])),
            false => Err(StreamEvent::Error("can't read IOPipe".to_string()))
        }
    }
}

impl Write for IOPipe {
    fn write(&mut self, buff: &[u8]) -> Result<usize, Error> {
        let n = unsafe { write(self.fd, buff.as_ptr() as *const c_void, buff.len()) };
        if n >= 0 {
            Ok(n as usize)
        } else {
            Err(Error::new(ErrorKind::Other, "Can't write IOPipe"))
        }
    }

    fn flush(&mut self) -> Result<(), Error> {
        if unsafe { fsync(self.fd) } == 0 {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "Can't fsync"))
        }
    }
}

pub struct Process {
    pid: Option<pid_t>,
    cmdline: Vec<String>,
    redir_in: Option<RawFd>,
    redir_out: Option<RawFd>,
    redir_err: Option<RawFd>
}

impl Process {
    pub fn new<'a>(cmdline: Vec<&'a str>) -> Self {
        Process { pid: None,
                  cmdline: cmdline.iter().map(|s| format!("{}\0", s))
                                  .collect(),
                  redir_in: None, 
                  redir_out: None, redir_err: None }
    }

    pub fn push_arg(mut self, arg: String) -> Self {
        self.cmdline.push(format!("{}\0", arg));
        self
    }

    pub fn with_in(mut self, inp: RawFd) -> Self {
        self.redir_in = Some(inp);
        self
    }

    pub fn with_out(mut self, out: RawFd) -> Self {
        self.redir_out = Some(out);
        self
    }

    pub fn with_err(mut self, err: RawFd) -> Self {
        self.redir_err = Some(err);
        self
    }
    
    pub fn spawn(mut self) -> Result<Self, String> {
        let pid = unsafe { fork() };
        if pid < 0 { return Err("Can't fork()".to_string()); }

        if pid > 0 {
            self.pid = Some(pid);
            Ok(self)
        } else {
            unsafe {
                self.redir_in.map(|fd| dup2(fd, 0));
                self.redir_out.map(|fd| dup2(fd, 1));
                self.redir_err.map(|fd| dup2(fd, 2));

                let mut cargs : Vec<*const i8> =
                    self.cmdline.iter().map(|str| str.as_ptr() as *const i8)
                                .collect();
                cargs.push(0 as *const i8);

                execvp(self.cmdline[0].as_ptr() as *const i8, cargs.as_ptr() as *const *const i8);
                Err("execvp() returned".to_string())
            }
        }
    }

    pub fn wait(self) -> i32 {
        unsafe {
            let mut status: i32 = 0;
            waitpid(self.pid.unwrap(), &mut status as *mut i32, 0);
            status
        }
    }
}

pub struct Pipe {
    pub inp: RawFd,
    pub out: RawFd
}

impl Pipe {
    pub fn new() -> Result<Self,String> {
        unsafe {
            let mut fds : [i32;2] = [ -1, -1 ];
            match pipe(fds.as_mut_ptr()) {
                -1 => Err("Can't pipe()".to_string()),
                _ => Ok(Pipe { inp: fds[0], out: fds[1] })
            }
        }
    }
}

pub struct Pty {
    host: RawFd,
    guest: RawFd
}

impl Pty {
    pub fn new() -> Option<Self> {
        unsafe {
            let host = posix_openpt(O_RDWR | O_NOCTTY);
            if host > 0 && grantpt(host) == 0 && unlockpt(host) == 0 {
                let guestname = ptsname(host);
                if guestname as usize > 0 {
                    let guest = open(guestname, O_RDWR);
                    if guest > 0 {
                        return Some(Pty { host: host,
                                          guest: guest });
                    }
                }
            }
            return None;
        }
    }

    pub fn spawn<'a>(self, args: Vec<&'a str>, out: Option<NamedWritePipe>) -> Result<IOPipe, String> {
        unsafe {
            setsid();
            ioctl(self.guest, TIOCSCTTY, 0 as *const c_void);
    
            let proc = Process::new(args)
                               .with_in(self.guest)
                               .with_out(out.map(|o| o.fd).unwrap_or(self.guest))
                               .with_err(self.guest)
                               .spawn();

            proc.map(|p| IOPipe::new(self.host, p.pid))
        }
    }
}

pub trait DoCtrlD: Write {
    fn ctrl_d(&mut self) -> bool;
}

impl DoCtrlD for std::io::Stdout {
    fn ctrl_d(&mut self) -> bool {
        false
    }
}

impl DoCtrlD for IOPipe {
    fn ctrl_d(&mut self) -> bool {
        let sig = [0x04 as u8];
        self.write(&sig).unwrap();
        true
    }
}

pub struct MultiSource {
    sources: Vec<Box<dyn Muxable>>
}

impl MultiSource {
    pub fn new(size: usize) -> Self {
        MultiSource { sources: Vec::with_capacity(size) }
    }

    pub fn add(mut self, source: Box<dyn Muxable>) -> Self {
        self.sources.push(source);
        self
    }
}

impl Muxable for MultiSource {
    fn get_fds(&self) -> Vec<i32> {
        self.sources.iter()
                    .flat_map(|s| s.get_fds())
                    .collect()
    }

    fn read_str(&mut self, fd:i32) -> Result<Vec<u8>,StreamEvent> {
        for s in &mut self.sources {
            for srcfd in s.get_fds() {
                if fd == srcfd {
                    return s.read_str(fd);
                }
            }
        }

        Err(StreamEvent::Error(format!("Unexpected MultiSource Error: wrong fd {}", fd)))
    }
}

pub struct Destination<'a> {
    writer: &'a mut dyn DoCtrlD,
    sources: Vec<&'a mut dyn Muxable>
}

impl <'a> Destination<'a> {
    pub fn new(writer: &'a mut dyn DoCtrlD, sources: Vec<&'a mut dyn Muxable>) -> Self {
        Destination { writer: writer, sources: sources }
    }
}

pub fn read_into<'a>(i: &mut dyn Muxable, fd: i32, o: &mut dyn DoCtrlD) -> Result<(), StreamEvent> {
    match i.read_str(fd) {
        Ok(s) => match o.write(s.as_ref()).map(|_| o.flush()) {
                    Ok(_) => Ok (()),
                    Err(_) => Err(StreamEvent::Error("Can't write".to_string()))
                 },
        Err(e) => Err(e)
    }
}

pub struct Topology<'a> {
    destinations: Vec<Destination<'a>>,
    pollstruct: Vec<pollfd>
}

impl<'a> Topology<'a> {
    pub fn new(size: usize) -> Self {
        Topology { destinations: Vec::with_capacity(size),
                   pollstruct: Vec::with_capacity(size) }
    }

    pub fn add(mut self, dest: Destination<'a>) -> Self {
        dest.sources
            .iter()
            .for_each(|src| src.get_fds()
                               .iter()
                               .for_each(|fd| self.pollstruct.push(pollfd {
                                                 fd: *fd,
                                                 events: POLLIN,
                                                 revents: 0 })));
        self.destinations.push(dest);
        self
    }

    pub fn insert(&mut self, dest: Destination<'a>) {
        dest.sources
            .iter()
            .for_each(|src| src.get_fds()
                               .iter()
                               .for_each(|fd| self.pollstruct.push(pollfd {
                                                 fd: *fd,
                                                 events: POLLIN,
                                                 revents: 0 })));
        self.destinations.push(dest);
    }

    pub fn run(mut self) {
        loop {
            self.tick(-1);
        }
    }

    pub fn tick(&mut self, time: i32) {
        unsafe {
            let ret = poll(self.pollstruct.as_mut_ptr(), self.pollstruct.len() as u64, time);
            if ret > 0 {
                let mut i = 0;
                for di in 0..self.destinations.len() {
                    let d = &mut self.destinations[di];
                    for si in 0..d.sources.len() {
                        for _ in d.sources[si].get_fds() {
                            if self.pollstruct[i].revents & POLLIN > 0 {
                                match read_into(d.sources[si], self.pollstruct[i].fd, d.writer) {
                                    Err(StreamEvent::Eof) => {
                                        if !d.writer.ctrl_d() { return; }
                                    },
                                        Err(StreamEvent::Error(e)) => panic!("{}", e),
                                        Err(_) => {},
                                        Ok(()) => {}
                                }
                            } else if self.pollstruct[i].revents & POLLHUP > 0 {
                                return;
                            }

                            i+=1;
                        }
                    }
                }
            }
        }
    }
}

