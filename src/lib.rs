extern crate libc;
extern crate termios;

use libc::{poll,pollfd,POLLIN,read,unlink,close,mkfifo,
           open,O_RDWR,c_void,posix_openpt, O_NOCTTY,
           grantpt, unlockpt, ptsname, fork, setsid,
           dup2, execvp, write, pid_t, kill, SIGKILL,
           ioctl, TIOCSCTTY, fsync, POLLHUP };
use termios::*;
use std::os::unix::prelude::{RawFd, AsRawFd};
use std::io::{Error,ErrorKind, Stdin, Write, Read};

type CStr = *const i8;

#[derive(Debug)]
pub enum StreamEvent {
    Eof, Error(String)
}

pub trait ReadStr {
    fn read_str(&mut self) -> Result<Vec<u8>, StreamEvent>;
}

pub trait Muxable:AsRawFd+ReadStr {}

pub struct NamedReadPipe {
    pub fd: RawFd,
    pub name: String
}

impl NamedReadPipe {
    pub fn new(name: String) -> Result<Self,StreamEvent> {
        let cs = format!("{}\0", name);
        let csptr = cs.as_bytes().as_ptr() as CStr;

        unsafe {
            unlink(csptr);
            let ret = mkfifo(csptr, 0o666);
            if ret == 0 {
                // I use RDWR, because opening in O_RDONLY would block
                // on open until someone open another end of pipe.
                let fd = open(csptr, O_RDWR);
                if fd > 0 {
                    return Ok(NamedReadPipe{fd: fd, name: name});
                }
            }
    
            return Err(StreamEvent::Error("Can't open fifo".to_string()));
        }
    }
}

impl ReadStr for NamedReadPipe {
    fn read_str(&mut self) -> Result<Vec<u8>, StreamEvent> {
        let mut buff: [u8;1024] = [0;1024];
        unsafe {
            let n = read(self.fd, buff.as_mut_ptr() as *mut c_void, buff.len());
            if n >= 0 {
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

impl ReadStr for std::io::Stdin {
    fn read_str(&mut self) -> Result<Vec<u8>, StreamEvent> {
        let mut buff: [u8; 10] = [0;10];
        match self.read(&mut buff) {
            Ok(n) => Ok(Vec::from(&buff[0..n])),
            Err(e) => Err(StreamEvent::Error(e.to_string()))
        }
    }
}

impl Drop for NamedReadPipe {
    fn drop(&mut self) {
        unsafe { 
            unlink(self.name.as_ptr() as *const i8);
            close(self.fd);
        }
    }
}

impl Drop for NamedWritePipe {
    fn drop(&mut self) {
        unsafe { 
            unlink(self.name.as_ptr() as *const i8);
            close(self.fd);
        }
    }
}
impl AsRawFd for NamedReadPipe {
    fn as_raw_fd(&self) -> RawFd { self.fd }
}

impl Muxable for std::io::Stdin {}
impl Muxable for NamedReadPipe {}

pub struct EchoPipe <I: Muxable> {
    pub input: I
}

impl<I:Muxable> AsRawFd for EchoPipe<I> {
    fn as_raw_fd(&self) -> RawFd { self.input.as_raw_fd() }
}

impl<I:Muxable> ReadStr for EchoPipe<I> {
    fn read_str(&mut self) -> Result<Vec<u8>,StreamEvent> {
        self.input.read_str().map(|s| {
                                print!("{}", String::from(std::str::from_utf8(s.as_ref()).unwrap()));
                                s
                            })
    }
}
impl<I: Muxable> Muxable for EchoPipe<I> {}

pub struct StdinReadKey {
    tos: Termios,
    handle: Stdin
}

impl StdinReadKey {
    pub fn new() -> Self {
        let handle = std::io::stdin();
        let mut tos = Termios::from_fd(handle.as_raw_fd())
                              .expect("This program can't be piped");
        tos.c_lflag &= !(ECHO | ICANON);
        tcsetattr(handle.as_raw_fd(), TCSAFLUSH, &tos).unwrap();

        StdinReadKey { tos: tos, handle: handle }
    }
}

impl AsRawFd for StdinReadKey {
    fn as_raw_fd(&self) -> RawFd { self.handle.as_raw_fd() }
}

impl ReadStr for StdinReadKey {
    fn read_str(&mut self) -> Result<Vec<u8>, StreamEvent> {
        self.handle.read_str()  
    }
}

impl Muxable for StdinReadKey {}

impl Drop for StdinReadKey {
    fn drop(&mut self) {
        self.tos.c_lflag |= ECHO | ICANON;
        tcsetattr(self.as_raw_fd(), TCSAFLUSH, &self.tos).unwrap();
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

impl AsRawFd for IOPipe {
    fn as_raw_fd(&self) -> RawFd { self.fd }
}

impl ReadStr for IOPipe {
    fn read_str(&mut self) -> Result<Vec<u8>, StreamEvent> {
        let mut buff: [u8;1024] = [0;1024];
        let n = unsafe { read(self.fd, buff.as_mut_ptr() as *mut c_void, 1024) };
        match n > 0 {
            true => Ok(Vec::from(&buff[0..n as usize])),
            false => Err(StreamEvent::Error("can't read IOPipe".to_string()))
        }
    }
}

impl Muxable for IOPipe {}

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

    pub fn spawn_output(self, args: Vec<String>) -> Result<IOPipe, String> {
        let pid = unsafe { fork() };
        if pid < 0 { return Err("Can't fork()".to_string()); }

        if pid > 0 {
            unsafe { close(self.guest) };
            return Ok(IOPipe::new(self.host, Some(pid)));
        }

        unsafe {
            close(self.host);

            setsid();
            ioctl(self.guest, TIOCSCTTY, 0 as *const c_void);

            dup2(self.guest, 0);
            dup2(self.guest, 1);
            dup2(self.guest, 2);

            close(self.guest);

            let mut cargs : Vec<*const i8> =
                args.iter().map(|str| str.as_ptr() as *const i8)
                           .collect();
            cargs.push(0 as *const i8);

            execvp(args[0].as_ptr() as *const i8, cargs.as_ptr() as *const *const i8);

            return Err("execvp() returned!".to_string());
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

pub struct Destination<'a> {
    writer: &'a mut dyn DoCtrlD,
    sources: Vec<&'a mut dyn Muxable>
}

impl <'a> Destination<'a> {
    pub fn new(writer: &'a mut dyn DoCtrlD, sources: Vec<&'a mut dyn Muxable>) -> Self {
        Destination { writer: writer, sources: sources }
    }
}

pub fn read_into<'a>(i: &mut dyn Muxable, o: &mut dyn DoCtrlD) -> Result<(), StreamEvent> {
    match i.read_str() {
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
        dest.sources.iter()
                    .for_each(|s| self.pollstruct.push(pollfd {
                                                        fd: s.as_raw_fd(),
                                                        events: POLLIN,
                                                        revents: 0 }));
        self.destinations.push(dest);
        self
    }

    pub fn insert(&mut self, dest: Destination<'a>) {
        dest.sources.iter()
                    .for_each(|s| self.pollstruct.push(pollfd {
                                                        fd: s.as_raw_fd(),
                                                        events: POLLIN,
                                                        revents: 0 }));
        self.destinations.push(dest);
    }

    pub fn tick(&mut self, time: i32) {
        unsafe {
            let ret = poll(self.pollstruct.as_mut_ptr(), self.pollstruct.len() as u64, time);
            if ret > 0 {
                let mut i = 0;
                for di in 0..self.destinations.len() {
                    let d = &mut self.destinations[di];
                    for si in 0..d.sources.len() {
                        if self.pollstruct[i].revents & POLLIN > 0 {
                            match read_into(d.sources[si], d.writer) {
                                Err(StreamEvent::Eof) => {
                                    if !d.writer.ctrl_d() { return; }
                                },
                                Err(StreamEvent::Error(e)) => panic!("{}", e),
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

    pub fn run(mut self) {
        loop {
            self.tick(-1);
        }
    }
}

