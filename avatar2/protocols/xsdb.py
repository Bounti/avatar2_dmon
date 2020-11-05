import sys
import subprocess
import telnetlib
import logging
import distutils
from codecs import encode
import binascii
from threading import Thread, Lock, Event
from struct import pack, unpack
from time import sleep
import re
from os.path import abspath
if sys.version_info < (3, 0):
    import Queue as queue
else:
    import queue

from avatar2.targets import TargetStates
from avatar2.message import AvatarMessage, UpdateStateMessage, BreakpointHitMessage

END_OF_MSG = "\r\n"


class XSDBProtocol(Thread):
    """
    This class implements the xsdb protocol.

    :param xsdb_executable: The executable
    :param additional_args: Additional arguments delivered to xsdb.
    :type  additional_args: list
    :param telnet_port:        the port used for the telnet connection
    """

    def __init__(self, avatar, origin, xsdb_executable="xsdb",
                 additional_args=[], host='127.0.0.1', telnet_port=6666,
                 output_directory='/tmp', debug=False):
        """
        xsdb machine interface protocol
        :param avatar: The Avatar instance
        :param origin: The Target this protocol belongs to
        :param xsdb_executable: The path to the xsdb you want to use
        :param additional_args: Additional args to xsdb
        :param host: THe host of the running xsdb.  Probably localhost
        :param telnet_port: The port for xsdb's TCL machine interface.  Should be 6666
        :param output_directory: The directory where logfiles should go
        :param debug: Enable xsdb debug output
        """
        self.log = logging.getLogger('%s.%s' % (origin.log.name, self.__class__.__name__)) if origin else \
                                    logging.getLogger(self.__class__.__name__)
        self._telnet_port = telnet_port
        self._host = host
        self.in_queue = queue.Queue()
        self.out_queue = queue.Queue()
        self.trace_queue = queue.Queue()
        self.trace_enabled = Event()
        self.avatar = avatar
        self.telnet = None
        self._close = Event()
        self.buf = u""
        self.cmd_lock = Lock()
        self._origin = origin
        self._firmware = None
        
        self._bkpt_limit = 0
        self._bkpt_list = {}

        self.output_directory = output_directory
        executable_path = distutils.spawn.find_executable(xsdb_executable)
        self._cmd_line = [executable_path]
        if debug is True:
            self._cmd_line += ['--debug']

        self._cmd_line += ['-eval', 'xsdbserver start -host localhost -port %d' % self._telnet_port]
        self._cmd_line += additional_args

        self._xsdb = None

        with open("%s/xsdb_out.txt" % output_directory, "wb") as out, \
                open("%s/xsdb_err.txt" % output_directory, "wb") as err:
            self.log.debug("Starting xsdb with command line: %s" % (" ".join(self._cmd_line)))
            self._xsdb = subprocess.Popen(self._cmd_line,
                                             stdout=out, stderr=err)#, shell=True)
        Thread.__init__(self)
        self.daemon = True

    def connect(self):
        """
        Connects to xsdb telnet Server for all subsequent communication
        returns: True on success, else False
        """
        sleep(3)
        
        if self._xsdb.poll() is not None:
            raise RuntimeError(("xsdb errored! Please check "
                                "%s/xsdb_err.txt for details" %
                                self.output_directory))


        self.log.debug("Connecting to xsdb on %s:%s" % (self._host, self._telnet_port))
        try:
            self.telnet = telnetlib.Telnet(self._host, self._telnet_port)
            self.log.debug("Connected to xsdb.")
            self.telnet.write(("connect" + END_OF_MSG).encode('ascii'))
            resp = self.telnet.read_until("\r\n".encode("ascii")).decode("ascii")
            if not "okay" in str(resp):
                return False
            self.log.debug("xsdb conneced to hw_sever.")
            self.telnet.write(("targets 2" + END_OF_MSG).encode('ascii'))
            resp = self.telnet.read_until("\r\n".encode("ascii")).decode("ascii")
            self.log.debug("xsdb selects target 2: core 0.")
            self.start()
            if "okay" in str(resp):
                return True
            else:
                self.log.warning("xsdb failed to connect with response %s" % resp)
                return False
        except:
            self.log.exception("Error connecting to xsdb TCL port %d" % self._telnet_port)
            return False

    def reset(self):
        """
        Resets the target
        returns: True on success, else False
        """
        self.log.debug("Resetting target")
        resp = self.execute_command('rst -proc')
        if not 'okay' in str(resp):
            self.log.error('Failed to reset the target with xsdb')
            return False
        else:
            self.log.debug("Target reset complete")
            return True

    def shutdown(self):
        """
        Shuts down xsdb
        returns: True on success, else False
        """
        self.telnet.write(("exit" + END_OF_MSG).encode('ascii'))
        self._close.set()
        if self.telnet:
            self.telnet.close()
        # Fix
        if self._xsdb is not None:
            self._xsdb.terminate()
            self._xsdb = None

    def execute_command(self, cmd):
        try:
            self.cmd_lock.acquire()
            self.in_queue.put(cmd)
            ret = self.out_queue.get()
            if "FAILED" in ret:
                raise RuntimeError("Command '%s' failed!" % cmd)
            return ret
        except:
            raise
        finally:
            self.cmd_lock.release()
    
    def run(self):
        cmd = None
        self.log.debug("Starting xsdbSocketListener")
        while 1:
            #not self.avatar._close.is_set() and not self._close.is_set():
            if self.in_queue.empty() is False:
                cmd = self.in_queue.get()
                self.log.debug("Executing command %s" % cmd)
                self.telnet.write((cmd + END_OF_MSG).encode('ascii'))
                
                try:
                    line = self.read_response()
                except EOFError:
                    self.log.warning("xsdb Connection closed!")
                    self.shutdown()
                    break
                if line is not None:
                    line = line.rstrip(END_OF_MSG)
                    # This is an error
                    if not "okay" in line and not "Already" in line:
                        self.log.debug(line)
                        self.log.error(line)
                        if cmd:
                            # tell the caller we failed
                            self.out_queue.put("FAILED")
                    else:
                        if not cmd:
                            # We didn't ask for it.  Just debug it
                            self.log.debug(line)
                        else:
                            self.log.debug("response --> " +  line)
                            self.out_queue.put(line)
                            cmd = None
            #sleep(.001) # Have a heart. Give other threads a chance
        self.log.debug("xsdb Background thread exiting")

    def read_response(self):
        self.buf = self.telnet.read_until("okay".encode("ascii"), timeout=20).decode("ascii")
        self.buf += self.telnet.read_until("\r\n".encode("ascii"), timeout=2).decode("ascii")
        self.buf += self.telnet.read_eager().decode('ascii')
        return self.buf
        #if END_OF_MSG in self.buf:
        #    resp, self.buf = self.buf.split(END_OF_MSG, 1)
        #    return resp
        #return None

#    ### The Memory Protocol starts here
#
#    def write_memory(self, address, wordsize, val, num_words=1, raw=False):
#        """Writes memory
#
#        :param address:   Address to write to
#        :param wordsize:  the size of the write (1, 2, 4 or 8)
#        :param val:       the written value
#        :type val:        int if num_words == 1 and raw == False
#                          list if num_words > 1 and raw == False
#                          str or byte if raw == True
#        :param num_words: The amount of words to read
#        :param raw:       Specifies whether to write in raw or word mode
#        :returns:         True on success else False
#        """
#        #print "nucleo.write_memory(%s, %s, %s, %s, %s)" % (repr(address), repr(wordsize), repr(val), repr(num_words), repr(raw))
#        if isinstance(val, str) and len(val) != num_words:
#            self.log.debug("Setting num_words = %d" % (len(val) / wordsize))
#            num_words = len(val) / wordsize
#        for i in range(0, num_words, wordsize):
#            if raw:
#                write_val = '0x' + encode(val[i:i+wordsize], 'hex_codec').decode('ascii')
#            elif isinstance(val, int) or isinstance(val, long):
#                write_val = hex(val).rstrip("L")
#            else:
#                # A list of ints
#                write_val = hex(val[i]).rstrip("L")
#            write_addr = hex(address + i).rstrip("L")
#            if wordsize == 1:
#                self.execute_command('mwr %s %s' % (write_addr, write_val))
#            elif wordsize == 2:
#                self.execute_command('mwr %s %s' % (write_addr, write_val))
#            else:
#                self.execute_command('mwr %s %s' % (write_addr, write_val))
#
#        return True
#
#    def read_memory(self, address, wordsize=4, num_words=1, raw=False):
#        """reads memory
#
#        :param address:   Address to write to
#        :param wordsize:  the size of a read word (1, 2, 4 or 8)
#        :param num_words: the amount of read words
#        :param raw:       Whether the read memory should be returned unprocessed
#        :return:          The read memory
#        """
#        num2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}
#        raw_mem = b''
#        words = []
#        for i in range(0, num_words, wordsize):
#            read_addr = hex(address + i).rstrip('L')
#            if wordsize == 1:
#                resp = self.execute_command('mrd %s' % read_addr)
#            elif wordsize == 2:
#                resp = self.execute_command("mrd %s" % read_addr)
#            else:
#                resp = self.execute_command('mrd %s' % read_addr)
#            if resp:
#                val = int(resp)
#                raw_mem += binascii.unhexlify(hex(val)[2:].zfill(wordsize * 2))
#            else:
#                self.log.error("Could not read from address %s" % read_addr)
#                return None
#        # OCD flips the endianness
#        raw_mem = raw_mem[::-1]
#        if raw:
#            self.log.debug("Read %s from %#08x" % (repr(raw), address))
#            return raw_mem
#        else:
#            # Todo: Endianness support
#            fmt = '<%d%s' % (num_words, num2fmt[wordsize])
#            mem = list(unpack(fmt, raw_mem))
#            if num_words == 1:
#                return mem[0]
#            else:
#                return mem
#
#    ### The register protocol starts here
#
#    def read_register(self, reg):
#
#        try:
#            resp = self.execute_command("rrd %s" % reg)
#            val = int(resp.split(":")[1].strip(), 16)
#            return val
#
#        except:
#            self.log.exception("Failed to read from register " + repr(reg))
#            return False
#
#    def write_register(self, reg, value):
#        """Set one register on the target
#        :returns: True on success"""
#        try:
#            self.execute_command("rwr %s %s" % (reg, hex(value)))
#            return True
#        except:
#            self.log.exception(("Error writing register %s" % reg))
#            return False

#    def cont(self):
#        """Continues the execution of the target
#        :returns: True on success"""
#        try:
#            resp = self.execute_command("con")
#        except:
#            self.log.exception("Error halting target")
#            return False
#        avatar_msg = UpdateStateMessage(self._origin, TargetStates.RUNNING)
#        self.avatar.fast_queue.put(avatar_msg)
#        return True

#    def stop(self):
#        """Stops execution of the target
#        :returns: True on success"""
#        try:
#            resp = self.execute_command("stop")
#        except:
#            self.log.exception("Error halting target")
#            return False
#        self.log.debug("Target is now halted")
#        avatar_msg = UpdateStateMessage(self._origin, TargetStates.STOPPED)
#        self.avatar.fast_queue.put(avatar_msg)
#        return True

#    def step(self):
#        """Step one instruction on the target
#        :returns: True on success"""
#        try:
#            resp = self.execute_command("stpi")
#            return True
#        except:
#            self.log.exception("Failed to step the target")
#
#    def set_breakpoint(self, line,
#                       hardware=False,
#                       temporary=False,
#                       regex=False,
#                       condition=None,
#                       ignore_count=0,
#                       thread=0):
#        """Inserts a breakpoint
#        :param str line: the thing to break at.  An address.
#        :param bool hardware: Hardware breakpoint
#        :param bool temporary:  Tempory breakpoint
#        :param str regex:     If set, inserts breakpoints matching the regex
#        :param str condition: If set, inserts a breakpoint with specified condition
#        :param int ignore_count: Amount of times the bp should be ignored
#        :param int thread:    Threadno in which this breakpoints should be added
#        :returns:             The number of the breakpoint
#        """
#        self._bkpt_list[line] = len(self._bkpt_list)-1
#        
#        cmd = ["bpadd"]
#        if regex:
#            raise ValueError("xsdb doesn't support regex breakpoints!")
#        if condition:
#            raise ValueError("xsdb doesn't support conditional breakpoints!")
#        if ignore_count:
#            raise ValueError("xsdb doesn't support ignore counts")
#        if thread:
#            raise ValueError("xsdb doesn't support thread options!")
#
#        if isinstance(line, int):
#            cmd.append("--addr %#08x" % line)
#        else:
#            cmd.append("--addr "+str(line))
#        if hardware:
#            cmd.append("-type hw")
#        try:
#            resp = self.execute_command(" ".join(cmd))
#            self.log.debug("Breakpoint set")
#            return True
#        except:
#            self.log.exception("Error setting breakpoint")
#            return False
#
#    def set_watchpoint(self, variable, write=True, read=False):
#        cmd = ["bpadd"]
#
#        if isinstance(variable, int):
#            cmd.append("%#08x" % variable)
#        else:
#            cmd.append(str(variable))
#        if read and write:
#            cmd.append("-mode 0x8")
#        elif read:
#            cmd.append("-mode 0x1")
#        elif write:
#            cmd.append("-mode 0x2")
#        else:
#            raise ValueError("At least one read and write must be True")
#        try:
#            resp = self.execute_command(" ".join(cmd))
#            return True
#        except:
#            self.log.exception("Error setting watchpoint")
#            return False
#    
#    def set_file(self, elf=''):
#        """Load an ELF file
#        :returns: True on success"""
#        self._firmware = elf
#
#    def download(self):
#        """Download code to target
#        :returns: True on success"""
#        if self._firmware is None:
#            raise Exception("XSDBProtocol was unable to execute download without a proper ELF file. Please call set_file first")
#        try:
#            cmd = ["dow", self._firmware]
#            resp = self.execute_command(" ".join(cmd))
#            return True
#        except:
#            self.log.exception("Error setting watchpoint")
#            return False
#
#    def remove_breakpoint(self, bkpt):
#        bkpt = self._bkpt_list[bkpt]
#        
#        """Deletes a breakpoint"""
#        cmd = ['bpremove']
#        if isinstance(bkpt, int):
#            cmd.append("%#08x" % bkpt)
#        else:
#            cmd.append(str(bkpt))
#        try:
#            self.execute_command(" ".join(cmd))
#            return True
#        except:
#            self.log.exception("Error removing breakpoint")


#    def remote_connect(self, ip='127.0.0.1', port=3333):
#        """
#        connect to a remote gdb server
#
#        :param ip: ip of the remote gdb-server (default: localhost)
#        :param port: port of the remote gdb-server (default: port)
#        :returns: True on successful connection
#        """
#
#        req = ['gdbremote', 'connect']
#        ret, resp = self._sync_request(req, GDB_PROT_DONE)
#        if not ret:
#            self.log.critical(
#                "Unable to set GDB/MI to async, received response: %s" %
#                resp)
#            raise Exception("GDBProtocol was unable to switch to async")
#
#        req = ['-gdb-set', 'architecture', self._arch.gdb_name]
#        ret, resp = self._sync_request(req, GDB_PROT_DONE)
#
#
#        if not ret:
#            self.log.critical(
#                "Unable to set architecture, received response: %s" %
#                resp)
#            raise Exception(("GDBProtocol was unable to set the architecture\n"
#                             "Did you select the right gdb_executable?"))
#
#        # if we are on ARM, set abi to AAPPCS to avoid bugs due to
#        # fp-derefencation (https://github.com/avatartwo/avatar2/issues/19)
#        if self._arch.gdb_name == 'arm':
#            self.set_abi('AAPCS')
#
#        req = ['-target-select', 'remote', '%s:%d' % (ip, int(port))]
#        ret, resp = self._sync_request(req, GDB_PROT_CONN)
#
#        self.log.debug(
#            "Attempted to connect to target. Received response: %s" %
#            resp)
#        if not ret:
#            self.log.critical("GDBProtocol was unable to connect to remote target")
#            raise Exception("GDBProtocol was unable to connect")
#        
#        self.update_target_regs()
#
#        return ret
#
#    def remote_disconnect(self):
#        """
#        disconnects from remote target
#        """
#
#        ret, resp = self._sync_request('-target-disconnect', GDB_PROT_DONE)
#
#        self.log.debug(
#            "Attempted to disconnect from target. Received response: %s" %
#            resp)
#        return ret

