from avatar2.targets import Target, TargetStates
from avatar2.protocols.xsdb import XSDBProtocol
from avatar2.protocols.gdb import GDBProtocol

from avatar2.watchmen import watch

class DMonTarget(Target):
    '''
    dmon is a framework to perform security testing of real world
    firmware programs. The dmon target and protocol allow Avatar2
    to interact with the high performance dmon emulation platform.

    For more information, please visit:
    https://github.com/Bounti/dmon
    '''

    def __init__(self, avatar, 
                 ps7_init_file,
                 hdf_file,
                 firmware,
                 processor='cortex-m3',
                 gdb_executable=None, gdb_additional_args=None, 
                 gdb_ip='127.0.0.1', gdb_port=3333,
                 gdb_verbose_mi=False,
                 enable_init_files=False,
                 arguments=None,
                 **kwargs):

        super(DMonTarget, self).__init__(avatar, **kwargs)

        self.processor = processor
        self._ps7_init_file = ps7_init_file
        self._hdf_file = hdf_file
        self._firmware = firmware

        self.gdb_executable = (gdb_executable if gdb_executable is not None
                               else self._arch.get_gdb_executable())
        self.gdb_additional_args = gdb_additional_args if gdb_additional_args else []
        self.gdb_ip = gdb_ip
        self.gdb_port = gdb_port
        self._arguments = arguments
        self._enable_init_files = enable_init_files
        self._verbose_gdbmi = gdb_verbose_mi

    @watch('TargetInit')
    def init(self):

        if self.processor == 'cortex-m3':
            dmon = XSDBProtocol(avatar=self.avatar, origin=self,
                    output_directory=self.avatar.output_directory)
            gdb = GDBProtocol(gdb_executable=self.gdb_executable,
                    arch=self._arch,
                    additional_args=self.gdb_additional_args,
                    avatar=self.avatar, origin=self,
                    enable_init_files=self._enable_init_files,
                    local_arguments=self._arguments,
                    verbose=self._verbose_gdbmi)
        else:
            dmon = None
            self.log.warning("Target board not implemented")
            raise Exception("Target board not implemented")


        if dmon.connect():
            #dmon.execute_command("connect -url tcp:127.0.0.1:3121")
            dmon.execute_command("source %s" % self._ps7_init_file)
            dmon.execute_command("targets -set -nocase -filter {name =~\"APU*\" && jtag_cable_name =~ \"Digilent Zed 210248A398A9\"} -index 0")
            dmon.execute_command("loadhw -hw %s -mem-ranges [list {0x40000000 0xbfffffff}]" % self._hdf_file)
            dmon.execute_command("configparams force-mem-access 1")
            dmon.execute_command("targets -set -nocase -filter {name =~\"APU*\" && jtag_cable_name =~ \"Digilent Zed 210248A398A9\"} -index 0")
            dmon.execute_command("stop")
            dmon.execute_command("ps7_init")
            dmon.execute_command("ps7_post_config")
            dmon.execute_command("targets -set -nocase -filter {name =~ \"ARM*#0\" && jtag_cable_name =~ \"Digilent Zed 210248A398A9\"} -index 0")
            dmon.execute_command("rst -processor")
            dmon.execute_command("targets -set -nocase -filter {name =~ \"ARM*#0\" && jtag_cable_name =~ \"Digilent Zed 210248A398A9\"} -index 0")
            dmon.execute_command("dow %s" % self._firmware)
            dmon.execute_command("configparams force-mem-access 0")
            #dmon.reset()
            dmon.execute_command("con")
            self.log.info("Connected to Target")
        else:
            self.log.warning("Connecting failed")
            raise Exception("Connecting to target failed")

        if gdb.remote_connect(ip=self.gdb_ip, port=self.gdb_port):
            self.log.info("Connected to Target")
        else:
            self.log.warning("Connecting failed")
            raise Exception("Connecting to target failed")
        
        self.update_state(TargetStates.STOPPED)

        #if dmon.stop():
        #   self.update_state(TargetStates.STOPPED)

        #self.protocols.set_all(dmon)
        self.protocols.set_all(gdb)
        self.protocols.monitor = gdb

        #self.wait()

    def reset(self):
        return self.protocols.execution.reset()

    #@watch('TargetWait')
    #def wait(self, state=TargetStates.STOPPED):
    #    return self.protocols.execution.wait(state)


