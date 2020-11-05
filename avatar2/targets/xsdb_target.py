from avatar2.targets import Target, TargetStates
from avatar2.protocols.xsdb import XSDBProtocol

from avatar2.watchmen import watch

class XSDBTarget(Target):
    '''
    xsdb is a framework to perform security testing of real world
    firmware programs. The xsdb target and protocol allow Avatar2
    to interact with the high performance xsdb emulation platform.

    For more information, please visit:
    https://github.com/Bounti/xsdb
    '''

    def __init__(self, avatar, 
                 processor='cortex-m3',
                 **kwargs):

        super(XSDBTarget, self).__init__(avatar, **kwargs)

        self.processor = processor

    @watch('TargetInit')
    def init(self):

        if self.processor == 'cortex-m3':
            xsdb = XSDBProtocol(avatar=self.avatar, origin=self,
                    output_directory=self.avatar.output_directory)
        else:
            xsdb = None
            self.log.warning("Target board not implemented")
            raise Exception("Target board not implemented")


        if xsdb.connect():
            xsdb.reset()
            self.update_state(TargetStates.RUNNING)
            self.log.info("Connected to Target")
        else:
            self.log.warning("Connecting failed")
            raise Exception("Connecting to target failed")

        if xsdb.stop():
            self.update_state(TargetStates.STOPPED)

        self.protocols.set_all(xsdb)
        self.protocols.monitor = xsdb
        
        #self.wait()

    def reset(self):
        return self.protocols.execution.reset()

    @watch('TargetWait')
    def wait(self, state=TargetStates.STOPPED):
        return self.protocols.execution.wait(state)

