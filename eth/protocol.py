from boofuzz import *

class Protocol():
    def __init__(self, session):
        self.session = session

class DiscoveryProtocol(Protocol):
    def __init__(self, session):
        super().__init__(session)
        self.build()
    
    def build(self):
        s_initialize("TEST")
        s_string("aaa", name="f1")
        s_delim(" ")
        s_string("bbb", name="f2")
        def c(a):
            return b''.join([a, b'asd'])
        s_constraint("f1", ["f2"], c, 0.8)