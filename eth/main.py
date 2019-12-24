# import sys, os
# root = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../")
# print(root)
# sys.path.append(root)
from boofuzz import *
from protocol import DiscoveryProtocol

def main():
    session = Session(target=Target(connection=UDPSocketConnection("127.0.0.1", 30303)))
    p = DiscoveryProtocol(session)
    for i in range(3):
        s_mutate()
        print(s_render())


if __name__ == "__main__":
    main()