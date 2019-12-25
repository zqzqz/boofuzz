import os
from boofuzz import *
from eth_utils import keccak
from eth_keys import keys

class Protocol():
    def __init__(self, session):
        self.session = session

class DiscoveryProtocol(Protocol):
    def __init__(self, session):
        super().__init__(session)
        self.build()
    
    def build(self):
        self._build_ping()
        self._build_pong()
        self._build_find_node()
        self._build_nodes()

        self.session.connect(s_get("PING"))
        self.session.connect(s_get("PONG"))
        self.session.connect(s_get("FIND_NODE"))
        self.session.connect(s_get("NODES"))

    def _build_ping(self):
        s_initialize("PING")
        s_bytes(value=bytes.fromhex("76576eacbcf500aeb0bdc3757da898f6483af25df54819cc1cac8cfe287d8a04"), size=32, fuzzable=False, name="hash")
        s_bytes(value=bytes.fromhex("a938f42352f0103e4737ab6a72908b419196e65fa9c4586f68a6ffeb31401e3c2d3b32f26af6bdeb2ab7738f062d22e2ea4ed371f615afc3b6a4a60f88df79fc00"), size=64, fuzzable=False, name="signature")
        s_static(value=bytes.fromhex("01"), name="type")
        with s_block("payload"):
            s_delim(value=bytes.fromhex("dc"), name="d1")
            s_static(value=bytes.fromhex("04"), name="version")
            s_delim(value=bytes.fromhex("cb84"), name="d2")
            s_bytes(value=bytes.fromhex("74ca1b88"), size=4, name="sender_address")
            s_delim(value=bytes.fromhex("82"), name="d3")
            s_bytes(value=bytes.fromhex("6ff1"), size=4, name="sender_udp_port")
            s_delim(value=bytes.fromhex("82"), name="d4")
            s_bytes(value=bytes.fromhex("6ff1"), size=4, name="sender_tcp_port")
            s_delim(value=bytes.fromhex("c984"), name="d5")
            s_bytes(value=bytes.fromhex("8dd46c08"), size=4, name="recipient_address")
            s_delim(value=bytes.fromhex("82"), name="d6")
            s_bytes(value=bytes.fromhex("765f"), size=4, name="recipient_udp_port")
            s_delim(value=bytes.fromhex("8084"), name="d7")
            s_bytes(value=bytes.fromhex("5e0e7698"), size=4, name="expiration")
        def _hash(sig, _type, payload):
            return keccak(b''.join([sig, _type, payload]))
        def _signature(_type, payload):
            sk = keys.PrivateKey(os.urandom(32))
            return bytes.fromhex(sk.sign_msg(b''.join([_type, payload])))
        s_constraint("hash", ["signature", "type", "payload"], _hash, 0.98)
        s_constraint("signature", ["type", "payload"], _signature, 0.98)

    def _build_pong(self):
        s_initialize("PONG")
        s_bytes(value=bytes.fromhex("7382fe08e439631b0751340421a17e3df8fbdf91be22835b65fa7d8abf9a970a"), size=32, fuzzable=False, name="hash")
        s_bytes(value=bytes.fromhex("296afd362edc174eead6246fb5dfd958f88d7c178dd77063862909ef29f7447d3a0e7680be6ea7e7e7b2e713b3bda7960a1c20390b3416c33775800b043416f100"), size=64, fuzzable=False, name="signature")
        s_static(value=bytes.fromhex("02"), name="type")
        with s_block("payload"):
            s_delim(value=bytes.fromhex("f2"), name="d1")
            s_delim(value=bytes.fromhex("cb84"), name="d2")
            s_bytes(value=bytes.fromhex("8dd46c08"), size=4, name="recipient_address")
            s_delim(value=bytes.fromhex("82"), name="d3")
            s_bytes(value=bytes.fromhex("765f"), size=4, name="recipient_udp_port")
            s_delim(value=bytes.fromhex("82"), name="d4")
            s_bytes(value=bytes.fromhex("765f"), size=4, name="recipient_tcp_port")
            s_delim(value=bytes.fromhex("a0"), name="d5")
            s_bytes(value=bytes.fromhex("82e1539c480f038d345bfec48be744323104e2575aba2b9ab056dbfddaaa86e7"), size=32, name="ping_hash")
            s_delim(value=bytes.fromhex("84"), name="d6")
            s_bytes(value=bytes.fromhex("5dfe7698"), size=4, name="expiration")
        def _hash(sig, _type, payload):
            return keccak(b''.join([sig, _type, payload]))
        def _signature(_type, payload):
            sk = keys.PrivateKey(os.urandom(32))
            return bytes.fromhex(sk.sign_msg(b''.join([_type, payload])))
        s_constraint("hash", ["signature", "type", "payload"], _hash, 0.98)
        s_constraint("signature", ["type", "payload"], _signature, 0.98)

    def _build_find_node(self):
        s_initialize("FIND_NODE")
        s_bytes(value=bytes.fromhex("6f32026cd25327097d1bd4546e7b32a8fc7973f48a730192818073e1fb2197a3"), size=32, fuzzable=False, name="hash")
        s_bytes(value=bytes.fromhex("d42f4c81ebac68289d218074a2079dfab4885cbe7f6b284a8f08a6efe6afecd1641bde0a9a86d80af4ca05a1879edfd878fbca1e88fbbf99b5d6199fb3e01c6900"), size=64, fuzzable=False, name="signature")
        s_static(value=bytes.fromhex("03"), name="type")
        with s_block("payload"):
            s_delim(value=bytes.fromhex("f847b840"), name="d1")
            s_bytes(value=bytes.fromhex("4d6888bb4313cabb02520e2ec9cf97909c808fa2aff17085cfc72ccd064e2908617758915184ba9719eb96c64e35c0843936e620e6453a48db2b2ab86511184e"), size=64, name="target")
            s_delim(value=bytes.fromhex("84"), name="d2")
            s_bytes(value=bytes.fromhex("5dfe7698"), size=4, name="expiration")
        def _hash(sig, _type, payload):
            return keccak(b''.join([sig, _type, payload]))
        def _signature(_type, payload):
            sk = keys.PrivateKey(os.urandom(32))
            return bytes.fromhex(sk.sign_msg(b''.join([_type, payload])))
        s_constraint("hash", ["signature", "type", "payload"], _hash, 0.98)
        s_constraint("signature", ["type", "payload"], _signature, 0.98)

    def _build_nodes(self):
        s_initialize("NODES")
        s_bytes(value=bytes.fromhex("e8d783b9f7e1facd320e4aade13aa8136db17045c3d04c5c70973c49201804ff"), size=32, fuzzable=False, name="hash")
        s_bytes(value=bytes.fromhex("a20903509d1f116b95b4cd1e8fa09e1f7f43bed2f63db337bd7ffdd2cf343ff05746e25c65b2fa69065f3acb9a78d014a493115c9ae47f1e244edf5c9536f58300"), size=64, fuzzable=False, name="signature")
        s_static(value=bytes.fromhex("04"), name="type")
        with s_block("payload"):
            s_delim(value=bytes.fromhex("f8f4f8ed"), name="d1")
            with s_block("node"):
                s_delim(value=bytes.fromhex("f84d84"), name="d2")
                s_bytes(value=bytes.fromhex("8dd46c08"), size=4, name="node_address")
                s_delim(value=bytes.fromhex("82"), name="d3")
                s_bytes(value=bytes.fromhex("765f"), size=4, name="node_udp_port")
                s_delim(value=bytes.fromhex("82"), name="d4")
                s_bytes(value=bytes.fromhex("765f"), size=4, name="node_tcp_port")
                s_delim(value=bytes.fromhex("b840"), name="d5")
                s_bytes(value=bytes.fromhex("5864cd487d3e127eb85486e43fa34b5c255a91152fec035be94ab24beee1f791d9fd9d0ae39828a325ae72666858407182489fea3a0ca0f37edd57ede1105a31"), size=64, name="target")
            s_repeat("node", 0, 32)
        def _hash(sig, _type, payload):
            return keccak(b''.join([sig, _type, payload]))
        def _signature(_type, payload):
            sk = keys.PrivateKey(os.urandom(32))
            return bytes.fromhex(sk.sign_msg(b''.join([_type, payload])))
        s_constraint("hash", ["signature", "type", "payload"], _hash, 0.98)
        s_constraint("signature", ["type", "payload"], _signature, 0.98)