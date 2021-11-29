#!/usr/bin/python3
from brownie import LazyMint, accounts, network, config
import uuid
import brownie
# from eip712.messages import EIP712Message, EIP712Type
from eth_account import Account, messages
import eth_account
from eth_account.datastructures import SignedMessage
from eth_account.account import sign_message_hash
import eth_keys
from eth_account.messages import defunct_hash_message
from eth_utils.conversions import to_bytes
from hexbytes import HexBytes
from web3 import Web3

import os


def sign_defunct_message( 
        private_key: str,
        primitive: bytes = None,
        *,
        hexstr: str = None,
        text: str = None,
        ) -> SignedMessage:
        """Signs an `EIP-191` using this account's private key.
        Args:
            message: An text
        Returns:
            An eth_account `SignedMessage` instance.
        """
        msg_hash_bytes = defunct_hash_message(primitive, hexstr=hexstr, text=text)
        eth_private_key = eth_keys.keys.PrivateKey(HexBytes(private_key))
        (v, r, s, eth_signature_bytes) = sign_message_hash(eth_private_key, msg_hash_bytes)
        return SignedMessage(
            messageHash=msg_hash_bytes,
            r=r,
            s=s,
            v=v,
            signature=HexBytes(eth_signature_bytes),
        )


def main():
    from_add = accounts.add(private_key=os.environ['FAKE_PRIVATE_KEY1'])
    to_add = accounts.add(private_key=os.environ['FAKE_PRIVATE_KEY2'])
    
    print(from_add.address)
    
    print(network.show_active())
    publish_source = True if os.getenv("ETHERSCAN_TOKEN") else False
    mint = LazyMint.deploy({"from": from_add}, publish_source=publish_source)

    t1 = str(uuid.uuid1()).replace('-', '')
    t2 = str(uuid.uuid1()).replace('-', '')
    token_id = '0x' + t1 + t2

    signed = sign_defunct_message(from_add.private_key, hexstr=token_id)

    print(token_id, signed.messageHash)
    r = eth_account.Account.recoverHash(signed.messageHash, signature=signed.signature)
    assert (r==from_add.address),(r, from_add.address)
    res = {'toBytes':None, 'eip191format':None, 'getMessageHash':None}

    for fn in res:
        res[fn] = (getattr(mint, fn)(token_id)).return_value

    res['verify'] = mint.verify(token_id, signed.signature, from_add.address)

    print('tokenID', token_id)

    for fn in ['toBytes', 'eip191format','getMessageHash' ]:
        print(res[fn])

    print('Verified?', 'Yes' if res['verify'] else 'No')