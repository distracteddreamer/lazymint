#!/usr/bin/python3
from brownie import LazyMint, accounts, network, config
from brownie.network.contract import VirtualMachineError
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

from eth_utils.curried import keccak

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


    while(True):
        t1 = str(uuid.uuid1()).replace('-', '')
        token_id = '0x' + t1 + t1
        signed = sign_defunct_message(from_add.private_key, hexstr=token_id)
        

        hash_addr = HexBytes(keccak(hexstr=HexBytes(to_bytes(hexstr=from_add.address)).hex())).hex()
    
        r = eth_account.Account.recoverHash(signed.messageHash, signature=signed.signature)
        assert (r==from_add.address),(r, from_add.address)
        t = token_id
        token_id = hex(int(t, 16) ^ int(hash_addr, 16))
        
        if (token_id[:2][:32] != token_id[2:][32:]):
            break

    res = {'toBytes':None, 'eip191format':None,'getTokenHash':None, 'getMessageHash':None}
    for fn in res:
        res[fn] = (getattr(mint, fn)(token_id)).return_value

    res['verify'] = mint.verify(token_id, signed.signature, from_add.address).return_value
    res['lazyVerify'] = mint.lazyVerify(token_id)
    for sender in ['from', 'to']:
        try:
            res[f'getApproved{sender}'] = mint.getApproved(token_id, {'from': locals()[f'{sender}_add'].address})
        except VirtualMachineError as vme:
            res[f'getApproved{sender}'] = (vme.message)


    # print(res['verify'])
    isowner = mint.ownerOf(token_id)

    mint.safeTransferFrom(from_add.address, to_add.address, token_id, signed.signature)
    new_owner = mint.ownerOf(token_id)



    print('tokenID', token_id, 'orig', t, 'hash_addr', hash_addr)

    for fn in ['toBytes', 'eip191format','getMessageHash', 'getTokenHash']:
        print(fn, res[fn])

    print('Lazy verified?', 'Yes' if res['lazyVerify'] else 'No')
    print(f'Is token now owned by from?', 'Yes' if isowner else f'No')
    print('Verified?', 'Yes' if res['verify'] else 'No')
    
    print(f'Is token now owned by to?', 'Yes' if (new_owner == to_add.address) else f'No it is owned by {new_owner}')
    
    # print(hash_addr== ('0x'+''.join([hex(i)[2:] for i in mint.splitBytes(hash_addr)])))
    # x=('0x'+''.join([hex(i)[2:] for i in mint.splitUint256(token_id)]))
    # print(token_id==x, token_id, x)
    # print(mint.xorSplit(token_id))
    # print(int(hash_addr[2:][:32], 16)^int(hash_addr[2:][32:], 16))

    print(f'Was {from_add.address} approved before minting?', res['getApprovedfrom'])
    print(f'Was {to_add.address}  approved before minting?', res['getApprovedto'])
    