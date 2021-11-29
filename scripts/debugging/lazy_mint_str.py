#!/usr/bin/python3
from brownie import LazyMintStr, accounts, network, config
import uuid
import brownie
# from eip712.messages import EIP712Message, EIP712Type
from eth_account import Account, messages
import eth_account
from eth_account.datastructures import SignedMessage
from eth_account.account import sign_message_hash
import eth_keys
from eth_account.messages import defunct_hash_message
from hexbytes import HexBytes
from web3 import Web3

import os

def sign_defunct_message(message, private_key):
    """Signs an `EIP-191` using this account's private key.
    Args:
        message: An text
    Returns:
        An eth_account `SignedMessage` instance.
    """
    msg_hash_bytes = defunct_hash_message(hexstr=message)
    eth_private_key = eth_keys.keys.PrivateKey(HexBytes(private_key))
    (v, r, s, eth_signature_bytes) = sign_message_hash(eth_private_key, msg_hash_bytes)
    return SignedMessage(
        messageHash=msg_hash_bytes,
        r=r,
        s=s,
        v=v,
        signature=HexBytes(eth_signature_bytes),
    )
    
def sign_defunct_message2(message, private_key):
    """Signs an `EIP-191` using this account's private key.
    Args:
        message: A hexstr
    Returns:
        An eth_account `SignedMessage` instance.
    """
    msg_hash_bytes =  Web3.keccak(hexstr=message)
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
    mint = LazyMintStr.deploy({"from": from_add}, publish_source=publish_source)

    token_id = "Hello"

    signed = from_add.sign_defunct_message(token_id)

    print(token_id, signed.messageHash)

    assert (eth_account.Account.recoverHash(signed.messageHash, signature=signed.signature)==from_add.address)

    # x = transaction = mint.lazyMint(
    #     from_add.address, 
    #     to_add.address,
    #     token_id,
    #     signed.signature,
    #     {"from": from_add})s
    # transaction.wait(1)

    y = mint.f1(token_id).return_value
    z = mint.f2(token_id).return_value
    d1 = mint.fn1(token_id).return_value
    d2 = mint.fn2(token_id).return_value


    matches = {}
    matches['keccak256(abi.encode(tokenId))'] = mint.verifyViaf2(token_id, signed.signature, from_add.address).return_value
    matches['ECDSA.toEthSignedMessageHash(abi.encode(tokenId))'] = mint.verifyViafn1(token_id, signed.signature, from_add.address).return_value
    matches['ECDSA.toEthSignedMessageHash(keccak256(abi.encode(tokenId)))'] = \
        mint.verifyViafn2(token_id, signed.signature, from_add.address).return_value

    print('Result')
    print('Hash of tokenId in python', signed.messageHash.hex())
    print('abi.encode(tokenId)', y)
    print('keccak256(abi.encode(tokenId))', z)
    print('ECDSA.toEthSignedMessageHash(abi.encode(tokenId))', d1)
    print('ECDSA.toEthSignedMessageHash(keccak256(abi.encode(tokenId)))', d2)


    print('Did it verify?')
    for k, v in matches.items():
        print(k, 'Yes' if v else 'No')