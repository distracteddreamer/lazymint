#!/usr/bin/python3
import os
from brownie import LazyMint, accounts, network, config


def main():
    #dev = accounts.add(config["wallets"]["from_key"])
    dev = accounts.add(private_key="0x416b8a7d9290502f5661da81f0cf43893e3d19cb9aea3c426cfb36e8186e9c09")
    print(network.show_active())
    publish_source = True if os.getenv("ETHERSCAN_TOKEN") else False
    LazyMint.deploy({"from": dev}, publish_source=publish_source)
