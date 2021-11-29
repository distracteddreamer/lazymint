// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract LazyMintStr is ERC721 {

    constructor () public ERC721 ("mint", "MINT"){
    }

    event Log(
        uint256 tokenId,
        bytes encoded,
        bytes32 encoded256,
        bytes32 msgHash
    );

    function lazyMint(
        address from,
        address to,
        uint256 tokenId,
        bytes memory signature
    ) public  returns (bytes32) {
      bytes memory y = abi.encode(tokenId);
      bytes32 z = keccak256(y);
      bytes32 d = ECDSA.toEthSignedMessageHash(z);
      return d;
      //require(ECDSA.recover(d, signature)==from, "Sender not allowed to send token");
      //_safeMint(from, tokenId);
      //safeTransferFrom(from, to, tokenId);  
    }

    function getEthSignedMessageHash(bytes32 _messageHash)
        public
        pure
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    function getEthSignedMessageHash(bytes memory _messageHash)
        public
        pure
        returns (bytes32)
    {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n", 
                Strings.toString(_messageHash.length), 
                _messageHash)
            );
    }



    function f1(
        string memory tokenId
    ) public  returns (bytes memory) {
      bytes memory y = abi.encodePacked(tokenId);
      return y;  
    }

    function toBytes(string memory tokenId) public  returns (bytes memory) {
        return abi.encodePacked(tokenId);
    }

    function eip191format(
        string memory tokenId
    ) public  returns (bytes memory) {
      bytes memory s = toBytes(tokenId);
      return abi.encodePacked("\x19Ethereum Signed Message:\n", 
                Strings.toString(s.length), 
                s);
    }

    function getMessageHash(string memory tokenId) public returns (bytes32) {
        return keccak256(eip191format(tokenId));
    }

    function f2(
       string memory tokenId
    ) public  returns (bytes32) {
      bytes memory y = abi.encodePacked(tokenId);
      bytes32 z = keccak256(y);
      return z;
    }

    function fn1(
       string memory tokenId
    ) public  returns (bytes32) {
      bytes memory y = abi.encodePacked(tokenId);
      bytes32 d = getEthSignedMessageHash(y);
      return d;
    }

    function fn2(
       string memory tokenId
    ) public  returns (bytes32) {
      bytes memory y = abi.encodePacked(tokenId);
      bytes32 z = keccak256(y);
      bytes32 d = getEthSignedMessageHash(z);
      return d;
    }

    function verifyViaf2(string memory tokenId, bytes memory signature, address addr) 
    public returns (bool) {
      return ECDSA.recover(f2(tokenId), signature) == addr;
    }

    function verifyViafn1(string memory tokenId, bytes memory signature, address addr) 
    public returns (bool) {
      return ECDSA.recover(fn1(tokenId), signature) == addr;
    }

    function verifyViafn2(string memory tokenId, bytes memory signature, address addr) 
    public returns (bool) {
      return ECDSA.recover(fn2(tokenId), signature) == addr;
    }

    function verify(string memory tokenId, bytes memory signature, address addr) public returns (bool) {
        return ECDSA.recover(getMessageHash(tokenId), signature) == addr;
    }


}
