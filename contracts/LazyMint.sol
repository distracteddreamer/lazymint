// SPDX-License-Identifier: MIT
pragma solidity 0.8.0;

import "./ERC721.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract LazyMint is ERC721 {

    constructor () public ERC721 ("lazyNFT", "LAZYNFT"){

    }

    function toBytes(uint256 tokenId) public returns (bytes memory) {
        return abi.encodePacked(tokenId);
    }

    function eip191format(
        uint256 tokenId
    ) public  returns (bytes memory) {
      bytes memory s = toBytes(tokenId);
      return abi.encodePacked("\x19Ethereum Signed Message:\n", 
                Strings.toString(s.length), 
                s);
    }

    function getMessageHash(uint256 tokenId) public returns (bytes32) {
        return keccak256(eip191format(tokenId));
    }

    function getTokenHash(uint256 t) public returns (bytes32){
       return getMessageHash(t ^ senderAddressToUint256());
    }

    function verify(uint256 tokenId, bytes memory signature, address addr) public returns (bool) {
        return ECDSA.recover(getTokenHash(tokenId), signature) == addr;
    }

    function _mint(address to, uint256 tokenId) internal virtual override {
        require(to != address(0), "ERC721: mint to the zero address");
        if(!_isLazyOwner(tokenId)){
          require((!_exists(tokenId)), "ERC721: token already minted");
        }
        _beforeTokenTransfer(address(0), to, tokenId);

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }
    
    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory _data
    ) public virtual override {
        // if _isLazyOwner() is true then it can't be a regular token
        // since _owners[tokenId] is the zero address
        if(_isLazyOwner(tokenId)){ 
          // Stricter test here compared to read-only functions
          require(verify(tokenId, _data, from), "ERC721: transfer caller is not owner nor approved");
          _safeMint(from, tokenId);
        } else {
            require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        }
        _safeTransfer(from, to, tokenId, _data);
    }

    function bytes32ToUint256(bytes32 inBytes) public view returns (uint256 outUint) {
      return uint256(inBytes);
    }

    function senderAddressToUint256() public view returns (uint256 outUint) {
        bytes memory z = abi.encodePacked(msg.sender);
        bytes32 z2 = keccak256(z);
        return bytes32ToUint256(z2);
      }



function splitUint256(uint256 r) public pure returns (uint256 a, uint256 b) {
        a = uint128(r >> 128);
        b = uint128(r);
    }


function splitBytes(bytes32 r) public pure returns (uint128 a, uint128 b) {
        a = uint128(bytes16(r));
        b = uint128(bytes16(r << 128));
    }



function lazyVerify(uint256 tokenId) public view returns (bool) {
   uint256 x = tokenId ^ senderAddressToUint256();
   (uint256 a, uint256 b) = splitUint256(x);
   (uint256 a2, uint256 b2) = splitUint256(tokenId);
   return (a == b) && (a2 != b2);
}

function _isLazyOwner(uint256 tokenId) public view virtual returns (bool) {
      return ((_owners[tokenId] == address(0)) && lazyVerify(tokenId));
    }

function ownerOf(uint256 tokenId) public view virtual override returns (address) {
    address owner = _owners[tokenId];
    if (_isLazyOwner(tokenId)){
          owner = msg.sender;
        }
    require(owner != address(0), "ERC721: owner query for nonexistent token");
    return owner;
}


  function xorWithAddress(uint256 num)  public returns (uint256 outUint) {
    return num ^ senderAddressToUint256();
  }


    function _exists(uint256 tokenId) internal view virtual override returns (bool) {

      if (_owners[tokenId] == address(0)){
        return _isLazyOwner(tokenId);
      }

      return true;
  }


  function getApproved(uint256 tokenId) public view virtual override returns (address) {
      require(_exists(tokenId), "ERC721: approved query for nonexistent token");

      if (_isLazyOwner(tokenId)) {
          return msg.sender;
      }
    
      return _tokenApprovals[tokenId];
  }

}

/*      // Could potentially do this by maintaining a counter per owner and generating tokenId accordingly
      // Skipping for now
      function balanceOf(address owner) public view virtual override returns (uint256) {
          require(owner != address(0), "ERC721: balance query for the zero address");
          return _balances[owner];
      }

      // Not sure if one can do anything about this in the absence of token id
      function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
          return _operatorApprovals[owner][operator];
      }

      // _isApprovedOrOwner will return true for msg.sender only
*/