pragma solidity ^0.5.7;

import "./Ownable.sol";
import "./Pausable.sol";

contract OwnablePausable is Pausable{

    function renounceOwnership() public onlyOwner hardPausable {
        super.renounceOwnership();
    }

    function transferOwnership(address newOwner) public onlyOwner hardPausable {
        super.transferOwnership(newOwner);
    }

}