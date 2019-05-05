pragma solidity ^0.5.7;

import "./Ownable.sol";

contract Pausable is Ownable{

    enum PauseLevel { RUNNING, SOFTPAUSED, HARDPAUSED }
    PauseLevel public currentPauseLevel; // get the getter for free

    event PauseLevelChanged(address indexed whoChanged, PauseLevel pauseLevel);

    constructor () internal {
        currentPauseLevel = PauseLevel.RUNNING;
        emit PauseLevelChanged(msg.sender, currentPauseLevel);
    }

    function setPauseLevel(PauseLevel newPauseLevel) public onlyOwner {
         emit PauseLevelChanged(msg.sender, newPauseLevel);
         currentPauseLevel = newPauseLevel;
    }

    modifier hardPausable() {
        require(currentPauseLevel < PauseLevel.HARDPAUSED, "Pausable, 23: Can only execute if contract is not hard-paused.");
        _;
    }

    modifier softPausable() {
        require(currentPauseLevel < PauseLevel.SOFTPAUSED, "Pausable, 28: Can only execute if contract is not paused.");
        _;
    }
}