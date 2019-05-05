pragma solidity ^0.5.7;

import "./OwnablePausable.sol";
import "./SafeMath.sol";

contract Remittance is OwnablePausable {

    using SafeMath for uint;

    uint idCount;
    uint public currentFlatFee;
    uint public lockedBalance;
    uint internal _maxFutureTime;
    uint internal _maxExpiresTime;

    struct RemittanceTx {

        // keep track of the amount that was sent
        uint sentAmount;

        // fee user will pay to facilitate the remittance
        uint feeAmount;

        // keep track of sending party in case of refund
        address payable sendingParty;

        // keep track of address allowed to execute a transaction (otherwise front-running possible)
        address payable allowedIntermediary;

        // users will need to provide some strings that hash to these values
        bytes32 authorizationDblHash1;
        bytes32 authorizationDblHash2;

        // time limits and expirations
        uint whenTxRedeemable;
        uint whenTxExpires;
    }

    mapping (bytes32 => RemittanceTx) public remittances;
    mapping (uint => bytes32) public remittanceIdsToHashes;

    event LogChangedFeeAmount(address whoChanged, uint newFeeAmount);
    event LogCreatedRemittanceTx(address whoSent, uint whatValue, uint whatFee, address allowedIntermediary);
    event LogRemittanceRefunded(address whoExecutedRefund, address whereRefundWasSent, uint howMuchRefunded);
    event LogRemittanceCompleted(address whoCompletedRemittance, uint feeAmount, uint deliveredAmount);
    event LogLockedBalance(uint amount);
    event LogUnlockedBalance(uint amount);
    event LogWithdrawFromUnlockedBalance(address whoWithdrew, address withdrewToAddress, uint amount);

    // will add user adjustable valid-after and expiration times in next iteration
    constructor(uint initialFlatFee) public {

        _maxFutureTime = 60 * 60 * 24 * 7; // can only be one week into the future
        _maxExpiresTime = 60 * 60 * 24 * 14; // can only expire up to two weeks in the future

        currentFlatFee = initialFlatFee;

    }

    function changeFeeAmount(uint newFeeAmount) public onlyOwner softPausable {

        emit LogChangedFeeAmount(msg.sender, newFeeAmount);
        currentFlatFee = newFeeAmount;

    }

    function createNewRemittanceTx(
        bytes32 dblHashedSecret1,
        bytes32 dblHashedSecret2,
        address payable allowedIntermediary,
        uint txRedeemableTime,
        uint txExpirationTime
        )
        public softPausable payable returns(uint){

            require(msg.value > currentFlatFee, "You must send at least more ether than the fee.");

            // block timestamps seem reasonable where +- 30 seconds won't interfere with the intention of the user
            require(txExpirationTime > txRedeemableTime, "RemittanceTx would expire before it was redeemable.");
            require(txExpirationTime > block.timestamp, "Expiration time cannot be in the past.");
            require(txRedeemableTime < block.timestamp.add(_maxFutureTime), "Redeemable time is too far in the future.");
            require(txExpirationTime < block.timestamp.add(_maxExpiresTime), "Expiration time is too far in the future.");

            bytes32 remittanceIdHash = keccak256(abi.encodePacked(msg.sender, dblHashedSecret1, dblHashedSecret2));
            RemittanceTx storage newRemittance = remittances[remittanceIdHash];

            remittanceIdsToHashes[idCount] = remittanceIdHash;
            idCount = idCount.add(1);

            newRemittance.sentAmount = msg.value;
            newRemittance.feeAmount = currentFlatFee;
            newRemittance.sendingParty = msg.sender;
            newRemittance.allowedIntermediary = allowedIntermediary;
            newRemittance.authorizationDblHash1 = dblHashedSecret1;
            newRemittance.authorizationDblHash2 = dblHashedSecret2;
            newRemittance.whenTxRedeemable = txRedeemableTime;
            newRemittance.whenTxExpires = txExpirationTime;

            emit LogLockedBalance(msg.value);
            lockedBalance = lockedBalance.add(msg.value);

            return idCount.sub(1);
    }

    function getRemittanceTxFromId(uint remittanceId) internal view returns(RemittanceTx memory){
        bytes32 remittanceHashId = remittanceIdsToHashes[remittanceId];
        require(remittanceHashId != 0x0, "No outstanding transaction matches details.");

        return remittances[remittanceHashId];
    }

    function refundExpiredRemittanceTx(uint remittanceId) public softPausable {

        RemittanceTx memory aRemittance = getRemittanceTxFromId(remittanceId);

        require(block.timestamp >= aRemittance.whenTxExpires, "Transaction has not yet expired. Ineligable for refund.");

        emit LogRemittanceRefunded(msg.sender, aRemittance.sendingParty, aRemittance.sentAmount);
        emit LogUnlockedBalance(aRemittance.sentAmount);

         // remove the outstanding transaction
        delete(remittances[remittanceIdsToHashes[remittanceId]]);
        delete(remittanceIdsToHashes[remittanceId]);

        // and update the locked balance
        lockedBalance = lockedBalance.sub(aRemittance.sentAmount);

        // refund the transaction to original sender
        aRemittance.sendingParty.transfer(aRemittance.sentAmount);
    }

    function completeRemittanceTx(uint remittanceId, bytes32 hashedSecret1, bytes32 hashedSecret2) public softPausable {

        RemittanceTx memory aRemittance = getRemittanceTxFromId(remittanceId);

        require(aRemittance.sentAmount > 0, "Transaction has a zero-value.");
        require(aRemittance.whenTxRedeemable < block.timestamp, "Transaction is not yet redeemable.");

        bytes32 dblHashedSecret1 = keccak256(abi.encodePacked(hashedSecret1));
        bytes32 dblHashedSecret2 = keccak256(abi.encodePacked(hashedSecret2));
        require(aRemittance.authorizationDblHash1 == dblHashedSecret1, "Secret1 mismatch.");
        require(aRemittance.authorizationDblHash2 == dblHashedSecret2, "Secret2 mismatch.");

        emit LogUnlockedBalance(aRemittance.sentAmount);
        emit LogRemittanceCompleted(msg.sender, aRemittance.feeAmount, aRemittance.sentAmount.sub(aRemittance.feeAmount));

         // remove the outstanding transaction
        delete(remittances[remittanceIdsToHashes[remittanceId]]);
        delete(remittanceIdsToHashes[remittanceId]);

        // and update the locked balance
        lockedBalance = lockedBalance.sub(aRemittance.sentAmount);

        // send amount to handler
        aRemittance.allowedIntermediary.transfer(aRemittance.sentAmount);
    }

    function changeAllowedIntermediary(uint remittanceId, address payable newAllowedIntermediary) public softPausable {

        RemittanceTx memory aRemittance = getRemittanceTxFromId(remittanceId);

        require(msg.sender == aRemittance.sendingParty, "Only remittance sender can change remittance handler.");

        RemittanceTx storage editableRemittance = remittances[remittanceIdsToHashes[remittanceId]];
        editableRemittance.allowedIntermediary = newAllowedIntermediary;
    }

    function withdrawFromUnlockedBalance(uint amountRequested, address payable whereTo) public onlyOwner softPausable {

        uint unlockedBalance = address(this).balance - lockedBalance;
        require(amountRequested <= unlockedBalance, "Requested to withdraw more than is available for withdrawal.");

        emit LogWithdrawFromUnlockedBalance(msg.sender, whereTo, amountRequested);
        whereTo.transfer(amountRequested);
    }

}