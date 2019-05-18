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

        // fee user will pay to contract to structure the remittance
        uint feeAmount;

        // keep track of sending party in case of refund
        address payable sendingParty;

        // time limits and expirations
        uint whenTxRedeemable;
        uint whenTxExpires;
    }

    mapping (bytes32 => RemittanceTx) public remittances;

    event LogChangedFeeAmount(address whoChanged, uint newFeeAmount);
    event LogCreatedRemittanceTx(address whoSent, uint whatValue, uint whatFee, address allowedIntermediary);
    event LogRemittanceRefunded(address whoExecutedRefund, address whereRefundWasSent, uint howMuchRefunded);
    event LogRemittanceCompleted(address whoCompletedRemittance, uint feeAmount, uint deliveredAmount);
    event LogLockedBalance(uint amount);
    event LogUnlockedBalance(uint amount);
    event LogWithdrawFromUnlockedBalance(address whoWithdrew, address withdrewToAddress, uint amount);

    // will add user adjustable valid-after and expiration times in next iteration
    constructor(uint initialFlatFee) public {

        _maxFutureTime = 7 days; // can only be one week into the future
        _maxExpiresTime = 14 days; // can only expire up to two weeks in the future

        currentFlatFee = initialFlatFee;

    }

    function changeFeeAmount(uint newFeeAmount) public onlyOwner softPausable {

        // fee set here goes to contract owner, not to remittance facilitator
        emit LogChangedFeeAmount(msg.sender, newFeeAmount);
        currentFlatFee = newFeeAmount;

    }

    // The hashedSecretAsID comes from a hashed password and a facilitator destination address. It is computed on the front end.
    function createNewRemittanceTx(bytes32 hashedSecretAsID, uint txRedeemableTime, uint txExpirationTime) public softPausable payable {

            require(msg.value > currentFlatFee, "You must, at least, send enough ether to cover the fee.");

            // block timestamps seem reasonable where +- 30 seconds won't interfere with the intention of the user
            require(txExpirationTime > txRedeemableTime, "RemittanceTx would expire before it was redeemable.");
            require(txExpirationTime > block.timestamp, "Expiration time cannot be in the past.");
            require(txRedeemableTime < block.timestamp.add(_maxFutureTime), "Redeemable time is too far in the future.");
            require(txExpirationTime < block.timestamp.add(_maxExpiresTime), "Expiration time is too far in the future.");

            RemittanceTx storage newRemittance = remittances[hashedSecretAsID];

            newRemittance.sentAmount = msg.value;
            newRemittance.feeAmount = currentFlatFee;
            newRemittance.sendingParty = msg.sender;
            newRemittance.whenTxRedeemable = txRedeemableTime;
            newRemittance.whenTxExpires = txExpirationTime;

            emit LogLockedBalance(msg.value);
            lockedBalance = lockedBalance.add(msg.value);
    }

    function refundExpiredRemittanceTx(bytes32 hashedSecretAsID) public softPausable {

        RemittanceTx memory aRemittance = remittances[hashedSecretAsID];

        require(block.timestamp >= aRemittance.whenTxExpires, "Transaction has not yet expired. Ineligable for refund.");

        emit LogRemittanceRefunded(msg.sender, aRemittance.sendingParty, aRemittance.sentAmount);
        emit LogUnlockedBalance(aRemittance.sentAmount);

         // remove the transaction record
        delete(remittances[hashedSecretAsID]);

        // and update the locked balance
        lockedBalance = lockedBalance.sub(aRemittance.sentAmount);

        // finally, refund the transaction to original sender
        aRemittance.sendingParty.transfer(aRemittance.sentAmount);
    }

    function completeRemittanceTx(bytes32 hashedSecret) public softPausable {

        bytes32 secretVerification = keccak256(abi.encodePacked(hashedSecret, msg.sender));

        RemittanceTx memory aRemittance = remittances[secretVerification];

        require(aRemittance.sentAmount > 0, "Transaction has a zero-value.");
        require(aRemittance.whenTxRedeemable < block.timestamp, "Transaction is not yet redeemable.");

        emit LogUnlockedBalance(aRemittance.sentAmount);
        emit LogRemittanceCompleted(msg.sender, aRemittance.feeAmount, aRemittance.sentAmount.sub(aRemittance.feeAmount));

         // remove the outstanding transaction
        delete(remittances[secretVerification]);

        // and update the locked balance
        lockedBalance = lockedBalance.sub(aRemittance.sentAmount);

        // send amount, less remittance contract use fee, to facilitator
        msg.sender.transfer(aRemittance.sentAmount.sub(aRemittance.feeAmount));
    }

    function withdrawFromUnlockedBalance(uint amountRequested, address payable whereTo) public onlyOwner softPausable {

        uint unlockedBalance = address(this).balance - lockedBalance;
        require(amountRequested <= unlockedBalance, "Requested to withdraw more than is available for withdrawal.");

        emit LogWithdrawFromUnlockedBalance(msg.sender, whereTo, amountRequested);
        whereTo.transfer(amountRequested);
    }

}