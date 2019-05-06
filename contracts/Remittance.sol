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

        // users will need to prove they have access to some data that hashes to this
        bytes32 hashedSecret;

        // time limits and expirations
        uint whenTxRedeemable;
        uint whenTxExpires;
    }

    mapping (bytes32 => RemittanceTx) public remittances;
    mapping (uint => bytes32) public remittanceIdsToHashes;
    mapping (bytes32 => bytes32) public completionCommitments;

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

        emit LogChangedFeeAmount(msg.sender, newFeeAmount);
        currentFlatFee = newFeeAmount;

    }

    function createNewRemittanceTx(bytes32 hashedSecret, uint txRedeemableTime, uint txExpirationTime) public softPausable payable returns(uint){

            require(msg.value > currentFlatFee, "You must send at least more ether than the fee.");

            // block timestamps seem reasonable where +- 30 seconds won't interfere with the intention of the user
            require(txExpirationTime > txRedeemableTime, "RemittanceTx would expire before it was redeemable.");
            require(txExpirationTime > block.timestamp, "Expiration time cannot be in the past.");
            require(txRedeemableTime < block.timestamp.add(_maxFutureTime), "Redeemable time is too far in the future.");
            require(txExpirationTime < block.timestamp.add(_maxExpiresTime), "Expiration time is too far in the future.");

            bytes32 remittanceIdHash = keccak256(abi.encodePacked(idCount, hashedSecret));
            RemittanceTx storage newRemittance = remittances[remittanceIdHash];

            remittanceIdsToHashes[idCount] = remittanceIdHash;
            idCount = idCount.add(1);

            newRemittance.sentAmount = msg.value;
            newRemittance.feeAmount = currentFlatFee;
            newRemittance.sendingParty = msg.sender;
            newRemittance.hashedSecret = hashedSecret; // hashed secret derived from sender and receiver secrets

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

    // potential intermediaries will need to submit a secretVerification
    // using web3.utils.soliditySha3(the_secret, some_salt) or similar
    // the_secret is itself the hash of the sending and receiving parties.
    function commitToCompleteRemittanceTx(uint remittanceId, bytes32 secretVerification) public softPausable {
        completionCommitments[keccak256(abi.encodePacked(remittanceId, msg.sender))] = secretVerification;
    }

    // after committing the secretVerification hash, the intermediary can complete the remittance
    // assuming their revealed secret matches their verification and the actual secret for the remittance
    function completeRemittanceTx(uint remittanceId, bytes32 secret, bytes32 salt) public softPausable {

        bytes32 secretVerification = completionCommitments[keccak256(abi.encodePacked(remittanceId, msg.sender))];

        require(secretVerification != 0x0, "You need to commit to complete this remittance before you can actually complete it.");

        RemittanceTx memory aRemittance = getRemittanceTxFromId(remittanceId);

        require(aRemittance.sentAmount > 0, "Transaction has a zero-value.");
        require(aRemittance.whenTxRedeemable < block.timestamp, "Transaction is not yet redeemable.");

        require(secretVerification == keccak256(abi.encodePacked(secret, salt)), "Secret verification from commitment mismatch!");
        require(aRemittance.hashedSecret == keccak256(abi.encodePacked(secret)), "Secret mismatch!");

        emit LogUnlockedBalance(aRemittance.sentAmount);
        emit LogRemittanceCompleted(msg.sender, aRemittance.feeAmount, aRemittance.sentAmount.sub(aRemittance.feeAmount));

         // remove the outstanding transaction
        delete(remittances[remittanceIdsToHashes[remittanceId]]);
        delete(remittanceIdsToHashes[remittanceId]);
        delete(secretVerification);

        // and update the locked balance
        lockedBalance = lockedBalance.sub(aRemittance.sentAmount);

        // send amount to handler
        msg.sender.transfer(aRemittance.sentAmount);
    }

    function withdrawFromUnlockedBalance(uint amountRequested, address payable whereTo) public onlyOwner softPausable {

        uint unlockedBalance = address(this).balance - lockedBalance;
        require(amountRequested <= unlockedBalance, "Requested to withdraw more than is available for withdrawal.");

        emit LogWithdrawFromUnlockedBalance(msg.sender, whereTo, amountRequested);
        whereTo.transfer(amountRequested);
    }

}