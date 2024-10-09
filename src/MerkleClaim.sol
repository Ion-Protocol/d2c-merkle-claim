// SPDX-License-Identifier: UNLICENSED
pragma solidity =0.8.21;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";
import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

error OWNER_ONLY();
error ROOT_ROLE_ONLY();
error PAUSE_ROLE_ONLY();
error PAUSED();
error INVALID_PARAMS();

/**
 * @title MerkleClaim
 * @notice A claim contract to allow reward distribution based on verified merkle leafs.
 * @custom:security-contact security@molecularlabs.io
 */
contract MerkleClaim is Ownable2Step {
    using SafeTransferLib for address;

    event NewRootRole(address newRootRole);

    event NewPendingRoot(bytes32 newPendingRoot);

    event NewActiveRoot(bytes32 newActiveRoot);

    event Pause();

    event Unpause();

    event Claim(address indexed user, address[] assets, uint256[] amounts);

    event PendingPeriodChange(uint256 newPendingPeriod);

    event SetPauseRole(address pauser);

    uint128 public constant MIN_PENDING_PERIOD = 1 hours;

    // Internal but will have a getter provided.
    bytes32 internal _root;

    uint128 public pendingPeriod = MIN_PENDING_PERIOD;
    uint128 public lastPendingUpdate;
    bytes32 public pending;
    address public rootRole;
    bool public isPaused;

    mapping(address => bool) public hasPauseRole;
    mapping(address user => mapping(address token => uint256)) public usersClaimedAmountOfAsset;

    /**
     * @param _rootRole address to receive the root role permission.
     */
    constructor(address _rootRole) Ownable(msg.sender) {
        rootRole = _rootRole;
        emit NewRootRole(_rootRole);
    }

    modifier whenNotPaused() {
        if (isPaused) {
            revert PAUSED();
        }
        _;
    }

    /**
     * @dev Only owner can unpause the contract.
     */
    function unpause() external onlyOwner {
        isPaused = false;
        emit Unpause();
    }

    /**
     * @dev Only hasPauseRole roles can pause the contract.
     */
    function pause() external {
        if (hasPauseRole[msg.sender]) {
            isPaused = true;
            emit Pause();
        } else {
            revert PAUSE_ROLE_ONLY();
        }
    }

    /**
     * @dev Owner can adjust pause roles.
     * @param _pauser address to give pause role to.
     * @param _hasPauseRole true or false to set address role in the mapping.
     */
    function setPauseRole(address _pauser, bool _hasPauseRole) external onlyOwner {
        hasPauseRole[_pauser] = _hasPauseRole;
        emit SetPauseRole(_pauser);
    }

    /**
     * @dev Sets the pending period. This is the time that a newly published
     * root will remain pending before becoming active. This allows the team
     * time to detect a malicious root push and pause the contract.
     * @param _newPendingPeriod to set in seconds; cannot be less than the MIN_PENDING_PERIOD.
     */
    function setPendingPeriod(uint128 _newPendingPeriod) external onlyOwner {
        if (_newPendingPeriod < MIN_PENDING_PERIOD) {
            revert INVALID_PARAMS();
        }
        pendingPeriod = _newPendingPeriod;
        emit PendingPeriodChange(_newPendingPeriod);
    }

    /**
     * @dev Owner may set the root role at will.
     * @param _newRootRole address to set.
     */
    function setRootRole(address _newRootRole) external onlyOwner {
        rootRole = _newRootRole;
        emit NewRootRole(_newRootRole);
    }

    /**
     * @dev Owner may transfer any amount of any asset out of this contract.
     * @param assets array of ERC20s.
     * @param amounts array of amounts to withdraw in line with assets. Must have the same length as assets.
     * @param receiver address of all assets.
     */
    function transferAssets(address[] calldata assets, uint256[] calldata amounts, address receiver)
        external
        onlyOwner
    {
        if (assets.length == amounts.length && receiver != address(0)) {
            for (uint256 i; i < assets.length;) {
                assets[i].safeTransfer(receiver, amounts[i]);
                unchecked {
                    ++i;
                }
            }
        } else {
            revert INVALID_PARAMS();
        }
    }

    /**
     * @dev Only Root Role may set the new pending root.
     * @param _newRoot to set to pending.
     */
    function setPendingRoot(bytes32 _newRoot) external {
        if (msg.sender == rootRole) {
            pending = _newRoot;
            lastPendingUpdate = uint128(block.timestamp);
            emit NewPendingRoot(_newRoot);
        } else {
            revert ROOT_ROLE_ONLY();
        }
    }

    /**
     * @dev User facing function to call and claim rewards. Can only be called when not paused.
     * @param proof is merkle proof of the leaf and root.
     * @param user to claim rewards for (sent to user).
     * @param assets array of ERC20 assets.
     * @param totalClaimableForAsset array of total amounts of each asset to claim in order.
     */
    function claim(
        bytes32[] calldata proof,
        address user,
        address[] calldata assets,
        uint256[] calldata totalClaimableForAsset
    ) external whenNotPaused {
        // only continue to transfer assets if the arrays length are the same and the merkle proof is valid
        if (assets.length == totalClaimableForAsset.length && _isValid(proof, user, assets, totalClaimableForAsset)) {
            mapping(address => uint256) storage claimAmountsByUserKey = usersClaimedAmountOfAsset[user];
            for (uint256 i; i < assets.length;) {
                address asset = assets[i];
                // rewards to distribute for each asset are = totalClaimable - claimedAmount
                // this should never underflow as rewards should never decrease and a user should have never claimed more than they
                // have in total.
                // This accounting method is useful to simplify backend logic/security while preventing double claims
                uint256 rewards = totalClaimableForAsset[i] - claimAmountsByUserKey[asset];
                claimAmountsByUserKey[asset] = totalClaimableForAsset[i];
                asset.safeTransfer(user, rewards);
                unchecked {
                    ++i;
                }
            }
            emit Claim(user, assets, totalClaimableForAsset);
        } else {
            revert INVALID_PARAMS();
        }
    }

    /**
     * @dev Public function to return root, returns pending root instead if the pending period has elapsed.
     */
    function root() public view returns (bytes32) {
        if (block.timestamp < (lastPendingUpdate + pendingPeriod) || pending == bytes32(0)) {
            return _root;
        }
        return pending;
    }

    /**
     * @dev Helper function to perform validity check in a single line.
     * @param proof The user provided merkle proof.
     * @param user The user to receive rewards (part of leaf).
     * @param assets The array of assets to claim for user.
     * @param totalClaimableForAsset The array of amounts of each asset to claim.
     */
    function _isValid(
        bytes32[] calldata proof,
        address user,
        address[] calldata assets,
        uint256[] calldata totalClaimableForAsset
    ) internal returns (bool valid) {
        bytes32 activeRoot = _getRoot();
        bytes32 leafHash = keccak256(bytes.concat(keccak256(abi.encode(user, assets, totalClaimableForAsset))));
        valid = MerkleProofLib.verifyCalldata(proof, activeRoot, leafHash);
    }

    /**
     * @dev Helper function to return root, but also switch to the pending root if the pending period has elapsed.
     */
    function _getRoot() internal returns (bytes32) {
        if (block.timestamp < (lastPendingUpdate + pendingPeriod) || pending == bytes32(0)) {
            return _root;
        }
        bytes32 _proposedRoot = pending;
        _root = _proposedRoot;
        delete pending;

        emit NewActiveRoot(_proposedRoot);
        return _proposedRoot;
    }
}
