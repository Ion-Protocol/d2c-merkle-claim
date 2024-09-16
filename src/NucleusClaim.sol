// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {MerkleProofLib} from "solady/utils/MerkleProofLib.sol";

error OWNER_ONLY();
error ROOT_ROLE_ONLY();
error PAUSE_ROLE_ONLY();
error PAUSED();
error INVALID_PARAMS();

event NewOwner(address newOwner);

event NewRootRole(address newRootRole);

event NewPendingRoot(bytes32 newPendingRoot);

event NewActiveRoot(bytes32 newActiveRoot);

event Pause();

event Unpause();

event Claim(address user, address[] assets, uint256[] amounts);

event PendingPeriodChange(uint256 newPendingPeriod);

/**
 * @title NucleusClaim
 * @notice a claim contract to allow reward distribution based on verified merkle leafs.
 */
contract NucleusClaim {
    using SafeTransferLib for address;

    // internal but will have a getter provided
    bytes32 internal _root;

    uint256 public pendingPeriod;
    uint256 public lastPendingUpdate;
    bytes32 public pending;
    address public owner;
    address public rootRole;
    bool public isPaused;

    mapping(address => bool) public hasPauseRole;
    mapping(address => mapping(address => uint256)) public usersClaimedAmountOfAsset;

    /// @param _rootRole address to receive the root role permission
    constructor(address _rootRole) {
        owner = msg.sender;
        emit NewOwner(msg.sender);
        rootRole = _rootRole;
        emit NewRootRole(_rootRole);
    }

    modifier onlyOwner() {
        if (msg.sender == owner) {
            _;
        } else {
            revert OWNER_ONLY();
        }
    }

    modifier whenNotPaused() {
        if (isPaused) {
            revert PAUSED();
        }
        _;
    }

    /// @dev only owner can unpause the contract
    function unpause() external onlyOwner {
        isPaused = false;
        emit Unpause();
    }

    /// @dev only hasPauseRole roles can pause the contract
    function pause() external {
        if (hasPauseRole[msg.sender]) {
            isPaused = true;
            emit Pause();
        } else {
            revert PAUSE_ROLE_ONLY();
        }
    }

    /// @dev owner can adjust pause roles
    function setPauseRole(address _pauser, bool _hasPauseRole) external onlyOwner {
        hasPauseRole[_pauser] = _hasPauseRole;
    }

    /**
     * @dev sets the pending period. This is the time that a newly published root will remain pending before becoming active. This allows the team time to detect a malicious root push and pause the contract
     * @param _newPendingPeriod to set in seconds
     */
    function setPendingPeriod(uint256 _newPendingPeriod) external onlyOwner {
        pendingPeriod = _newPendingPeriod;
        emit PendingPeriodChange(_newPendingPeriod);
    }

    /**
     * @dev Owner may set the root role at will
     * @param _newRootRole address to set
     */
    function setRootRole(address _newRootRole) external onlyOwner {
        rootRole = _newRootRole;
        emit NewRootRole(_newRootRole);
    }

    /**
     * @dev Owner may transfer any amount of any asset out of this contract
     * @param assets array of ERC20s
     * @param amounts array of amounts to withdraw in line with assets. Must have the same length as assets
     * @param receiver address of all assets
     */
    function transferAssets(address[] calldata assets, uint256[] calldata amounts, address receiver)
        external
        onlyOwner
    {
        if (assets.length == amounts.length) {
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
     * @dev Only Root Role may set the new pending root
     * @param _newRoot to set to pending
     */
    function setPendingRoot(bytes32 _newRoot) external {
        if (msg.sender == rootRole) {
            pending = _newRoot;
            lastPendingUpdate = block.timestamp;
            emit NewPendingRoot(_newRoot);
        } else {
            revert ROOT_ROLE_ONLY();
        }
    }

    /**
     * @dev user facing function to call and claim rewards. Can only be called when not paused
     * @param proof is merkle proof of the leaf and root
     * @param user to claim rewards for (sent to user)
     * @param assets array of ERC20 assets
     * @param totalClaimableForAsset array of total amounts of each asset to claim in order
     */
    function claim(
        bytes32[] calldata proof,
        address user,
        address[] calldata assets,
        uint256[] calldata totalClaimableForAsset
    ) external whenNotPaused {
        bytes32 _root = _getRoot();
        bytes32 leafHash = keccak256(bytes.concat(keccak256(abi.encode(user, assets, totalClaimableForAsset))));
        bool valid = MerkleProofLib.verifyCalldata(proof, _root, leafHash);

        if (valid) {
            assert(assets.length == totalClaimableForAsset.length);
            for (uint256 i; i < assets.length;) {
                address asset = assets[i];
                uint256 rewards = totalClaimableForAsset[i] - usersClaimedAmountOfAsset[user][asset];
                usersClaimedAmountOfAsset[user][asset] = totalClaimableForAsset[i];
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

    /// @dev public function to return root, returns pending root instead if the pending period has elapsed
    function root() public view returns (bytes32) {
        if (pending == _root || block.timestamp < (lastPendingUpdate + pendingPeriod)) {
            return _root;
        }
        return pending;
    }

    /// @dev heper function to return root, but also switch to the pending root if the pending period has elapsed
    function _getRoot() internal returns (bytes32) {
        if (block.timestamp < (lastPendingUpdate + pendingPeriod) || pending == bytes32(0)) {
            return _root;
        }
        _root = pending;
        delete pending;

        emit NewActiveRoot(pending);
        return _root;
    }
}
