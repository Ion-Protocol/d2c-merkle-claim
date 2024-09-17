// SPDX-License-Identifier: UNLICENSED
pragma solidity =0.8.21;

import {Test, console} from "forge-std/Test.sol";
import "src/NucleusClaim.sol";
import {ERC20} from "solady/tokens/ERC20.sol";

contract EXAMPLEERC20 is ERC20 {
    /// @dev Returns the name of the token.
    function name() public view override returns (string memory) {
        return "Example";
    }

    /// @dev Returns the symbol of the token.
    function symbol() public view override returns (string memory) {
        return "E";
    }
}

contract NucleusClaimTest is Test {
    address ROOT_ROLE = makeAddr("ROOT_ROLE");
    NucleusClaim public claim;
    uint256 constant FOUR_HOURS = 60 * 60 * 4;

    function setUp() public {
        claim = new NucleusClaim(ROOT_ROLE);
        claim.setPendingPeriod(FOUR_HOURS);
    }

    function testClaim() public {
        // get values for test
        address user = _makeLeaf();
        address[] memory assets = _assets();
        uint256[] memory amounts = _amounts();

        bytes32[] memory proof = _makeProof();

        // set the pending root
        vm.prank(ROOT_ROLE);
        claim.setPendingRoot(_makeRoot());

        // claim should fail as root is still pending
        vm.startPrank(user);
        vm.expectRevert(INVALID_PARAMS.selector);
        claim.claim(proof, user, assets, amounts);

        // warp pending period and claim
        vm.warp(block.timestamp + FOUR_HOURS);
        claim.claim(proof, user, assets, amounts);

        // assert the assets were claimed
        for (uint256 i; i < assets.length; ++i) {
            assertEq(ERC20(assets[i]).balanceOf(user), amounts[i], "user did not receive correct amount of assets");
        }

        // user attempts to double claim, but should still have the same amount of assets
        claim.claim(proof, user, assets, amounts);

        // assert the assets were claimed
        for (uint256 i; i < assets.length; ++i) {
            assertEq(ERC20(assets[i]).balanceOf(user), amounts[i], "user did not receive correct amount of assets");
        }

        // user again tries to manipulate rewards by increasing the amounts, but this should fail
        amounts[0] = amounts[0] + 1 ether;
        vm.expectRevert(INVALID_PARAMS.selector);
        claim.claim(proof, user, assets, amounts);
    }

    function testEmergencyScenario() public {
        // set up pause role
        address pauser = makeAddr("pause1");
        address newRootRole = makeAddr("newRootRole");

        claim.setPauseRole(pauser, true);

        // for the sake of testing, we use the real root and pretend it is malicious as we must assume the attacker passes in a valid root for their attack
        bytes32 maliciousRoot = _makeRoot();

        // attacker gets access to private key and sets a malicious root
        vm.prank(ROOT_ROLE);
        claim.setPendingRoot(maliciousRoot);

        // as leaf is still pending, attacker cannot yet claim
        address user = _makeLeaf();
        address[] memory assets = _assets();
        uint256[] memory amounts = _amounts();

        bytes32[] memory proof = _makeProof();

        vm.expectRevert(INVALID_PARAMS.selector);
        claim.claim(proof, user, assets, amounts);

        // team uses pauser role to pause
        vm.prank(pauser);
        claim.pause();

        // now that it's paused, attempt to claim is reverted even after time has elapsed
        vm.warp(block.timestamp + FOUR_HOURS);
        vm.expectRevert(PAUSED.selector);
        claim.claim(proof, user, assets, amounts);

        // pauser cannot unpause
        vm.prank(pauser);
        vm.expectRevert(OWNER_ONLY.selector);
        claim.unpause();

        // attacker cannot unpause
        vm.prank(ROOT_ROLE);
        vm.expectRevert(OWNER_ONLY.selector);
        claim.unpause();

        // owner revokes the root role and sets a new one that publishes a new root
        // note this is really the same root but from now on we pretend that it is "safe" and the goal is to have this root pass, not fail
        claim.setRootRole(newRootRole);
        vm.prank(newRootRole);
        claim.setPendingRoot(_makeRoot());

        // attacker fails in attempt to set the root again
        vm.prank(ROOT_ROLE);
        vm.expectRevert(ROOT_ROLE_ONLY.selector);
        claim.setPendingRoot(maliciousRoot);
        // owner now waits the period and unpauses
        vm.warp(block.timestamp + FOUR_HOURS);
        claim.unpause();

        // users usual claim is valid
        claim.claim(proof, user, assets, amounts);

        for (uint256 i; i < assets.length; ++i) {
            assertEq(ERC20(assets[i]).balanceOf(user), amounts[i], "user did not receive correct amount of assets");
        }
    }

    function testTransferAssetsOut(address[] memory assets) public{
        // example ERC20 to etch our fake ERC20 addresses at
        address example = address(new EXAMPLEERC20());

        uint[] memory amounts = new uint[](assets.length);
        for(uint i; i < amounts.length; ++i){
            // bound address by left shifting to not be a precompile
            assets[i] = address(bytes20(assets[i]) << 8);
            // bound amounts as the uint representation of the addresses to get random numbers without needing to generate another address array and bound its size
            amounts[i] = bound(uint(bytes32(bytes20(assets[i]))), 1, 100 ether);
            // if first time with this address, etch it
            if(assets[i].code.length == 0){
                vm.etch(assets[i], example.code);
            }
            // deal tokens to it. If an address is used multiple times, deal multiple times
            uint prebal = ERC20(assets[i]).balanceOf(address(claim));
            deal(assets[i], address(claim), (100 ether)+prebal);
        }

        // transfer the assets
        claim.transferAssets(assets, amounts, address(this));
        for(uint i; i < amounts.length; ++i){
            // assert not that these amounts are equal but rather that they modulo to zero...
            // This is because an address can be delt multiple times, with the same token amount
            // That's why this is also valid if 2x or 3x the amounts are received as it's withdrawn in 2 instances in the transferAssets arrays
            assertEq(ERC20(assets[i]).balanceOf(address(this)) % amounts[i], 0, "Tokens not received");
        }
    }

    function testPause() public {
        assertFalse(claim.isPaused(), "should not start paused");

        // owner can give pause role
        address pauser = makeAddr("pause1");
        claim.setPauseRole(pauser, true);

        vm.prank(pauser);
        claim.pause();

        assertTrue(claim.isPaused(), "must be paused");

        // now that it's paused, attempt to claim is reverted
        address user = _makeLeaf();
        address[] memory assets = _assets();
        uint256[] memory amounts = _amounts();

        bytes32[] memory proof = _makeProof();

        vm.expectRevert(PAUSED.selector);
        claim.claim(proof, user, assets, amounts);

        // pauser cannot unpause
        vm.prank(pauser);
        vm.expectRevert(OWNER_ONLY.selector);
        claim.unpause();

        // owner can unpause
        claim.unpause();
        assertFalse(claim.isPaused(), "no longer paused");
    }

    function testPending() external {
        bytes32 newRoot = bytes32(uint256(125));

        vm.startPrank(ROOT_ROLE);
        claim.setPendingRoot(newRoot);

        assertEq(claim.root(), bytes32(0), "Root should still be 0 after update");

        vm.warp(block.timestamp + FOUR_HOURS);
        assertEq(claim.root(), newRoot, "Root should be new root after pending period");
    }

    function _dealAssets(address[] memory assets) internal {
        address example = address(new EXAMPLEERC20());
        for (uint256 i; i < assets.length; ++i) {
            vm.etch(assets[i], example.code);
            deal(assets[i], address(claim), 100 ether);
        }
    }

    // pre-determined valid values from backend
    function _makeRoot() internal pure returns (bytes32) {
        return 0x2cf12b666e19679e8f64a6f3fd27ca90fa5e745cfe5eac7da203d4f53941dd02;
    }

    // pre-determined valid values from backend
    function _makeProof() internal pure returns (bytes32[] memory proof) {
        proof = new bytes32[](3);
        proof[0] = 0xab688b4e08305519a154a6f797bf173e17dcd4dc3310de6ba98dcb31dced2336;
        proof[1] = 0x236f2d9ccfda258b88b5b087e005bf3971ac96e79c0a6683404fe4ce35cf891e;
        proof[2] = 0x4c94b04443fb35cb848cb7b33c339c607fc2a74b582009e8fa3b4a4bbbdf46bb;
    }

    // pre-determined valid values from backend
    function _makeLeaf() internal returns (address user) {
        user = 0x3ce33553e706E3bac85F7552A98B5bf7a449C06b;

        address[] memory assets = _assets();

        // create the ERC20s and deal them
        _dealAssets(assets);

        uint256[] memory amounts = _amounts();
    }

    function _assets() internal pure returns (address[] memory assets) {
        assets = new address[](2);
        assets[0] = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        assets[1] = 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984;
    }

    function _amounts() internal pure returns (uint256[] memory amounts) {
        amounts = new uint256[](2);
        amounts[0] = 5000000000000000000;
        amounts[1] = 3000000000000000000;
    }
}
