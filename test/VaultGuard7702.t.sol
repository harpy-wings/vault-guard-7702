// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {Test} from "forge-std/Test.sol";
import {VaultGuard7702} from "../src/VaultGuard7702.sol";
import {IVaultGuard7702} from "../src/interfaces/IVaultGuard7702.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// -------------------------------------------------------------------------
// Test doubles
// -------------------------------------------------------------------------

contract MockFeeToken is ERC20 {
    constructor() ERC20("Mock Fee Token", "MFT") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockTarget {
    uint256 public lastValue;
    bytes public lastCalldata;
    uint256 public callCount;

    function echo(uint256 value) external payable returns (uint256) {
        _recordCall();
        return value;
    }

    function _recordCall() internal {
        lastValue = msg.value;
        lastCalldata = msg.data;
        callCount++;
    }
}

contract RevertTarget {
    error InsufficientBalance(uint256 required, uint256 available);

    function alwaysRevert(uint256 required, uint256 available) external pure {
        revert InsufficientBalance(required, available);
    }

    function revertWithString() external pure {
        revert("MockTarget: intentional failure");
    }
}

contract ReentrantTarget {
    function reenter(bytes calldata innerCallData) external {
        (bool success, bytes memory returndata) = msg.sender.call(innerCallData);
        if (!success) {
            assembly {
                revert(add(returndata, 32), mload(returndata))
            }
        }
    }
}

// -------------------------------------------------------------------------
// Test suite
// -------------------------------------------------------------------------

contract VaultGuard7702Test is Test {
    // EIP-712 constants — must mirror VaultGuard7702.sol exactly.
    bytes32 private constant DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant EXECUTE_TYPE_HASH = keccak256(
        "Execute(address target,bytes data,address feeToken,uint256 feeAmount,uint256 nonce,uint256 value,uint256 deadline)"
    );
    bytes32 private constant HASHED_NAME = keccak256("VaultGuard7702");
    bytes32 private constant HASHED_VERSION = keccak256("1");

    uint256 private constant USER_A_PK = 0xA11CE;
    uint256 private constant USER_B_PK = 0xB0B;
    uint256 private constant TOKEN_BALANCE = 1_000_000 ether;

    VaultGuard7702 internal implementation;
    MockFeeToken internal feeToken;
    MockTarget internal target;
    RevertTarget internal revertTarget;
    ReentrantTarget internal reentrantTarget;

    address internal userA;
    address internal userB;
    address internal relayer;

    function setUp() public {
        implementation = new VaultGuard7702();
        feeToken = new MockFeeToken();
        target = new MockTarget();
        revertTarget = new RevertTarget();
        reentrantTarget = new ReentrantTarget();

        userA = vm.addr(USER_A_PK);
        userB = vm.addr(USER_B_PK);
        relayer = makeAddr("relayer");

        // Simulate EIP-7702 persistent delegation: implementation bytecode runs at each EOA.
        vm.signAndAttachDelegation(address(implementation), USER_A_PK);
        vm.signAndAttachDelegation(address(implementation), USER_B_PK);

        vm.deal(userA, 100 ether);
        vm.deal(userB, 100 ether);

        feeToken.mint(userA, TOKEN_BALANCE);
        feeToken.mint(userB, TOKEN_BALANCE);
    }

    // -------------------------------------------------------------------------
    // Deployment & delegation context
    // -------------------------------------------------------------------------

    function test_DeploysImplementation_WithBytecode() public view {
        assertGt(address(implementation).code.length, 0);
    }

    function test_EIP7702Delegation_MapsAddressThisToUserEOA() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.data = abi.encodeCall(MockTarget.echo, (42));

        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        bytes memory result = _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        assertEq(abi.decode(result, (uint256)), 42);
        assertEq(target.callCount(), 1);
    }

    function test_EIP7702Delegation_VmEtch_SimulatesSameExecutionContext() public {
        uint256 userCPk = 0xC0FFEE;
        address userC = vm.addr(userCPk);
        vm.deal(userC, 10 ether);
        feeToken.mint(userC, TOKEN_BALANCE);

        VaultGuard7702 freshImpl = new VaultGuard7702();
        vm.etch(userC, address(freshImpl).code);

        ExecuteIntent memory intent = ExecuteIntent({
            target: address(target),
            data: abi.encodeCall(MockTarget.echo, (777)),
            feeToken: address(feeToken),
            feeAmount: 0,
            nonce: 88,
            value: 0,
            deadline: block.timestamp + 1 hours
        });

        (bytes memory signature,,,,) = _signIntent(userCPk, userC, intent);

        vm.prank(relayer);
        bytes memory result = _wallet(userC)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        assertEq(abi.decode(result, (uint256)), 777);
    }

    // -------------------------------------------------------------------------
    // EIP-712 execute — success paths
    // -------------------------------------------------------------------------

    function test_Execute_WithBytesSignature_Success() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.feeAmount = 0.25 ether;
        intent.value = 0.1 ether;
        intent.data = abi.encodeCall(MockTarget.echo, (123));

        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        uint256 relayerBefore = feeToken.balanceOf(relayer);
        uint256 userBefore = userA.balance;

        vm.prank(relayer);
        bytes memory result = _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        assertEq(abi.decode(result, (uint256)), 123);
        assertEq(target.lastValue(), intent.value);
        assertEq(feeToken.balanceOf(relayer), relayerBefore + intent.feeAmount);
        assertEq(userA.balance, userBefore - intent.value);
    }

    function test_Execute_EmitsExecutedEvent_WithBytesSignature() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.data = abi.encodeCall(MockTarget.echo, (456));
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        vm.expectEmit(true, true, true, false, userA);
        emit IVaultGuard7702.Executed(
            intent.target,
            intent.data,
            intent.feeToken,
            intent.feeAmount,
            relayer,
            intent.nonce,
            abi.encode(uint256(456))
        );
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );
    }

    function test_Execute_WithVRSSignature_Success() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.nonce = 7;
        intent.data = abi.encodeCall(MockTarget.echo, (99));

        (,, uint8 v, bytes32 r, bytes32 s) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        bytes memory result = _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                v,
                r,
                s
            );

        assertEq(abi.decode(result, (uint256)), 99);
    }

    // -------------------------------------------------------------------------
    // Cross-user replay protection
    // -------------------------------------------------------------------------

    function test_RevertIf_InvalidSignature_CrossUserReplay() public {
        ExecuteIntent memory intent = _defaultIntent();
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        vm.expectRevert(IVaultGuard7702.InvalidSignature.selector);
        _wallet(userB)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );
    }

    function test_RevertIf_InvalidSignature_OnImplementationDirectly() public {
        ExecuteIntent memory intent = _defaultIntent();
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        vm.expectRevert(IVaultGuard7702.InvalidSignature.selector);
        implementation.execute(
            intent.target,
            intent.data,
            intent.feeToken,
            intent.feeAmount,
            intent.nonce,
            intent.value,
            intent.deadline,
            signature
        );
    }

    function test_RevertIf_InvalidSignature_WrongSignerKey() public {
        ExecuteIntent memory intent = _defaultIntent();
        (bytes memory signature,,,,) = _signIntent(USER_B_PK, userB, intent);

        vm.prank(relayer);
        vm.expectRevert(IVaultGuard7702.InvalidSignature.selector);
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );
    }

    function test_RevertIf_InvalidSignature_TamperedCalldata() public {
        ExecuteIntent memory intent = _defaultIntent();
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        bytes memory tamperedData = abi.encodeCall(MockTarget.echo, (1337));

        vm.prank(relayer);
        vm.expectRevert(IVaultGuard7702.InvalidSignature.selector);
        _wallet(userA)
            .execute(
                intent.target,
                tamperedData,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );
    }

    function test_RevertIf_InvalidSignature_VRSOverload() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.nonce = 11;
        (,, uint8 v, bytes32 r, bytes32 s) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        vm.expectRevert(IVaultGuard7702.InvalidSignature.selector);
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                v,
                r,
                bytes32(uint256(s) ^ 1)
            );
    }

    // -------------------------------------------------------------------------
    // Nonce replay prevention
    // -------------------------------------------------------------------------

    function test_RevertIf_NonceAlreadyUsed_SecondExecution() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.nonce = 42;
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.startPrank(relayer);
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        vm.expectRevert(abi.encodeWithSelector(IVaultGuard7702.NonceAlreadyUsed.selector, intent.nonce));
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );
        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Deadline enforcement
    // -------------------------------------------------------------------------

    function test_RevertIf_DeadlineExpired_AfterTimestamp() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.deadline = block.timestamp + 100;
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.warp(block.timestamp + 101);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IVaultGuard7702.DeadlineExpired.selector, intent.deadline));
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );
    }

    function test_Execute_DeadlineAtCurrentTimestamp_Success() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.deadline = block.timestamp;
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        assertEq(target.callCount(), 1);
    }

    // -------------------------------------------------------------------------
    // Gas sponsorship & fee settlement
    // -------------------------------------------------------------------------

    function test_Execute_WithFee_TransfersERC20ToRelayer() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.feeAmount = 3 ether;
        intent.nonce = 1;
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        uint256 relayerBefore = feeToken.balanceOf(relayer);
        uint256 userBefore = feeToken.balanceOf(userA);

        vm.prank(relayer);
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        assertEq(feeToken.balanceOf(relayer), relayerBefore + intent.feeAmount);
        assertEq(feeToken.balanceOf(userA), userBefore - intent.feeAmount);
    }

    function test_Execute_ZeroFee_SkipsTokenTransfer() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.feeAmount = 0;
        intent.feeToken = address(feeToken);
        intent.nonce = 2;
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        uint256 relayerBefore = feeToken.balanceOf(relayer);
        uint256 userBefore = feeToken.balanceOf(userA);

        vm.prank(relayer);
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        assertEq(feeToken.balanceOf(relayer), relayerBefore);
        assertEq(feeToken.balanceOf(userA), userBefore);
        assertEq(target.callCount(), 1);
    }

    // -------------------------------------------------------------------------
    // Revert bubbling
    // -------------------------------------------------------------------------

    function test_RevertIf_TargetReverts_BubblesCustomError() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.target = address(revertTarget);
        intent.data = abi.encodeCall(RevertTarget.alwaysRevert, (100, 0));
        intent.nonce = 3;
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(RevertTarget.InsufficientBalance.selector, uint256(100), uint256(0)));
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );
    }

    function test_RevertIf_TargetReverts_DoesNotTransferFee() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.target = address(revertTarget);
        intent.data = abi.encodeCall(RevertTarget.alwaysRevert, (1, 0));
        intent.feeAmount = 5 ether;
        intent.nonce = 4;
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        uint256 relayerBefore = feeToken.balanceOf(relayer);

        vm.prank(relayer);
        vm.expectRevert();
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        assertEq(feeToken.balanceOf(relayer), relayerBefore);
    }

    function test_RevertIf_TargetReverts_BubblesStringReason() public {
        ExecuteIntent memory intent = _defaultIntent();
        intent.target = address(revertTarget);
        intent.data = abi.encodeCall(RevertTarget.revertWithString, ());
        intent.nonce = 12;
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        vm.prank(relayer);
        vm.expectRevert("MockTarget: intentional failure");
        _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );
    }

    // -------------------------------------------------------------------------
    // Transient reentrancy guard
    // -------------------------------------------------------------------------

    function test_RevertIf_ReentrantCall_DuringExecute() public {
        ExecuteIntent memory inner = _defaultIntent();
        inner.nonce = 999;
        inner.data = abi.encodeCall(MockTarget.echo, (1));
        (bytes memory innerSig,,,,) = _signIntent(USER_A_PK, userA, inner);

        bytes memory innerCall = abi.encodeWithSignature(
            "execute(address,bytes,address,uint256,uint256,uint256,uint256,bytes)",
            inner.target,
            inner.data,
            inner.feeToken,
            inner.feeAmount,
            inner.nonce,
            inner.value,
            inner.deadline,
            innerSig
        );

        ExecuteIntent memory outer = _defaultIntent();
        outer.target = address(reentrantTarget);
        outer.nonce = 5;
        outer.data = abi.encodeCall(ReentrantTarget.reenter, (innerCall));
        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, outer);

        vm.prank(relayer);
        vm.expectRevert(ReentrancyGuardTransient.ReentrancyGuardReentrantCall.selector);
        _wallet(userA)
            .execute(
                outer.target,
                outer.data,
                outer.feeToken,
                outer.feeAmount,
                outer.nonce,
                outer.value,
                outer.deadline,
                signature
            );
    }

    // -------------------------------------------------------------------------
    // Receive & fallback
    // -------------------------------------------------------------------------

    function test_Receive_AcceptsNativeTransfer_DelegatedEOA() public {
        uint256 beforeBalance = userA.balance;

        (bool success,) = userA.call{value: 1 ether}("");
        assertTrue(success);
        assertEq(userA.balance, beforeBalance + 1 ether);
    }

    function test_Fallback_AcceptsValueWithUnknownCalldata() public {
        uint256 beforeBalance = userA.balance;

        (bool success,) = userA.call{value: 0.5 ether}(hex"deadbeef");
        assertTrue(success);
        assertEq(userA.balance, beforeBalance + 0.5 ether);
    }

    // -------------------------------------------------------------------------
    // Fuzz
    // -------------------------------------------------------------------------

    function testFuzz_Execute_RandomizedPayload(
        uint256 feeAmount,
        uint256 nonce,
        uint256 value,
        uint256 echoValue,
        bytes calldata randomData
    ) public {
        feeAmount = bound(feeAmount, 0, 100 ether);
        value = bound(value, 0, 10 ether);
        nonce = bound(nonce, 0, type(uint128).max);
        echoValue = bound(echoValue, 0, type(uint128).max);

        bytes memory data = bytes.concat(abi.encodeCall(MockTarget.echo, (echoValue)), randomData);

        ExecuteIntent memory intent = ExecuteIntent({
            target: address(target),
            data: data,
            feeToken: address(feeToken),
            feeAmount: feeAmount,
            nonce: nonce,
            value: value,
            deadline: block.timestamp + 1 days
        });

        (bytes memory signature,,,,) = _signIntent(USER_A_PK, userA, intent);

        uint256 relayerBefore = feeToken.balanceOf(relayer);
        uint256 userEthBefore = userA.balance;

        vm.prank(relayer);
        bytes memory result = _wallet(userA)
            .execute(
                intent.target,
                intent.data,
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline,
                signature
            );

        assertEq(abi.decode(result, (uint256)), echoValue);
        assertEq(feeToken.balanceOf(relayer), relayerBefore + feeAmount);
        assertEq(userA.balance, userEthBefore - value);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    struct ExecuteIntent {
        address target;
        bytes data;
        address feeToken;
        uint256 feeAmount;
        uint256 nonce;
        uint256 value;
        uint256 deadline;
    }

    function _defaultIntent() internal view returns (ExecuteIntent memory intent) {
        intent = ExecuteIntent({
            target: address(target),
            data: abi.encodeCall(MockTarget.echo, (1)),
            feeToken: address(feeToken),
            feeAmount: 0,
            nonce: 0,
            value: 0,
            deadline: block.timestamp + 1 hours
        });
    }

    function _wallet(address eoa) internal pure returns (VaultGuard7702) {
        return VaultGuard7702(payable(eoa));
    }

    function _domainSeparator(address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPE_HASH, HASHED_NAME, HASHED_VERSION, block.chainid, verifyingContract));
    }

    function _structHash(ExecuteIntent memory intent) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EXECUTE_TYPE_HASH,
                intent.target,
                keccak256(intent.data),
                intent.feeToken,
                intent.feeAmount,
                intent.nonce,
                intent.value,
                intent.deadline
            )
        );
    }

    function _digest(ExecuteIntent memory intent, address verifyingContract) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(verifyingContract), _structHash(intent)));
    }

    function _signIntent(uint256 privateKey, address verifyingContract, ExecuteIntent memory intent)
        internal
        view
        returns (bytes memory signature, bytes32 digest, uint8 v, bytes32 r, bytes32 s)
    {
        digest = _digest(intent, verifyingContract);
        (v, r, s) = vm.sign(privateKey, digest);
        signature = abi.encodePacked(r, s, v);
    }
}
