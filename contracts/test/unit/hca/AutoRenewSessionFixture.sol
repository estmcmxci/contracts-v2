// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// solhint-disable private-vars-leading-underscore, func-name-mixedcase

import {Test} from "forge-std/Test.sol";
import {Execution} from "nexus/types/DataTypes.sol";

import {HCAOperationHashLib} from "../../../src/hca/libraries/HCAOperationHashLib.sol";
import {HCASmartSessionLib} from "../../../src/hca/libraries/HCASmartSessionLib.sol";

/// @title Session proof machinery for the auto-renew policy tests
/// @notice A COPY of the private helpers in `HCAOwnerAndSessionValidator.t.sol`, taken at commit
///         `3e54cdb8`. They are private to that contract and this needs them.
/// @dev Copied on purpose rather than lifted. Lifting would edit a file this change must leave
///      alone, and the diff story is "we added one rule and altered none". The cost is that the
///      logic lives twice in the repo. If `HCAOwnerAndSessionValidator.t.sol` changes its proof
///      format, this file must follow, and the 150-byte header is the thing most likely to move.
///      See `progress/contracts.md` under T1.
abstract contract AutoRenewSessionFixture is Test {

    bytes32 constant OPS_TYPEHASH = keccak256("Ops(address to,uint256 value,bytes data)");
    bytes32 constant OP_TYPEHASH =
        keccak256("Op(bytes32 vt,Ops[] ops)Ops(address to,uint256 value,bytes data)");
    bytes32 constant SMART_SESSION_DOMAIN_TYPEHASH =
        0xb03948446334eb9b2196d5eb166f69b9d49403eb4a12f36de8d3f9f3cb8e15c3;
    bytes32 constant SMART_SESSION_NAME_HASH =
        0x909aaff4c04d02fd420ef163a6d750c002b0a00dc41a031ba039e3fdb4732133;
    bytes32 constant SMART_SESSION_VERSION_HASH =
        0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;
    bytes32 constant SIGNED_SESSION_TYPEHASH =
        0x984917e689987af96289e12c5f5e934fcdf1df4186108f69ff7e8c3df950ce33;
    bytes32 constant CHAIN_SESSION_TYPEHASH =
        0xabc350ff4773ba356e85e2d2ee58d7d7511767acdb108b59058f5b4a5afc074b;
    bytes32 constant MULTI_CHAIN_SESSION_TYPEHASH =
        0xb4323194e4ca3723804b96dc7a0960bde1afff2b080b8b288fdc264c82e21357;
    bytes32 constant DEFAULT_SIGNED_PERMISSIONS_HASH =
        0x242b79d1322c5e6b12b617584cc2d5766cf18be6feb6acfa469ccf289e11e504;

    address constant SMART_SESSION_EMISSARY = 0xad568B3F825A8d5FFc06DD3253526B64D810Ae89;
    address constant OWNABLE_SESSION_VALIDATOR = 0x000000000013fdB5234E4E3162a810F54d9f7E98;

    uint256 constant SOURCE_CHAIN_ID = 84_532;
    uint256 constant SESSION_KEY = 0x5E5510;
    uint256 constant OWNER_KEY = 0x0A11CE;

    struct SessionEnableProofFixture {
        address sessionKey;
        uint48 validUntil;
        uint96 sessionNonce;
        address resolver;
        address refundToken;
        uint96 maxRefundExchangeRate;
        uint48 maxRefundGasOverhead;
        uint96 maxRefundAmount;
        uint8 sessionToEnableIndex;
        address renewPaymentToken;
        uint64 renewalDuration;
        uint96 maxRenewSpend;
        HCASmartSessionLib.HashAndChainId[] hashesAndChainIds;
        bytes32 ownerR;
        bytes32 ownerS;
        uint8 ownerV;
    }

    function _encodeExecutions(Execution[] memory executions) internal pure returns (bytes memory) {
        bytes memory packed =
            abi.encodePacked(
                bytes2(HCAOperationHashLib.ERC7579_ERC1271_MODE),
                uint8(executions.length)
            );
        for (uint256 i; i < executions.length; ++i) {
            Execution memory execution = executions[i];
            assertEq(execution.value, 0);
            assertLe(execution.callData.length, type(uint24).max);
            packed = bytes.concat(
                packed,
                abi.encodePacked(
                    execution.target,
                    uint24(execution.callData.length),
                    execution.callData
                )
            );
        }
        return packed;
    }

    function _decodeOperation(bytes memory operationData)
        internal
        pure
        returns (bytes32 mode, Execution[] memory executions)
    {
        if (operationData.length < 3) {
            revert HCAOperationHashLib.InvalidOperationEncoding();
        }
        bytes2 modePrefix;
        assembly ("memory-safe") {
            modePrefix := mload(add(operationData, 0x20))
        }
        mode = bytes32(modePrefix);
        uint256 count = uint8(operationData[2]);
        executions = new Execution[](count);
        uint256 cursor = 3;
        for (uint256 i; i < count; ++i) {
            if (operationData.length < cursor + 23) {
                revert HCAOperationHashLib.InvalidOperationEncoding();
            }
            address target;
            assembly ("memory-safe") {
                target := shr(96, mload(add(add(operationData, 0x20), cursor)))
            }
            uint256 callDataLength =
                (uint256(uint8(operationData[cursor + 20])) << 16) |
                (uint256(uint8(operationData[cursor + 21])) << 8) |
                uint256(uint8(operationData[cursor + 22]));
            cursor += 23;
            if (operationData.length < cursor + callDataLength) {
                revert HCAOperationHashLib.InvalidOperationEncoding();
            }
            executions[i] = Execution({target: target, value: 0, callData: _slice(
                operationData,
                cursor,
                callDataLength
            )});
            cursor += callDataLength;
        }
        if (cursor != operationData.length) {
            revert HCAOperationHashLib.InvalidOperationEncoding();
        }
    }

    function _operationHash(bytes memory operationData) internal pure returns (bytes32) {
        (bytes32 mode, Execution[] memory executions) = _decodeOperation(operationData);
        bytes32[] memory executionHashes = new bytes32[](executions.length);
        for (uint256 i; i < executions.length; ++i) {
            executionHashes[i] = keccak256(
                abi.encode(
                    OPS_TYPEHASH,
                    executions[i].target,
                    executions[i].value,
                    keccak256(executions[i].callData)
                )
            );
        }
        return
            keccak256(abi.encode(OP_TYPEHASH, mode, keccak256(abi.encodePacked(executionHashes))));
    }

    function _slice(bytes memory data, uint256 start, uint256 length)
        internal
        pure
        returns (bytes memory result)
    {
        result = new bytes(length);
        for (uint256 i; i < result.length; ++i) {
            result[i] = data[start + i];
        }
    }

    function _signRhinestoneMessage(uint256 privateKey, bytes32 digest)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 personalDigest =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, personalDigest);
        return abi.encodePacked(r, s, v + 4);
    }

    function _packProof(SessionEnableProofFixture memory proof)
        internal
        pure
        returns (bytes memory packed)
    {
        packed = abi.encodePacked(
            proof.sessionKey,
            proof.validUntil,
            proof.sessionNonce,
            proof.resolver,
            proof.refundToken,
            proof.maxRefundExchangeRate,
            proof.maxRefundGasOverhead,
            proof.maxRefundAmount,
            proof.sessionToEnableIndex,
            proof.renewPaymentToken,
            proof.renewalDuration,
            proof.maxRenewSpend,
            uint8(proof.hashesAndChainIds.length)
        );
        for (uint256 i; i < proof.hashesAndChainIds.length; ++i) {
            HCASmartSessionLib.HashAndChainId memory item = proof.hashesAndChainIds[i];
            packed = bytes.concat(packed, abi.encodePacked(item.chainId, item.sessionDigest));
        }
        return bytes.concat(packed, abi.encodePacked(proof.ownerR, proof.ownerS, proof.ownerV));
    }
}
