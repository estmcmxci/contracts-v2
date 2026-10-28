// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

// solhint-disable private-vars-leading-underscore, func-name-mixedcase

import {AutoRenewSessionFixture} from "./AutoRenewSessionFixture.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {Execution} from "nexus/types/DataTypes.sol";

import {ERC1271_MAGICVALUE} from "nexus/types/Constants.sol";

import {HCAOwnerAndSessionValidator} from "../../../src/hca/HCAOwnerAndSessionValidator.sol";
import {HCASmartSessionLib} from "../../../src/hca/libraries/HCASmartSessionLib.sol";
import {IETHRenewer, RenewData} from "../../../src/registrar/interfaces/IETHRenewer.sol";
import {IPermissionedRegistry} from "../../../src/registry/interfaces/IPermissionedRegistry.sol";
import {IRegistry} from "../../../src/registry/interfaces/IRegistry.sol";
import {RegistryRolesLib} from "../../../src/registry/libraries/RegistryRolesLib.sol";
import {LibLabel} from "../../../src/utils/LibLabel.sol";
import {VerifiableFactory} from "@ensdomains/verifiable-factory/VerifiableFactory.sol";
import {MockStandaloneHCA} from "../../mocks/MockStandaloneHCAStack.sol";
import {HCAOwnerAndSessionValidatorEnableHarness} from "./HCAOwnerAndSessionValidator.t.sol";

// Skeleton for the contested claim. Nine cases, from ERD.md section 4 of
// /Users/oakgroup/auto-renew.
//
// Every case is empty and calls vm.skip, so the run reports SKIP, not PASS.
// An empty body that reports PASS is a false green. Remove the skip line in
// the beat that fills the case.
//
// Fill the harness from this clone of ensdomains/contracts-v2 at
// post-audit-2, commit 3e54cdb8. Do not fill it from reference/, which is a
// snapshot.
//
// Rule: do not start any other part of that project until these pass.
//
// Fork setup: anvil --fork-url $SEPOLIA_RPC_URL. The fork runs on port 8546;
// 8545 is held by an unrelated anvil. ENSv2 is live on Sepolia, so these run
// against the real ETHRegistrar path. Addresses come from
// ../config/networks.ts, chain id 11155111. Nothing here may hardcode one.
// Re-run on a mainnet fork before the proposal.

/// @title Auto-renew session policy tests
/// @notice Proves the renew rule binds a session key to names the owner holds.
contract AutoRenewPolicyTest is AutoRenewSessionFixture {
    // Addresses come from `config/networks.ts`, never from a literal here. A Forge test cannot
    // read TypeScript, so `config/export-env.ts` turns that file into environment lines and this
    // reads them. Run the suite with them loaded:
    //
    //   cd /Users/oakgroup/auto-renew
    //   set -a; . <(bun config/export-env.ts 11155111); . ./.env; set +a
    //   cd contracts-v2/contracts && forge test --match-path 'test/unit/hca/AutoRenewPolicy.t.sol'
    //
    // Nothing is written to the clone. A missing variable fails `setUp` loudly, which is correct:
    // a renew test that silently used the zero address would prove nothing.
    address ethRegistry;
    address ethRenewer;
    address ethRegistrar;
    address paymentToken;

    // The name every case renews. Registered fresh in `setUp`, so the LABEL is known. The live
    // Sepolia labels `test`, `alice`, `vitalik` and `nick` are reservations with a zero owner,
    // and the token id from a `TransferSingle` log gives no label at all. The rule needs the
    // label, because it computes `LibLabel.id(label)` from the call data.
    string internal constant LABEL = "auto-renew-policy-t1";

    // A name the HCA owner does NOT hold, for T2. Same length as LABEL, so it prices the same
    // and the only difference between the two batches is who owns the name.
    string internal constant FOREIGN_LABEL = "auto-renew-policy-t2";
    address internal foreignOwner;

    // A SHORT name the owner holds, for T4. The oracle charges far more for a short label, so
    // its one-year price exceeds a cap set from a long one. That is how the spend cap is
    // exceeded without touching anything else.
    string internal constant SHORT_LABEL = "t4ab";
    uint256 internal shortPrice;

    // The owner needs a KEY, not just an address: it signs the session authorization. The proof
    // machinery in `HCAOwnerAndSessionValidator.t.sol` is private to that contract, so the
    // packing and salt are duplicated here when the proof is built. Duplicating in this NEW file
    // beats lifting them out of the existing one, which would alter a file this change should
    // leave alone.
    address internal hcaOwner;
    uint256 internal hcaOwnerKey;
    address internal sessionSigner;
    address internal intentExecutor = makeAddr("intent-executor");
    address internal gasRefundPaymaster = makeAddr("gas-refund-paymaster");

    MockStandaloneHCA internal hca;
    HCAOwnerAndSessionValidatorEnableHarness internal validator;

    // One year, fixed, per `DECISIONS.md` D7. The contracts define no year, so this is a policy
    // number. `MIN_RENEW_DURATION` is 1 second, so nothing in the protocol bounds it.
    uint64 internal constant RENEWAL_DURATION = 31557600;

    // Read from the oracle in `setUp`, never hardcoded. D7 makes the cap per session, taken from
    // the price of the name that session renews.
    uint256 internal renewPrice;

    function setUp() public {
        // The name owner needs a FRESH address, not `vm.addr(OWNER_KEY)`. On a fork that
        // address is already a deployed contract, and minting the name to it fails the ERC-1155
        // receiver check. A test key that is free on a blank chain need not be free on a real
        // one. The session signer may keep `SESSION_KEY`, because `_envelope` signs with it and
        // a signer never receives a token.
        (hcaOwner, hcaOwnerKey) = makeAddrAndKey("hca-owner");
        foreignOwner = makeAddr("foreign-owner");
        sessionSigner = vm.addr(SESSION_KEY);
        vm.createSelectFork(vm.envString("SEPOLIA_RPC_URL"));
        ethRegistry = vm.envAddress("AR_ETHREGISTRY");
        ethRenewer = vm.envAddress("AR_ETHRENEWER_V1");
        ethRegistrar = vm.envAddress("AR_ETHREGISTRAR");
        paymentToken = vm.envAddress("AR_TOKEN_USDC");

        // Fail here rather than inside a case. These are the fork's own answers, not an ABI's.
        assertEq(block.chainid, vm.envUint("AR_CHAIN_ID"), "forked the wrong chain");
        assertGt(ethRegistry.code.length, 0, "ETHRegistry has no code");
        assertGt(ethRenewer.code.length, 0, "ETHRenewerV1 has no code");
        assertGt(ethRegistrar.code.length, 0, "ETHRegistrar has no code");
        assertGt(paymentToken.code.length, 0, "payment token has no code");

        _registerOwnedName();
        _deployHCAStack();
        _readRenewPrice();
    }

    /// @dev Quotes the renewal from the live oracle. The batch must pull and approve this exact
    ///      number, so the test cannot invent it. The target is `ETHRegistrar`, the v2 path.
    function _readRenewPrice() internal {
        renewPrice = IETHRenewer(ethRegistrar).getRenewPrice(LABEL, RENEWAL_DURATION, IERC20(paymentToken));
        emit log_named_uint("one year on LABEL, payment token smallest unit", renewPrice);
        assertGt(renewPrice, 0, "oracle quoted zero for a one-year renewal");

        shortPrice = IETHRenewer(ethRegistrar).getRenewPrice(SHORT_LABEL, RENEWAL_DURATION, IERC20(paymentToken));
        emit log_named_uint("one year on SHORT_LABEL", shortPrice);
        // The cap in the session is `renewPrice` plus a tenth. The short name must price above
        // it, or T4 would prove nothing.
        assertGt(shortPrice, renewPrice + (renewPrice / 10), "short name does not exceed the cap");
    }

    /// @dev Deploys the modified validator and a mock HCA onto the fork, beside the real
    ///      contracts, and points the validator at the REAL `ETHRegistry`. `ERD.md` 6.2 asks for
    ///      exactly this. The adapters and the resolver implementation are placeholders, because
    ///      a renewal touches none of them.
    function _deployHCAStack() internal {
        hca = new MockStandaloneHCA(hcaOwner);
        validator = new HCAOwnerAndSessionValidatorEnableHarness(
            makeAddr("reverse-adapter"),
            makeAddr("addr-reverse-adapter"),
            makeAddr("resolver-implementation"),
            ethRegistry,
            address(new VerifiableFactory()),
            intentExecutor,
            gasRefundPaymaster
        );

        // The validator must read the real registry, or nothing below proves anything.
        assertEq(validator.ETH_REGISTRY(), ethRegistry, "validator points at the wrong registry");
    }

    /// @dev Mints `LABEL` to `hcaOwner` on the fork, so the cases have a name with a known label
    ///      and a real owner. `ETHRegistrar` holds the root `ROLE_REGISTRAR`, verified on chain,
    ///      so pranking it reaches `register` without the commit, reveal and payment dance. The
    ///      point of these tests is the session policy, not the registrar's own flow.
    function _registerOwnedName() internal {
        vm.prank(ethRegistrar);
        IPermissionedRegistry(ethRegistry)
            .register(LABEL, hcaOwner, IRegistry(address(0)), address(0), 0, uint64(block.timestamp + 365 days));

        // Assert the fork, not an ABI. `latestOwner` comes from `getState`, which rebuilds the
        // versioned token id from the labelhash; `latestOwnerOf` would read zero here. VERIFY 4.
        assertEq(
            IPermissionedRegistry(ethRegistry).getState(LibLabel.id(LABEL)).latestOwner,
            hcaOwner,
            "fresh name is not owned by the test owner"
        );
        // The renew TARGET for a natively registered v2 name is `ETHRegistrar`, not
        // `ETHRenewerV1`. `ETHRenewerV1` serves premigrated v1 names, so it refuses a name that
        // was registered fresh on v2. `ERD.md` 3.3 and 6.1 both say this; the fixture proved it.
        // `ETHRegistrar` holds both `ROLE_REGISTRAR` and `ROLE_RENEW`, so the rule admits it.
        assertTrue(IETHRenewer(ethRegistrar).isRenewable(LABEL), "fresh name is not renewable on v2");
        assertFalse(IETHRenewer(ethRenewer).isRenewable(LABEL), "ETHRenewerV1 unexpectedly renews a v2 name");

        // A second name, held by someone else, for the T2 refusal.
        vm.prank(ethRegistrar);
        IPermissionedRegistry(ethRegistry)
            .register(
                FOREIGN_LABEL, foreignOwner, IRegistry(address(0)), address(0), 0, uint64(block.timestamp + 365 days)
            );
        assertEq(
            IPermissionedRegistry(ethRegistry).getState(LibLabel.id(FOREIGN_LABEL)).latestOwner,
            foreignOwner,
            "the foreign name is not owned by the foreign owner"
        );

        // A short name, held by the SAME owner, for the T4 spend refusal.
        vm.prank(ethRegistrar);
        IPermissionedRegistry(ethRegistry)
            .register(SHORT_LABEL, hcaOwner, IRegistry(address(0)), address(0), 0, uint64(block.timestamp + 365 days));
    }

    // TODO: inherit the project's HCA harness and import:
    //   HCAOwnerAndSessionValidator (the modified one)
    //   IPermissionedRegistry, IETHRenewer, IETHRegistrar
    //   MockStandaloneHCA from ../../mocks/MockStandaloneHCAStack.sol
    // test/unit/hca/HCAOwnerAndSessionValidator.t.sol is the pattern to copy.

    /// @dev Builds the owner-signed session authorization for a RENEWAL. Adapted from
    ///      `_multiChainEnableProof` in `HCAOwnerAndSessionValidator.t.sol`, which builds one for
    ///      the register path. The differences are the three renew fields and a zero resolver: a
    ///      renewal touches no resolver.
    ///      All three renew fields go into the SALT. If they do not, the permissionId the test
    ///      derives diverges from the validator's and the proof is refused with
    ///      `InvalidSessionData`. That cost a whole beat the first time. See R3's third pass.
    function _renewEnableProof() internal view returns (SessionEnableProofFixture memory proof, bytes32 permissionId) {
        proof.sessionKey = sessionSigner;
        proof.validUntil = uint48(block.timestamp + 1 days);
        proof.sessionNonce = 0;
        // Non-zero, copied from the register fixture. The validator refuses a zero refund
        // configuration on this route, so these cannot all be left at zero.
        proof.refundToken = paymentToken;
        proof.maxRefundExchangeRate = 5_000_000_000;
        proof.maxRefundGasOverhead = 100_000;
        proof.maxRefundAmount = 25_000_000;
        proof.sessionToEnableIndex = 1;
        proof.renewPaymentToken = paymentToken;
        proof.renewalDuration = RENEWAL_DURATION;
        // Per D7 the cap is per session, taken from the live quote plus headroom for oracle drift.
        proof.maxRenewSpend = uint96(renewPrice + (renewPrice / 10));

        address[] memory sessionOwners = new address[](1);
        sessionOwners[0] = sessionSigner;
        bytes memory validatorInitData = abi.encode(uint256(1), sessionOwners);
        // SEVEN fields, not ten. The three renew caps ride in spare high bits of words 1 and 6.
        // See `_sessionAuthorizationSalt` for the bit ranges and for why this keeps the
        // permissionId of a pre-existing session unchanged.
        bytes32 salt = keccak256(
            abi.encode(
                uint256(proof.sessionNonce) | (uint256(uint160(proof.renewPaymentToken)) << 96),
                proof.validUntil,
                proof.resolver,
                proof.refundToken,
                proof.maxRefundExchangeRate,
                uint256(proof.maxRefundGasOverhead) | (uint256(proof.renewalDuration) << 48)
                    | (uint256(proof.maxRenewSpend) << 112),
                proof.maxRefundAmount
            )
        );
        permissionId = keccak256(abi.encode(OWNABLE_SESSION_VALIDATOR, validatorInitData, salt));
        bytes32 destinationSessionDigest = keccak256(
            abi.encode(
                SIGNED_SESSION_TYPEHASH,
                address(hca),
                type(uint256).max,
                uint256(0),
                DEFAULT_SIGNED_PERMISSIONS_HASH,
                salt,
                OWNABLE_SESSION_VALIDATOR,
                keccak256(validatorInitData),
                SMART_SESSION_EMISSARY
            )
        );
        proof.hashesAndChainIds = new HCASmartSessionLib.HashAndChainId[](2);
        proof.hashesAndChainIds[0] = HCASmartSessionLib.HashAndChainId({
            chainId: uint64(SOURCE_CHAIN_ID), sessionDigest: keccak256("source session")
        });
        proof.hashesAndChainIds[1] = HCASmartSessionLib.HashAndChainId({
            chainId: uint64(block.chainid), sessionDigest: destinationSessionDigest
        });

        bytes32[] memory chainSessionHashes = new bytes32[](2);
        for (uint256 i; i < 2; ++i) {
            HCASmartSessionLib.HashAndChainId memory item = proof.hashesAndChainIds[i];
            chainSessionHashes[i] = keccak256(abi.encode(CHAIN_SESSION_TYPEHASH, item.chainId, item.sessionDigest));
        }
        bytes32 structHash =
            keccak256(abi.encode(MULTI_CHAIN_SESSION_TYPEHASH, keccak256(abi.encodePacked(chainSessionHashes))));
        bytes32 domainSeparator =
            keccak256(abi.encode(SMART_SESSION_DOMAIN_TYPEHASH, SMART_SESSION_NAME_HASH, SMART_SESSION_VERSION_HASH));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (proof.ownerV, proof.ownerR, proof.ownerS) = vm.sign(hcaOwnerKey, digest);
    }

    /// @dev The same-chain envelope, mode 5. A copy of `_initialRefundEnvelope` from
    ///      `HCAOwnerAndSessionValidator.t.sol`; it was not in the extracted fixture.
    function _renewEnvelope(
        bytes32 permissionId,
        SessionEnableProofFixture memory proof,
        uint256 nonce,
        HCAOwnerAndSessionValidator.GasRefund memory gasRefund,
        bytes memory operationData,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(uint8(5)),
            permissionId,
            _packProof(proof),
            nonce,
            gasRefund.token,
            uint96(gasRefund.exchangeRate),
            uint96(gasRefund.overhead >> 128),
            uint48(uint128(gasRefund.overhead)),
            operationData,
            _signRhinestoneMessage(SESSION_KEY, digest)
        );
    }

    /// @dev The three executions D6 requires, in order: pull from the owner, approve the
    ///      registrar, renew. Both amounts are the EXACT quote, which `_checkRenewBatch` enforces.
    function _renewExecutions() internal view returns (Execution[] memory) {
        return _renewExecutionsFor(LABEL, RENEWAL_DURATION);
    }

    /// @dev The same batch for any label and duration, so a case can vary ONE thing. The amounts
    ///      always match the quote for the label being renewed, which keeps a failure
    ///      attributable to the thing the case varied and not to the money legs.
    function _renewExecutionsFor(string memory label, uint64 duration)
        internal
        view
        returns (Execution[] memory executions)
    {
        uint256 price = IETHRenewer(ethRegistrar).getRenewPrice(label, duration, IERC20(paymentToken));
        executions = new Execution[](3);
        executions[0] = Execution({
            target: paymentToken,
            value: 0,
            callData: abi.encodeWithSelector(IERC20.transferFrom.selector, hcaOwner, address(hca), price)
        });
        executions[1] = Execution({
            target: paymentToken,
            value: 0,
            callData: abi.encodeWithSelector(IERC20.approve.selector, ethRegistrar, price)
        });
        executions[2] = Execution({
            target: ethRegistrar,
            value: 0,
            callData: abi.encodeWithSelector(
                IETHRenewer.renew.selector,
                RenewData({label: label, duration: duration, referrer: bytes32(0)}),
                IERC20(paymentToken)
            )
        });
    }

    /// @dev Prepares one batch for validation and returns the digest and the envelope.
    ///      Split from the call on purpose. `vm.expectRevert` binds to the next EXTERNAL call,
    ///      and building a batch makes external calls of its own, to the price oracle and
    ///      through the digest harness. If the preparation ran under `expectRevert`, the
    ///      cheatcode would attach to `getRenewPrice` instead of `validate` and a refusal case
    ///      would report "did not revert" while the rule was working. Prepare first, then
    ///      `expectRevert`, then call `hca.validate` and nothing else.
    function _prepareBatch(Execution[] memory executions, uint256 nonce)
        internal
        view
        returns (bytes32 digest, bytes memory envelope)
    {
        (SessionEnableProofFixture memory proof, bytes32 permissionId) = _renewEnableProof();
        HCAOwnerAndSessionValidator.GasRefund memory gasRefund = HCAOwnerAndSessionValidator.GasRefund({
            token: proof.refundToken,
            exchangeRate: proof.maxRefundExchangeRate,
            overhead: (uint256(proof.maxRefundAmount) << 128) | proof.maxRefundGasOverhead
        });
        bytes memory operationData = _encodeExecutions(executions);
        digest = validator.singleChainDigestWithRefundHarness(address(hca), nonce, operationData, gasRefund);
        envelope = _renewEnvelope(permissionId, proof, nonce, gasRefund, operationData, digest);
    }

    // ---------------------------------------------------------------
    // 1. Session key renews a name the owner holds -> PASS
    // ---------------------------------------------------------------
    // The base case. Everything else is a refusal.
    function test_renew_ownedName_succeeds() public {
        (SessionEnableProofFixture memory proof, bytes32 permissionId) = _renewEnableProof();
        HCAOwnerAndSessionValidator.GasRefund memory gasRefund = HCAOwnerAndSessionValidator.GasRefund({
            token: proof.refundToken,
            exchangeRate: proof.maxRefundExchangeRate,
            overhead: (uint256(proof.maxRefundAmount) << 128) | proof.maxRefundGasOverhead
        });
        bytes memory operationData = _encodeExecutions(_renewExecutions());
        uint256 nonce = 1;
        bytes32 digest = validator.singleChainDigestWithRefundHarness(address(hca), nonce, operationData, gasRefund);

        assertEq(
            hca.validate(
                validator, digest, _renewEnvelope(permissionId, proof, nonce, gasRefund, operationData, digest)
            ),
            ERC1271_MAGICVALUE,
            "the policy refused a renewal of a name the owner holds"
        );
    }

    // ---------------------------------------------------------------
    // 2. Session key renews a name the owner does NOT hold -> REVERT
    // ---------------------------------------------------------------
    // This is the request. Expect PolicyRuleFailed.
    function test_renew_foreignName_reverts() public {
        // Everything matches T1 except the label. The name is registered, renewable and priced
        // the same; only its owner differs. So a refusal here is the owner binding and nothing
        // else. `latestOwner` is the foreign owner, so the binding fails first.
        (bytes32 digest, bytes memory envelope) = _prepareBatch(_renewExecutionsFor(FOREIGN_LABEL, RENEWAL_DURATION), 2);

        vm.expectRevert(HCAOwnerAndSessionValidator.PolicyRuleFailed.selector);
        hca.validate(validator, digest, envelope);
    }

    // ---------------------------------------------------------------
    // 3. Duration above the cap -> REVERT
    // ---------------------------------------------------------------
    function test_renew_durationAboveCap_reverts() public {
        // The duration is a FIXED value, not a maximum (D4, D7). So BOTH directions must be
        // refused, and the item's "above the bound" wording covers only half of it.
        (bytes32 digest, bytes memory envelope) = _prepareBatch(_renewExecutionsFor(LABEL, RENEWAL_DURATION + 1), 3);
        vm.expectRevert(HCAOwnerAndSessionValidator.PolicyRuleFailed.selector);
        hca.validate(validator, digest, envelope);

        // Below the value, and this direction is the real attack. `MIN_RENEW_DURATION` is 1
        // second on both the registrar and the renewer, verified on chain, and a one-second
        // renewal costs 6 units of MockUSDC. So without the exact match a stolen key could renew
        // for dust, repeatedly, inside any spend cap. The exact match is what refuses it.
        (digest, envelope) = _prepareBatch(_renewExecutionsFor(LABEL, 1), 4);
        vm.expectRevert(HCAOwnerAndSessionValidator.PolicyRuleFailed.selector);
        hca.validate(validator, digest, envelope);
    }

    // ---------------------------------------------------------------
    // 4. Spend above the period cap -> REVERT
    // ---------------------------------------------------------------
    // Fill the blast-radius number in THREAT-MODEL.md section 3 from this.
    function test_renew_spendAboveCap_reverts() public {
        // The owner holds this name and the duration is exact, so the owner binding and the
        // duration check both pass. The only violation is the price against `maxRenewSpend`.
        (bytes32 digest, bytes memory envelope) = _prepareBatch(_renewExecutionsFor(SHORT_LABEL, RENEWAL_DURATION), 5);

        vm.expectRevert(HCAOwnerAndSessionValidator.PolicyRuleFailed.selector);
        hca.validate(validator, digest, envelope);

        // The numbers for THREAT-MODEL.md section 3.
        emit log_named_uint("T4 cap, payment token smallest unit", renewPrice + (renewPrice / 10));
        emit log_named_uint("T4 refused price", shortPrice);
    }

    // ---------------------------------------------------------------
    // 5. Name expired, inside grace, owner unchanged -> PASS
    // ---------------------------------------------------------------
    // Proves latestOwnerOf is the right accessor. ownerOf fails here, and
    // this is the window that matters most to the user.
    // vm.warp past expiry, stay inside GRACE_PERIOD.
    // Closes VERIFY.md item 4, first half.
    function test_renew_insideGracePeriod_succeeds() public {
        // Move past expiry but stay inside the grace window. This is the window the product
        // exists for: the name has lapsed and the owner has not lost it yet.
        uint64 expiry = IPermissionedRegistry(ethRegistry).getState(LibLabel.id(LABEL)).expiry;
        uint64 grace = IETHRenewer(ethRegistrar).GRACE_PERIOD();
        vm.warp(uint256(expiry) + 1 days);
        assertLt(grace, type(uint64).max, "no grace period to test inside");
        assertGt(
            IETHRenewer(ethRegistrar).getRemainingGracePeriod(LABEL), 0, "the warp landed outside the grace window"
        );

        // The accessor claim, measured. `latestOwner` still answers after expiry, which is why
        // the rule reads `getState` and not `ownerOf`. `VERIFY.md` item 4.
        assertEq(
            IPermissionedRegistry(ethRegistry).getState(LibLabel.id(LABEL)).latestOwner,
            hcaOwner,
            "latestOwner changed inside the grace period"
        );
        assertEq(
            IPermissionedRegistry(ethRegistry).ownerOf(LibLabel.id(LABEL)),
            address(0),
            "ownerOf still answers inside grace, so the accessor choice is moot"
        );

        // Build AFTER the warp, so the session validity and the quote are current.
        (bytes32 digest, bytes memory envelope) = _prepareBatch(_renewExecutionsFor(LABEL, RENEWAL_DURATION), 6);

        assertEq(
            hca.validate(validator, digest, envelope),
            ERC1271_MAGICVALUE,
            "the policy refused a renewal inside the grace period"
        );
    }

    // ---------------------------------------------------------------
    // 6. Third party registers the name, old key retries -> REVERT
    // ---------------------------------------------------------------
    // The strongest test. Proves the rule grants no permanent right to a
    // name after the owner loses it, because latestOwner moves to the new
    // registrant. Closes VERIFY.md item 4, second half.
    function test_renew_afterReregistration_reverts() public {
        // Let the name lapse completely, past the grace window, so it becomes available.
        uint64 expiry = IPermissionedRegistry(ethRegistry).getState(LibLabel.id(LABEL)).expiry;
        vm.warp(uint256(expiry) + uint256(IETHRenewer(ethRegistrar).GRACE_PERIOD()) + 1);
        assertEq(
            IETHRenewer(ethRegistrar).getRemainingGracePeriod(LABEL),
            0,
            "still inside the grace window, so the name has not lapsed"
        );

        // A third party takes it.
        address thirdParty = makeAddr("third-party");
        vm.prank(ethRegistrar);
        IPermissionedRegistry(ethRegistry)
            .register(LABEL, thirdParty, IRegistry(address(0)), address(0), 0, uint64(block.timestamp + 365 days));
        assertEq(
            IPermissionedRegistry(ethRegistry).getState(LibLabel.id(LABEL)).latestOwner,
            thirdParty,
            "the third party does not hold the name"
        );

        // The old session is unchanged and still inside its own validity. It now fails, because
        // `latestOwner` moved. The binding grants no permanent right to a name after the owner
        // loses it. This is the claim the proposal rests on.
        (bytes32 digest, bytes memory envelope) = _prepareBatch(_renewExecutionsFor(LABEL, RENEWAL_DURATION), 7);

        vm.expectRevert(HCAOwnerAndSessionValidator.PolicyRuleFailed.selector);
        hca.validate(validator, digest, envelope);
    }

    // ---------------------------------------------------------------
    // 7. Renewal through an unauthorized registrar -> REVERT
    // ---------------------------------------------------------------
    // _isAuthorizedRegistrar, same check the register case uses.
    function test_renew_unauthorizedRegistrar_reverts() public {
        // A target that holds NO role at the registry root. The rule refuses it by authority,
        // before it looks at the name, so the error is `ActionNotAllowed` and not
        // `PolicyRuleFailed`. That distinction is the point: this is a refusal about WHO was
        // called, not about what was asked.
        address rogue = makeAddr("rogue-renewer");
        assertFalse(
            IPermissionedRegistry(ethRegistry).hasRootRoles(RegistryRolesLib.ROLE_RENEW, rogue),
            "the rogue target unexpectedly holds ROLE_RENEW"
        );

        Execution[] memory executions = _renewExecutionsFor(LABEL, RENEWAL_DURATION);
        executions[2].target = rogue;
        executions[1].callData = abi.encodeWithSelector(IERC20.approve.selector, rogue, renewPrice);
        (bytes32 digest, bytes memory envelope) = _prepareBatch(executions, 8);

        vm.expectRevert(
            abi.encodeWithSelector(
                HCAOwnerAndSessionValidator.ActionNotAllowed.selector, rogue, IETHRenewer.renew.selector
            )
        );
        hca.validate(validator, digest, envelope);
    }

    // ---------------------------------------------------------------
    // 8. revokeSessions() then any renewal -> REVERT
    // ---------------------------------------------------------------
    // The owner's one-transaction exit. Quote the result in the threat model.
    function test_renew_afterRevokeSessions_reverts() public {
        // Prepare the batch FIRST, so the proof carries the nonce that was current when the
        // owner authorized the session. Then revoke.
        (bytes32 digest, bytes memory envelope) = _prepareBatch(_renewExecutionsFor(LABEL, RENEWAL_DURATION), 9);

        // `StandaloneSingleOwnerHCA.revokeSessions()` increments `_sessionNonce` and is
        // `onlyOwner`. The mock exposes the nonce directly, so setting it to 1 is the same state
        // the real call produces after one revocation.
        hca.setSessionNonce(1);

        // The validator compares `proof.sessionNonce` against the account's current nonce and
        // refuses on mismatch. So one owner transaction kills every outstanding session, and the
        // session key cannot renew again. This is the owner's exit.
        vm.expectRevert(HCAOwnerAndSessionValidator.InvalidSessionData.selector);
        hca.validate(validator, digest, envelope);
    }

    // ---------------------------------------------------------------
    // 9. A v1 name renewed through the wrong registrar -> REVERT
    // ---------------------------------------------------------------
    // A name can hold a v2 reservation and still live on v1. v1 names renew
    // through ETHRenewerV1; ETHRegistrar renewal opens at rollout Stage 4.
    // The validator cannot choose; it can only refuse an unauthorized one.
    // See ERD.md section 3.3.
    function test_renew_v1NameWrongRegistrar_reverts() public {
        // The item's wording is "a v1 name through the wrong registrar". What the live fork
        // supports is the mirror of it: a NATIVE v2 name sent to `ETHRenewerV1`, which serves
        // premigrated v1 names and refuses this one. `setUp` asserts both renewability answers.
        //
        // The authority check PASSES here, because `ETHRenewerV1` does hold `ROLE_RENEW`. So the
        // refusal comes from renewability instead. D7 originally put our own check before the
        // price call so the refusal carried a policy error. C12 reversed that to save 210 bytes:
        // `getRenewPrice` calls `_requireRenewable`, which runs the same `_isRenewable`
        // predicate, so the name is still refused and the error is now the registrar's
        // `NameNotRenewable`. What this case tests is unchanged: a target that will not renew
        // the name cannot renew it.
        Execution[] memory executions = _renewExecutionsFor(LABEL, RENEWAL_DURATION);
        executions[2].target = ethRenewer;
        executions[1].callData = abi.encodeWithSelector(IERC20.approve.selector, ethRenewer, renewPrice);
        (bytes32 digest, bytes memory envelope) = _prepareBatch(executions, 10);

        vm.expectRevert(abi.encodeWithSelector(IETHRenewer.NameNotRenewable.selector, LABEL));
        hca.validate(validator, digest, envelope);
    }

    // ---------------------------------------------------------------
    // Golden vector for the TypeScript port
    // ---------------------------------------------------------------
    // progress/contracts.md C4. `operator/session.ts` rebuilds this
    // construction off chain, because a Nexus-style account needs an
    // ERC-4337 UserOperation and the payload has to exist before a bundler
    // can carry it. Two implementations of one byte layout drift unless
    // something compares them, so this case prints the T1 inputs AND the
    // T1 outputs as one JSON line and `operator/session.vector.test.ts`
    // asserts byte equality against it.
    //
    // It asserts nothing itself beyond what T1 already asserts; it exists to
    // be read by `scripts/dump-vector.sh`. Keep the key names in step with
    // `RenewSessionInputs`.
    function test_emit_typescriptVector() public {
        uint256 nonce = 1;
        (bytes32 digest, bytes memory envelope) = _prepareBatch(_renewExecutions(), nonce);

        // Same batch T1 validates, so a vector that matches is a vector of a
        // payload the policy accepts and not merely of one that encodes.
        assertEq(
            hca.validate(validator, digest, envelope),
            ERC1271_MAGICVALUE,
            "the vector does not describe an accepted payload"
        );

        // Three helpers, not one concat. Solc without viaIR runs out of stack
        // on a concat this wide, the same wall R3 hit; each helper holds its
        // own locals. See the LESSON under R3.
        emit log_string(string.concat(
                "{", _vectorStack(), ",", _vectorSession(nonce), ",", _vectorExpected(nonce), "}"
            ));
    }

    /// @dev The addresses and keys half of the C4 vector.
    function _vectorStack() internal view returns (string memory) {
        return string.concat(
            '"chainId":',
            vm.toString(block.chainid),
            ',"account":"',
            vm.toString(address(hca)),
            '","validator":"',
            vm.toString(address(validator)),
            '","intentExecutor":"',
            vm.toString(intentExecutor),
            '","registrar":"',
            vm.toString(ethRegistrar),
            '","paymentToken":"',
            vm.toString(paymentToken),
            '","nameOwner":"',
            vm.toString(hcaOwner),
            '","sessionKey":"',
            vm.toString(sessionSigner),
            '","ownerPrivateKey":"',
            vm.toString(bytes32(hcaOwnerKey)),
            '","sessionPrivateKey":"',
            vm.toString(bytes32(SESSION_KEY)),
            '"'
        );
    }

    /// @dev The session-parameter half. Every field here feeds the salt or the
    ///      packed header, so a difference shows up as a refused proof.
    function _vectorSession(uint256 nonce) internal view returns (string memory) {
        (SessionEnableProofFixture memory proof,) = _renewEnableProof();
        return string.concat(
            '"label":"',
            LABEL,
            '","duration":',
            vm.toString(uint256(RENEWAL_DURATION)),
            ',"renewPrice":',
            vm.toString(renewPrice),
            ',"maxRenewSpend":',
            vm.toString(uint256(proof.maxRenewSpend)),
            ',"validUntil":',
            vm.toString(uint256(proof.validUntil)),
            ',"sessionNonce":',
            vm.toString(uint256(proof.sessionNonce)),
            ',"nonce":',
            vm.toString(nonce),
            ',"sessionToEnableIndex":',
            vm.toString(uint256(proof.sessionToEnableIndex)),
            ",",
            _vectorRefund()
        );
    }

    /// @dev The refund configuration and the source-chain entry.
    function _vectorRefund() internal view returns (string memory) {
        (SessionEnableProofFixture memory proof,) = _renewEnableProof();
        return string.concat(
            '"refundToken":"',
            vm.toString(proof.refundToken),
            '","maxRefundExchangeRate":',
            vm.toString(uint256(proof.maxRefundExchangeRate)),
            ',"maxRefundGasOverhead":',
            vm.toString(uint256(proof.maxRefundGasOverhead)),
            ',"maxRefundAmount":',
            vm.toString(uint256(proof.maxRefundAmount)),
            ',"sourceChainId":',
            vm.toString(uint256(proof.hashesAndChainIds[0].chainId)),
            ',"sourceSessionDigest":"',
            vm.toString(proof.hashesAndChainIds[0].sessionDigest),
            '"'
        );
    }

    /// @dev What the TypeScript port must reproduce byte for byte.
    function _vectorExpected(uint256 nonce) internal view returns (string memory) {
        (, bytes32 permissionId) = _renewEnableProof();
        (bytes32 digest, bytes memory envelope) = _prepareBatch(_renewExecutions(), nonce);
        return string.concat(
            '"expectedPermissionId":"',
            vm.toString(permissionId),
            '","expectedDigest":"',
            vm.toString(digest),
            '","expectedOperationData":"',
            vm.toString(_encodeExecutions(_renewExecutions())),
            '","expectedEnvelope":"',
            vm.toString(envelope),
            '"'
        );
    }
}
