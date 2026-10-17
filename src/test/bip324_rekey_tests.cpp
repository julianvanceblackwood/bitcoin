// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bip324.h>
#include <chainparams.h>
#include <key.h>
#include <span.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bip324_rekey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bidirectional_rekey_boundaries)
{
    SelectParams(ChainType::MAIN);

    std::array<unsigned char, 32> initiator_private{};
    std::array<unsigned char, 32> responder_private{};
    initiator_private.back() = 1;
    responder_private.back() = 2;

    CKey initiator_key;
    CKey responder_key;
    initiator_key.Set(initiator_private.begin(), initiator_private.end(), /*fCompressedIn=*/true);
    responder_key.Set(responder_private.begin(), responder_private.end(), /*fCompressedIn=*/true);
    BOOST_REQUIRE(initiator_key.IsValid());
    BOOST_REQUIRE(responder_key.IsValid());

    std::array<std::byte, 32> initiator_entropy{};
    std::array<std::byte, 32> responder_entropy{};
    initiator_entropy[0] = std::byte{0x42};
    responder_entropy[0] = std::byte{0x24};

    BIP324Cipher initiator{initiator_key, initiator_entropy};
    BIP324Cipher responder{responder_key, responder_entropy};
    initiator.Initialize(responder.GetOurPubKey(), /*initiator=*/true);
    responder.Initialize(initiator.GetOurPubKey(), /*initiator=*/false);

    BOOST_REQUIRE(initiator);
    BOOST_REQUIRE(responder);
    BOOST_CHECK(std::ranges::equal(initiator.GetSessionID(), responder.GetSessionID()));
    BOOST_CHECK(std::ranges::equal(
        initiator.GetSendGarbageTerminator(), responder.GetReceiveGarbageTerminator()));
    BOOST_CHECK(std::ranges::equal(
        responder.GetSendGarbageTerminator(), initiator.GetReceiveGarbageTerminator()));

    // Exercise both independent cipher directions across two rekey boundaries.
    constexpr unsigned PACKET_COUNT{2 * BIP324Cipher::REKEY_INTERVAL + 3};
    for (unsigned packet{0}; packet < PACKET_COUNT; ++packet) {
        for (bool from_initiator : {true, false}) {
            BIP324Cipher& sender{from_initiator ? initiator : responder};
            BIP324Cipher& receiver{from_initiator ? responder : initiator};
            const bool ignore{(packet % 3) == 0};
            const std::vector<std::byte> contents(
                packet % 17, std::byte{static_cast<unsigned char>(packet % 256)});
            const std::array<std::byte, 3> aad{
                std::byte{static_cast<unsigned char>(packet % 256)},
                std::byte{static_cast<unsigned char>(packet / 256)},
                from_initiator ? std::byte{1} : std::byte{0},
            };

            std::vector<std::byte> ciphertext(contents.size() + BIP324Cipher::EXPANSION);
            sender.Encrypt(contents, aad, ignore, ciphertext);

            const auto received_len{
                receiver.DecryptLength(std::span{ciphertext}.first(BIP324Cipher::LENGTH_LEN))};
            BOOST_REQUIRE_EQUAL(received_len, contents.size());

            std::vector<std::byte> recovered(received_len);
            bool received_ignore{!ignore};
            BOOST_REQUIRE(receiver.Decrypt(
                std::span{ciphertext}.subspan(BIP324Cipher::LENGTH_LEN),
                aad, received_ignore, recovered));
            BOOST_CHECK(std::ranges::equal(recovered, contents));
            BOOST_CHECK_EQUAL(received_ignore, ignore);
        }
    }

    // Authentication must still reject altered AAD after the cipher has rekeyed twice.
    for (bool from_initiator : {true, false}) {
        BIP324Cipher& sender{from_initiator ? initiator : responder};
        BIP324Cipher& receiver{from_initiator ? responder : initiator};
        const std::array<std::byte, 2> contents{std::byte{0x12}, std::byte{0x34}};
        const std::array<std::byte, 2> aad{std::byte{0x56}, std::byte{0x78}};
        std::vector<std::byte> ciphertext(contents.size() + BIP324Cipher::EXPANSION);
        sender.Encrypt(contents, aad, /*ignore=*/false, ciphertext);

        const auto received_len{
            receiver.DecryptLength(std::span{ciphertext}.first(BIP324Cipher::LENGTH_LEN))};
        BOOST_REQUIRE_EQUAL(received_len, contents.size());
        std::vector<std::byte> recovered(received_len);
        const std::array<std::byte, 2> altered_aad{std::byte{0x57}, std::byte{0x78}};
        bool ignore{false};
        BOOST_CHECK(!receiver.Decrypt(
            std::span{ciphertext}.subspan(BIP324Cipher::LENGTH_LEN),
            altered_aad, ignore, recovered));
    }

    // Changing the authentication tag must fail in either direction after rekeying.
    for (bool from_initiator : {true, false}) {
        BIP324Cipher& sender{from_initiator ? initiator : responder};
        BIP324Cipher& receiver{from_initiator ? responder : initiator};
        const std::array<std::byte, 2> contents{std::byte{0xaa}, std::byte{0xbb}};
        const std::array<std::byte, 1> aad{std::byte{0x42}};
        std::vector<std::byte> ciphertext(contents.size() + BIP324Cipher::EXPANSION);
        sender.Encrypt(contents, aad, /*ignore=*/false, ciphertext);

        const auto received_len{
            receiver.DecryptLength(std::span{ciphertext}.first(BIP324Cipher::LENGTH_LEN))};
        BOOST_REQUIRE_EQUAL(received_len, contents.size());
        ciphertext.back() ^= std::byte{0x01};

        std::vector<std::byte> recovered(received_len);
        bool ignore{false};
        BOOST_CHECK(!receiver.Decrypt(
            std::span{ciphertext}.subspan(BIP324Cipher::LENGTH_LEN),
            aad, ignore, recovered));
    }
}

BOOST_AUTO_TEST_SUITE_END()
