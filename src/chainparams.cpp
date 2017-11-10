// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"
#include "checkpoints.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"
//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x44;
        pchMessageStart[1] = 0x66;
        pchMessageStart[2] = 0xa4;
        pchMessageStart[3] = 0xde;
        vAlertPubKey = ParseHex("04f16a9a2894ad5ebbd551be1a4bd2d10cdb679228c9b9fd13c016ed91528241bcf3bd55023679be17f0bd3a16e6fbeba2f222989769417eb053cd91e26e26900e");
        nDefaultPort = 16432;
        nRPCPort = 16433;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
		
        const char* pszTimestamp = "http://www.bbc.co.uk/news/technology-41858583"; // Security flaw forces Estonia ID 'lockdown'
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 4866349 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1509740520, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1509740520;
        genesis.nBits    = 0x1f00ffff; 
        genesis.nNonce   = 516348;

        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x9aa7f95cd777ba8f90fd17ccb85e1ab6f0fb5268b20f2dfe5987a6af4887d108"));
        assert(genesis.hashMerkleRoot == uint256("0x97eb4be147288836f72b9299517aff0074de1ed9cfd6735fb98291335bf75626"));

        
        base58Prefixes[PUBKEY_ADDRESS] = list_of(18);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(24);
        base58Prefixes[SECRET_KEY] =     list_of(96);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x44)(0x77)(0xB3)(0xAF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x44)(0x77)(0x7A)(0x03);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        nPOSStartBlock = 100;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x55;
        pchMessageStart[1] = 0x55;
        pchMessageStart[2] = 0x6d;
        pchMessageStart[3] = 0x7;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("04e6fbeba2f222989769417eb053cd9f16a9a2894ad5ebbdb9fd13c016ed91528241bcf3bd55023679be17f0bd3a16551be1a4bd2d10cdb679228c91e26e26900e");
        nDefaultPort = 26432;
        nRPCPort = 26433;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = 520649337; 
        genesis.nNonce = 72431;

        //assert(hashGenesisBlock == uint256("0x"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(12);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(26);
        base58Prefixes[SECRET_KEY]     = list_of(103);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0xb2)(0x88)(0x6E)(0x8C);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0xb2)(0x88)(0xD9)(0xAD);


        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        nPOSStartBlock = 100;

    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    
    bool fTestNet = GetBoolArg("-testnet", false);
    
    if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
