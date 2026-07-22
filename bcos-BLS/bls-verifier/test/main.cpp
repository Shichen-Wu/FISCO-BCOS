#include "BlsVerifier.h"
#include <iostream>
#include <cassert>

static bls::SecretKey newSk() { bls::SecretKey s; s.init(); return s; }
static bls::PublicKey getPk(const bls::SecretKey& sk) {
    bls::PublicKey p; sk.getPublicKey(p); return p;
}
static bls::Signature sign(const bls::SecretKey& sk, const std::string& m) {
    bls::Signature s; sk.sign(s, m.data(), m.size()); return s;
}
static bool bverify(const bls::Signature& s, const bls::PublicKey& p,
                    const std::string& m) {
    return s.verify(p, m.data(), m.size());
}

static std::string makeBitmap(const std::vector<uint32_t>& gids) {
    uint8_t bytes[32] = {0};
    for (uint32_t g : gids) {
        uint32_t i = g - 1;
        bytes[i / 8] |= (1u << (7 - (i % 8)));
    }
    char buf[67];
    buf[0] = '0'; buf[1] = 'x';
    for (int i = 0; i < 32; ++i)
        snprintf(buf + 2 + i * 2, 3, "%02x", bytes[i]);
    return std::string(buf);
}

static int g_pass = 0, g_fail = 0;
#define T(name) std::cout << "  [" << name << "] "; std::cout.flush()
#define OK(cond) do { \
    if (cond) { std::cout << "PASS\n"; ++g_pass; } \
    else { std::cout << "FAIL L" << __LINE__ << "\n"; ++g_fail; } \
} while(0)
#define EQ(a,b) OK((a) == (b))

int main() {
    BlsVerifier& v = BlsVerifier::instance();
    std::cout << "===== BlsVerifier 测试 =====\n\n";

    T("init");           EQ(v.init(), BlsVerifier::OK);
    T("re-init");        EQ(v.init(), BlsVerifier::ERR_ALREADY_INIT);

    const uint32_t N = 10;
    std::vector<bls::SecretKey> sks(N);
    std::vector<bls::PublicKey> pks(N);
    std::vector<std::string> pkHex(N);
    std::vector<uint32_t> all(N);
    for (uint32_t i = 0; i < N; ++i) {
        sks[i] = newSk(); pks[i] = getPk(sks[i]);
        pkHex[i] = pks[i].serializeToHexStr(); all[i] = i + 1;
    }

    T("register-10");
    bool ok = true;
    for (uint32_t i = 0; i < N; ++i)
        if (v.setGroupPublicKey(i + 1, pkHex[i]) != BlsVerifier::OK) ok = false;
    OK(ok);

    T("group-count");    EQ(v.groupCount(), (size_t)N);
    T("has-group-5");    OK(v.hasGroup(5));
    T("has-no-0");       OK(!v.hasGroup(0));
    T("bad-id-0");       EQ(v.setGroupPublicKey(0, pkHex[0]),
                             BlsVerifier::ERR_INVALID_GROUP_ID);
    T("bad-id-257");     EQ(v.setGroupPublicKey(257, pkHex[0]),
                             BlsVerifier::ERR_INVALID_GROUP_ID);
    T("bad-pubkey");     EQ(v.setGroupPublicKey(11, "xxx"),
                             BlsVerifier::ERR_INVALID_PUBKEY);

    std::string msg = "test_message_abc";
    std::string bm = makeBitmap(all);
    bls::Signature aggSig; aggSig.clear();
    bls::PublicKey aggPub; aggPub.clear();
    for (uint32_t i = 0; i < N; ++i) {
        aggSig.add(sign(sks[i], msg));
        aggPub.add(pks[i]);
    }
    std::string aggSigHex = aggSig.serializeToHexStr();
    T("pre-verify");     OK(bverify(aggSig, aggPub, msg));

    T("verify-pass");
    { bool r = false; int rc = v.verify(aggSigHex, bm, msg, r);
      OK(rc == BlsVerifier::OK && r); }
    T("verify-simple");  OK(v.verify(aggSigHex, bm, msg));

    T("verify-wrong-msg");
    { bool r = true; v.verify(aggSigHex, bm, "wrong", r); OK(!r); }

    {
        std::vector<uint32_t> odd = {1,3,5,7,9};
        std::string obm = makeBitmap(odd);
        bls::Signature os; os.clear(); bls::PublicKey op; op.clear();
        for (uint32_t g : odd) { os.add(sign(sks[g-1], msg)); op.add(pks[g-1]); }
        T("verify-odd");  OK(v.verify(os.serializeToHexStr(), obm, msg));
    }

    T("empty-bitmap");
    { bool r = false;
      int rc = v.verify(aggSigHex,
          "0x0000000000000000000000000000000000000000000000000000000000000000",
          msg, r);
      EQ(rc, BlsVerifier::ERR_EMPTY_BITMAP); }

    T("missing-pk");
    { bool r = false;
      int rc = v.verify(aggSigHex, makeBitmap({256}), msg, r);
      EQ(rc, BlsVerifier::ERR_PUBKEY_NOT_FOUND); }

    std::cout << "\n[压力] 注册至 128 组...\n";
    for (uint32_t i = 11; i <= 128; ++i) {
        bls::SecretKey sk = newSk();
        v.setGroupPublicKey(i, getPk(sk).serializeToHexStr());
    }
    T("pressure-count"); EQ(v.groupCount(), (size_t)128);

    T("verify-128-groups");
    OK(v.verify(aggSigHex, makeBitmap(all), msg));

    std::cout << "\n结果: " << g_pass << " 通过, " << g_fail << " 失败\n";
    return g_fail == 0 ? 0 : 1;
}
