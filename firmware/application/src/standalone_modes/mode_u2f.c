/*
 * mode_u2f.c — FIDO2 (CTAP2) + U2F (CTAP1) authenticator over NFC, standalone.
 *
 * Emulates an ISO-14443-4 token on the FIDO applet AID. SELECT answers
 * "FIDO_2_0" so phones drive it over CTAP2 (NFCCTAP_MSG, INS 0x10): GetInfo,
 * MakeCredential, GetAssertion in CBOR. U2F APDUs (INS 0x01/0x02) stay handled
 * as a CTAP1 fallback for PC/second-CU readers. The tested T=CL engine
 * (nfc_14a_4) does all ISO-DEP framing; responses are processed in on_tick so
 * S(WTX) keeps the reader waiting while ECDSA runs, and 61xx chaining returns
 * oversized results.
 *
 * NOTE: CTAP2 here is non-UV (up-only, non-resident) — no clientPIN. Works for
 * UV-discouraged / second-factor WebAuthn; passkeys (UV-required) need PIN.
 *
 * Stateless key wrapping — no per-credential flash:
 *   priv = HMAC-SHA256(mk, 0x01 | appId32 | nonce32)   (P-256 scalar)
 *   kh   = nonce32 | HMAC-SHA256(mk, 0x02 | appId32 | nonce32)32
 * Only a 32-byte master key and a 4-byte global counter live in FDS. A key
 * handle is bound to its appId by the MAC, so it cannot be used on another
 * origin. Keys live in internal flash, not a secure element — research use.
 *
 * Crypto: self-contained SHA-256/HMAC below; micro-ecc (uECC) for P-256.
 */

#include <stdint.h>
#include <string.h>
#include "app_standalone.h"
#include "standalone_led.h"
#include "nfc_14a.h"
#include "rfid/nfctag/hf/nfc_14a_4.h"
#include "utils/fds_util.h"
#include "nrf_drv_rng.h"
#include "uECC.h"

#define NRF_LOG_MODULE_NAME u2f
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();

/* ---- persistence ---- */
#define U2F_FDS_FILE          0x1020
#define U2F_FDS_KEY_MK        0x0001   /* 32-byte master key            */
#define U2F_FDS_KEY_CTR       0x0002   /* 4-byte global counter         */
#define U2F_FDS_KEY_ATT_PRIV  0x0003   /* 32-byte attestation priv key  */
#define U2F_FDS_KEY_ATT_CERT  0x0004   /* attestation cert (DER)        */
#define U2F_ATT_CERT_MAX      512      /* max provisioned cert size     */

/* ---- status words ---- */
#define SW_NO_ERROR               0x9000
#define SW_CONDITIONS_NOT_SAT     0x6985   /* also: test-of-presence / check-only "mine" */
#define SW_WRONG_DATA             0x6A80
#define SW_WRONG_LENGTH           0x6700
#define SW_CLA_NOT_SUPPORTED      0x6E00
#define SW_INS_NOT_SUPPORTED      0x6D00
#define SW_FILE_NOT_FOUND         0x6A82

/* ---- U2F / ISO7816 instructions ---- */
#define U2F_INS_REGISTER     0x01
#define U2F_INS_AUTHENTICATE 0x02
#define U2F_INS_VERSION      0x03
#define ISO_INS_SELECT       0xA4
#define ISO_INS_GET_RESPONSE 0xC0

#define U2F_AUTH_CHECK_ONLY  0x07
#define U2F_AUTH_ENFORCE     0x03
#define U2F_AUTH_NO_ENFORCE  0x08

static const uint8_t U2F_AID[]   = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};
static const uint8_t U2F_V2[]    = {'U','2','F','_','V','2'};
#define KH_LEN 64   /* nonce(32) | mac(32) */

/* ---- CTAP2 / FIDO2 (NFCCTAP) ---- */
#define NFCCTAP_MSG          0x10   /* CLA 0x80: carries a CTAP2 command         */
#define NFCCTAP_GETRESPONSE  0x11   /* CLA 0x80: fetch more of a chained response */
#define CTAP_CMD_MAKE_CRED   0x01
#define CTAP_CMD_GET_ASSERT  0x02
#define CTAP_CMD_GET_INFO    0x04
#define CTAP_CMD_CLIENT_PIN  0x06
#define CTAP_CMD_RESET       0x07
/* CTAP status bytes (first byte of a CTAP response) */
#define CTAP2_OK                     0x00
#define CTAP1_ERR_INVALID_CMD        0x01
#define CTAP1_ERR_INVALID_LENGTH     0x03
#define CTAP2_ERR_INVALID_CBOR       0x12
#define CTAP2_ERR_MISSING_PARAMETER  0x14
#define CTAP2_ERR_OPERATION_DENIED   0x27
#define CTAP2_ERR_UNSUPPORTED_OPTION 0x2B
#define CTAP2_ERR_NO_CREDENTIALS     0x2E

static const uint8_t FIDO2_V[] = {'F','I','D','O','_','2','_','0'};

/* AAGUID — fixed 16-byte authenticator model id (also embedded in GETINFO_CBOR
 * and in each MakeCredential attestedCredentialData). */
static const uint8_t AAGUID[16] = {
    0x50,0x68,0x72,0x65,0x61,0x6b,0x62,0x79,0x74,0x65,0x55,0x32,0x46,0x32,0x00,0x01
};

/* authenticatorGetInfo response (static CBOR, non-UV up-only non-resident):
 *   {1:["FIDO_2_0"], 3:h'<aaguid>',
 *    4:{"rk":false,"up":true,"makeCredUvNotRqd":true}}
 * makeCredUvNotRqd lets a CTAP2.1 platform create a credential with user
 * presence only; without it, modern Android assumes UV is required and aborts
 * after GetInfo (never sending MakeCredential) since we expose no PIN/UV. */
static const uint8_t GETINFO_CBOR[] = {
    0xA3,
    0x01, 0x81, 0x68, 'F','I','D','O','_','2','_','0',
    0x03, 0x50, 0x50,0x68,0x72,0x65,0x61,0x6b,0x62,0x79,0x74,0x65,0x55,0x32,0x46,0x32,0x00,0x01,
    0x04, 0xA3,
        0x62,'r','k',0xF4,
        0x62,'u','p',0xF5,
        0x70,'m','a','k','e','C','r','e','d','U','v','N','o','t','R','q','d',0xF5
};

/* =====================================================================
 *  Attestation material is provisioned at RUNTIME, no code edit needed:
 *    firmware/tools/gen_u2f_attestation.sh      # make a P-256 key + cert
 *    hw u2f set-attestation -k att.key -c att.crt
 *  which stores them in FDS (keys 3/4) and overrides the fallback below.
 *  The fallback is an empty placeholder: REGISTER only yields a usable
 *  credential once a real key/cert have been provisioned.
 * ===================================================================== */
static const uint8_t U2F_ATT_PRIV_DEFAULT[32] = { 0 };
static const uint8_t U2F_ATT_CERT_DEFAULT[]   = { 0x30, 0x00 };

/* ---- session ---- */
static nfc_tag_14a_4_tcl_state_t m_tcl;
static uint8_t  m_uid[7];
/* 4-byte aligned: FDS write source data must be word-aligned. */
static uint8_t  m_mk[32]       __attribute__((aligned(4)));
static uint32_t m_ctr;
static uint8_t  m_att_priv[32] __attribute__((aligned(4)));   /* from FDS or default */

/* Large response + ISO7816 GET RESPONSE chaining (REGISTER can exceed FSC). */
static uint8_t  m_big[640];
static uint16_t m_big_len;
static uint16_t m_big_off;
/* CTAP2 (NFCCTAP) responses must go out in one ISO-DEP frame: this phone does
 * not continue an NFCCTAP response via 61 XX / GET RESPONSE (it re-SELECTs). The
 * U2F path keeps small-frame 61 XX chaining, which real U2F readers do follow. */
static bool     m_ctap2_resp;

/* fixed anti-collision identity: ISO-14443-4 (SAK bit 0x20) + a minimal ATS */
static nfc_tag_14a_uid_size s_uid_size = NFC_TAG_14A_UID_DOUBLE_SIZE;
static uint8_t  s_atqa[2]  = {0x44, 0x00};
static uint8_t  s_sak[1]   = {0x20};
static nfc_tag_14a_coll_res_reference_t s_coll;
/* ATS: TL,T0(TA/TB/TC,FSCI=8),TA=80,TB=90(high FWI for slow ECDSA),TC=00, then
 * ISO7816-4 historical bytes: 80 (category) | 73 C0 21 C0 (card-capabilities TLV,
 * full ISO7816-4 — identical to a YubiKey 5) | 5A "Phreakbyte" (issuer-data TLV).
 * Without historical bytes iOS classifies the tag as storage/DESFire and probes
 * GetVersion; these route it to the ISO7816/FIDO path, same as a real key. */
static nfc_14a_ats_t s_ats = {
    .length = 21,
    .data = {0x15, 0x78, 0x80, 0x84, 0x00,      /* TA1=80 (106k), TB1=84 (SFGI4/FWI8, as YubiKey), TC1=00 */
             0x80, 0x73, 0xC0, 0x21, 0xC0,
             0x5A, 'P','h','r','e','a','k','b','y','t','e'}
};

static nfc_tag_14a_coll_res_reference_t *u2f_get_coll_res(void) {
    s_coll.size = &s_uid_size;
    s_coll.uid  = m_uid;
    s_coll.atqa = s_atqa;
    s_coll.sak  = s_sak;
    s_coll.ats  = &s_ats;
    return &s_coll;
}

/* ===================================================================== */
/*  SHA-256 + HMAC-SHA256 (self-contained, FIPS 180-4 / RFC 2104)         */
/* ===================================================================== */
typedef struct { uint32_t s[8]; uint64_t n; uint8_t b[64]; uint8_t bl; } sha256_t;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))

static void sha256_blk(sha256_t *c, const uint8_t *p) {
    uint32_t w[64], a,b,cc,d,e,f,g,h,t1,t2;
    for (int i=0;i<16;i++) w[i]=(p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
    for (int i=16;i<64;i++){
        uint32_t s0=ROR(w[i-15],7)^ROR(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1=ROR(w[i-2],17)^ROR(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=c->s[0];b=c->s[1];cc=c->s[2];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7];
    for (int i=0;i<64;i++){
        uint32_t S1=ROR(e,6)^ROR(e,11)^ROR(e,25), ch=(e&f)^((~e)&g);
        t1=h+S1+ch+K256[i]+w[i];
        uint32_t S0=ROR(a,2)^ROR(a,13)^ROR(a,22), mj=(a&b)^(a&cc)^(b&cc);
        t2=S0+mj;
        h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void sha256_init(sha256_t *c){
    c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;
    c->n=0;c->bl=0;
}
static void sha256_upd(sha256_t *c, const uint8_t *p, size_t n){
    c->n+=n;
    while(n){
        uint8_t k=64-c->bl; if(k>n)k=n;
        memcpy(c->b+c->bl,p,k); c->bl+=k; p+=k; n-=k;
        if(c->bl==64){ sha256_blk(c,c->b); c->bl=0; }
    }
}
static void sha256_fin(sha256_t *c, uint8_t out[32]){
    uint64_t bits=c->n*8; uint8_t pad=0x80;
    sha256_upd(c,&pad,1);
    uint8_t z=0; while(c->bl!=56) sha256_upd(c,&z,1);
    uint8_t L[8]; for(int i=0;i<8;i++) L[i]=(uint8_t)(bits>>(56-8*i));
    sha256_upd(c,L,8);
    for(int i=0;i<8;i++){ out[i*4]=c->s[i]>>24;out[i*4+1]=c->s[i]>>16;out[i*4+2]=c->s[i]>>8;out[i*4+3]=c->s[i]; }
}
static void hmac_sha256(const uint8_t *key, size_t kl, const uint8_t *msg, size_t ml, uint8_t out[32]){
    uint8_t k[64]={0}, ip[64], op[64], ih[32]; sha256_t c;
    if(kl>64){ sha256_init(&c); sha256_upd(&c,key,kl); sha256_fin(&c,k); } else memcpy(k,key,kl);
    for(int i=0;i<64;i++){ ip[i]=k[i]^0x36; op[i]=k[i]^0x5c; }
    sha256_init(&c); sha256_upd(&c,ip,64); sha256_upd(&c,msg,ml); sha256_fin(&c,ih);
    sha256_init(&c); sha256_upd(&c,op,64); sha256_upd(&c,ih,32); sha256_fin(&c,out);
}

/* ===================================================================== */
static int u2f_rng(uint8_t *dest, unsigned size){
    return nrf_drv_rng_rand(dest, (uint8_t)size) == NRF_SUCCESS ? 1 : 0;
}

/* DER-encode an ECDSA (r,s) pair (each 32 bytes) into out. Returns length. */
static uint16_t der_sig(const uint8_t *rs, uint8_t *out){
    const uint8_t *r=rs, *s=rs+32;
    uint8_t rb[33], sb[33]; int rl=32, sl=32;
    memcpy(rb, r, 32); memcpy(sb, s, 32);
    /* strip leading zeros, then prepend one if high bit set (positive INTEGER) */
    int ro=0; while(ro<31 && rb[ro]==0) ro++; rl=32-ro;
    uint8_t rbuf[33]; int rn=0; if(rb[ro]&0x80) rbuf[rn++]=0x00; memcpy(rbuf+rn, rb+ro, rl); rn+=rl;
    int so=0; while(so<31 && sb[so]==0) so++; sl=32-so;
    uint8_t sbuf[33]; int sn=0; if(sb[so]&0x80) sbuf[sn++]=0x00; memcpy(sbuf+sn, sb+so, sl); sn+=sl;
    uint16_t i=0;
    out[i++]=0x30; out[i++]=(uint8_t)(2+rn+2+sn);
    out[i++]=0x02; out[i++]=(uint8_t)rn; memcpy(out+i, rbuf, rn); i+=rn;
    out[i++]=0x02; out[i++]=(uint8_t)sn; memcpy(out+i, sbuf, sn); i+=sn;
    return i;
}

/* Derive the per-credential private key and the handle MAC from (appId,nonce). */
static void derive_priv(const uint8_t *app, const uint8_t *nonce, uint8_t priv[32]){
    uint8_t in[1+32+32]; in[0]=0x01; memcpy(in+1,app,32); memcpy(in+33,nonce,32);
    hmac_sha256(m_mk, sizeof(m_mk), in, sizeof(in), priv);
}
static void derive_mac(const uint8_t *app, const uint8_t *nonce, uint8_t mac[32]){
    uint8_t in[1+32+32]; in[0]=0x02; memcpy(in+1,app,32); memcpy(in+33,nonce,32);
    hmac_sha256(m_mk, sizeof(m_mk), in, sizeof(in), mac);
}

static void ctr_save(void){ fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_CTR, sizeof(m_ctr), &m_ctr); }

/* Provision the attestation key (32 bytes) + cert (DER) into FDS at runtime,
 * so users set them over the CLI instead of editing source. Takes effect on
 * the next arm; the key is also applied live if the mode is armed. */
bool u2f_set_attestation(const uint8_t *priv, const uint8_t *cert, uint16_t cert_len) {
    if (!priv || !cert || cert_len < 2 || cert_len > U2F_ATT_CERT_MAX) return false;
    /* FDS requires word-aligned source data; the inbound command buffer sits at
     * an odd offset after the frame preamble, so stage into aligned buffers. */
    static uint32_t priv_buf[32 / 4];
    static uint32_t cert_buf[(U2F_ATT_CERT_MAX + 3) / 4];
    memcpy(priv_buf, priv, 32);
    memcpy(cert_buf, cert, cert_len);
    bool ok = fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_ATT_PRIV, 32, priv_buf);
    ok = fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_ATT_CERT, cert_len, cert_buf) && ok;
    if (ok) memcpy(m_att_priv, priv, 32);
    return ok;
}

/* ---- APDU helpers ---- */
static uint16_t put_sw(uint8_t *resp, uint16_t off, uint16_t sw){
    resp[off++]=(uint8_t)(sw>>8); resp[off++]=(uint8_t)sw; return off;
}

/* Parse an ISO7816 command: short or extended Lc/Le. Fills *data,*lc. */
static bool apdu_parse(const uint8_t *a, uint16_t n, const uint8_t **data, uint16_t *lc){
    if (n < 4) return false;
    *data=NULL; *lc=0;
    if (n == 4) return true;                     /* no body */
    if (a[4] != 0) {                             /* short */
        *lc=a[4]; *data=a+5; return (5+*lc) <= n;
    }
    if (n < 7) return true;                      /* extended, no body (Le only) */
    *lc=(a[5]<<8)|a[6]; *data=a+7; return (7+*lc) <= n;
}

/* Build REGISTER response into m_big. */
static uint16_t do_register(const uint8_t *body, uint16_t lc, uint8_t *out){
    if (lc != 64) return put_sw(out, 0, SW_WRONG_LENGTH);
    /* Refuse if the attestation key isn't provisioned (all-zero) — signing with
     * an invalid scalar can hang uECC. Run `hw u2f set-attestation` first. */
    uint8_t az = 0; for (int i = 0; i < 32; i++) az |= m_att_priv[i];
    if (az == 0) return put_sw(out, 0, SW_CONDITIONS_NOT_SAT);
    const uint8_t *chal=body, *app=body+32;
    uint8_t nonce[32], priv[32], pub[64], kh[KH_LEN], mac[32];
    uECC_Curve C = uECC_secp256r1();

    for (int tries=0; ; tries++){
        if (tries>8) return put_sw(out,0,SW_WRONG_DATA);
        if (!u2f_rng(nonce,32)) return put_sw(out,0,SW_WRONG_DATA);
        derive_priv(app, nonce, priv);
        if (uECC_compute_public_key(priv, pub, C)) break;   /* valid scalar */
    }
    derive_mac(app, nonce, mac);
    memcpy(kh, nonce, 32); memcpy(kh+32, mac, 32);

    /* attestation signature over 0x00 | app | chal | kh | 0x04|pub */
    uint8_t pub65[65]; pub65[0]=0x04; memcpy(pub65+1, pub, 64);
    sha256_t c; uint8_t h[32]; uint8_t pfx=0x00;
    sha256_init(&c); sha256_upd(&c,&pfx,1); sha256_upd(&c,app,32); sha256_upd(&c,chal,32);
    sha256_upd(&c,kh,KH_LEN); sha256_upd(&c,pub65,65); sha256_fin(&c,h);
    uint8_t sig_rs[64], sig_der[72];
    if (!uECC_sign(m_att_priv, h, 32, sig_rs, C)) return put_sw(out,0,SW_WRONG_DATA);
    uint16_t sig_len = der_sig(sig_rs, sig_der);

    /* attestation cert: provisioned record (FDS, zero-copy) or the fallback */
    fds_record_desc_t cdesc; uint16_t clen = 0;
    const uint8_t *cert = fds_peek(U2F_FDS_FILE, U2F_FDS_KEY_ATT_CERT, &clen, &cdesc);
    bool peeked = (cert != NULL);
    if (!peeked) { cert = U2F_ATT_CERT_DEFAULT; clen = sizeof(U2F_ATT_CERT_DEFAULT); }

    uint16_t i=0;
    out[i++]=0x05;
    memcpy(out+i, pub65, 65); i+=65;
    out[i++]=KH_LEN;
    memcpy(out+i, kh, KH_LEN); i+=KH_LEN;
    memcpy(out+i, cert, clen); i+=clen;
    if (peeked) fds_peek_close(&cdesc);
    memcpy(out+i, sig_der, sig_len); i+=sig_len;
    i = put_sw(out, i, SW_NO_ERROR);
    return i;
}

/* Build AUTHENTICATE response. */
static uint16_t do_authenticate(uint8_t p1, const uint8_t *body, uint16_t lc, uint8_t *out){
    if (lc < 65) return put_sw(out,0,SW_WRONG_LENGTH);
    const uint8_t *chal=body, *app=body+32;
    uint8_t khl=body[64];
    if (khl != KH_LEN || lc < (uint16_t)(65+khl)) return put_sw(out,0,SW_WRONG_DATA);
    const uint8_t *kh=body+65, *nonce=kh, *mac=kh+32;

    uint8_t want[32]; derive_mac(app, nonce, want);
    if (memcmp(want, mac, 32) != 0) return put_sw(out,0,SW_WRONG_DATA);  /* not ours */
    if (p1 == U2F_AUTH_CHECK_ONLY) return put_sw(out,0,SW_CONDITIONS_NOT_SAT); /* "mine" */

    /* NFC tap is the presence gesture. */
    uint8_t up=0x01;
    m_ctr++; ctr_save();
    uint8_t ctb[4]={ (uint8_t)(m_ctr>>24),(uint8_t)(m_ctr>>16),(uint8_t)(m_ctr>>8),(uint8_t)m_ctr };

    uint8_t priv[32]; derive_priv(app, nonce, priv);
    sha256_t c; uint8_t h[32];
    sha256_init(&c); sha256_upd(&c,app,32); sha256_upd(&c,&up,1); sha256_upd(&c,ctb,4); sha256_upd(&c,chal,32);
    sha256_fin(&c,h);
    uint8_t sig_rs[64], sig_der[72];
    uECC_Curve C = uECC_secp256r1();
    if (!uECC_sign(priv, h, 32, sig_rs, C)) return put_sw(out,0,SW_WRONG_DATA);
    uint16_t sig_len = der_sig(sig_rs, sig_der);

    uint16_t i=0;
    out[i++]=up; memcpy(out+i, ctb, 4); i+=4;
    memcpy(out+i, sig_der, sig_len); i+=sig_len;
    i = put_sw(out, i, SW_NO_ERROR);
    return i;
}

/* Build a CTAP response into m_big: [status][cbor...] then SW 9000 (NFCCTAP
 * always returns 9000 at the APDU layer; the CTAP status lives in byte 0). */
static uint16_t ctap_err(uint8_t status){
    m_big[0] = status;
    m_big_len = put_sw(m_big, 1, SW_NO_ERROR);
    return m_big_len;
}

/* ---- minimal definite-length CBOR reader (the subset CTAP input uses) ---- */
typedef struct { const uint8_t *p, *end; } cbor_t;

/* Read a data item head: major type + argument. Advances past any argument. */
static bool cbor_head(cbor_t *c, uint8_t *major, uint64_t *val){
    if (c->p >= c->end) return false;
    uint8_t ib = *c->p++, ai = ib & 0x1F;
    *major = ib >> 5;
    if (ai < 24) { *val = ai; return true; }
    uint8_t nb = (ai == 24) ? 1 : (ai == 25) ? 2 : (ai == 26) ? 4 : (ai == 27) ? 8 : 0xFF;
    if (nb == 0xFF || c->p + nb > c->end) return false;
    uint64_t v = 0;
    for (uint8_t i = 0; i < nb; i++) v = (v << 8) | *c->p++;
    *val = v;
    return true;
}

/* Read a byte or text string: point ptr/len at its body, advance past it. */
static bool cbor_str(cbor_t *c, const uint8_t **ptr, uint64_t *len){
    uint8_t m; uint64_t v;
    if (!cbor_head(c, &m, &v) || (m != 2 && m != 3) || c->p + v > c->end) return false;
    *ptr = c->p; *len = v; c->p += v;
    return true;
}

/* Skip one item (recursively for arrays/maps). */
static bool cbor_skip(cbor_t *c){
    uint8_t m; uint64_t v;
    if (!cbor_head(c, &m, &v)) return false;
    switch (m) {
    case 0: case 1: case 7: return true;                 /* uint / negint / simple */
    case 2: case 3: if (c->p + v > c->end) return false; c->p += v; return true;
    case 4: for (uint64_t i = 0; i < v; i++) if (!cbor_skip(c)) return false; return true;
    case 5: for (uint64_t i = 0; i < 2 * v; i++) if (!cbor_skip(c)) return false; return true;
    default: return false;
    }
}

/* Is this map-key the text string "id"? (leaves cursor after the key either way) */
static bool key_is(const uint8_t *ks, uint64_t kl, const char *s){
    size_t n = strlen(s);
    return kl == n && memcmp(ks, s, n) == 0;
}

/* COSE_Key for a P-256 public key: {1:2,3:-7,-1:1,-2:x,-3:y}. */
static uint16_t cose_p256(uint8_t *o, const uint8_t *pub){
    uint16_t i = 0;
    o[i++] = 0xA5;
    o[i++] = 0x01; o[i++] = 0x02;                         /* kty: EC2  */
    o[i++] = 0x03; o[i++] = 0x26;                         /* alg: ES256 (-7) */
    o[i++] = 0x20; o[i++] = 0x01;                         /* crv: P-256 */
    o[i++] = 0x21; o[i++] = 0x58; o[i++] = 0x20; memcpy(o + i, pub, 32);      i += 32;  /* x */
    o[i++] = 0x22; o[i++] = 0x58; o[i++] = 0x20; memcpy(o + i, pub + 32, 32); i += 32;  /* y */
    return i;
}

static void sc4_of(uint32_t v, uint8_t *o){
    o[0]=(uint8_t)(v>>24); o[1]=(uint8_t)(v>>16); o[2]=(uint8_t)(v>>8); o[3]=(uint8_t)v;
}

/* authenticatorMakeCredential — non-UV, non-resident, self (packed) attestation.
 * We only need clientDataHash (key 1) and rp.id (key 2); the credential is the
 * same stateless key-wrap U2F uses, so no credential is stored. */
static uint16_t ctap_make_credential(const uint8_t *d, uint16_t len){
    cbor_t c = { d, d + len };
    uint8_t m; uint64_t np;
    if (!cbor_head(&c, &m, &np) || m != 5) return ctap_err(CTAP2_ERR_INVALID_CBOR);

    const uint8_t *cdh = NULL, *rpid = NULL; uint64_t cdh_len = 0, rpid_len = 0;
    for (uint64_t i = 0; i < np; i++) {
        uint8_t km; uint64_t key;
        if (!cbor_head(&c, &km, &key) || km != 0) return ctap_err(CTAP2_ERR_INVALID_CBOR);
        if (key == 1) {                                  /* clientDataHash */
            if (!cbor_str(&c, &cdh, &cdh_len)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
        } else if (key == 2) {                           /* rp: find "id" */
            uint8_t rm; uint64_t rn;
            if (!cbor_head(&c, &rm, &rn) || rm != 5) return ctap_err(CTAP2_ERR_INVALID_CBOR);
            for (uint64_t j = 0; j < rn; j++) {
                const uint8_t *ks; uint64_t kl;
                if (!cbor_str(&c, &ks, &kl)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
                if (key_is(ks, kl, "id")) {
                    if (!cbor_str(&c, &rpid, &rpid_len)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
                } else if (!cbor_skip(&c)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
            }
        } else if (!cbor_skip(&c)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
    }
    if (!cdh || cdh_len != 32 || !rpid) return ctap_err(CTAP2_ERR_MISSING_PARAMETER);

    uint8_t rpIdHash[32]; sha256_t sc;
    sha256_init(&sc); sha256_upd(&sc, rpid, rpid_len); sha256_fin(&sc, rpIdHash);

    uint8_t nonce[32], priv[32], pub[64], mac[32];
    uECC_Curve C = uECC_secp256r1();
    for (int t = 0; ; t++) {
        if (t > 8) return ctap_err(CTAP2_ERR_OPERATION_DENIED);
        if (!u2f_rng(nonce, 32)) return ctap_err(CTAP2_ERR_OPERATION_DENIED);
        derive_priv(rpIdHash, nonce, priv);
        if (uECC_compute_public_key(priv, pub, C)) break;
    }
    derive_mac(rpIdHash, nonce, mac);
    uint8_t credId[KH_LEN]; memcpy(credId, nonce, 32); memcpy(credId + 32, mac, 32);

    m_ctr++; ctr_save();
    uint8_t sc4[4]; sc4_of(m_ctr, sc4);

    /* authData = rpIdHash | flags(UP|AT) | signCount | attestedCredentialData */
    uint8_t ad[256]; uint16_t ap = 0;
    memcpy(ad + ap, rpIdHash, 32); ap += 32;
    ad[ap++] = 0x41;                                     /* UP(0x01) | AT(0x40) */
    memcpy(ad + ap, sc4, 4); ap += 4;
    memcpy(ad + ap, AAGUID, 16); ap += 16;
    ad[ap++] = 0x00; ad[ap++] = KH_LEN;                  /* credentialId length */
    memcpy(ad + ap, credId, KH_LEN); ap += KH_LEN;
    ap += cose_p256(ad + ap, pub);

    (void)cdh;   /* "none" attestation signs nothing at registration */

    /* response map {1:"none", 2:authData, 3:{}} — "none" attestation keeps the
     * response in a single frame (packed self-attestation would overrun the
     * 260-byte frame buffer). The RP records the pubkey from authData; the
     * credential proves possession at GetAssertion. */
    uint8_t *o = m_big; uint16_t i = 0;
    o[i++] = CTAP2_OK;
    o[i++] = 0xA3;
    o[i++] = 0x01; o[i++] = 0x64; memcpy(o + i, "none", 4); i += 4;
    o[i++] = 0x02; o[i++] = 0x58; o[i++] = (uint8_t)ap; memcpy(o + i, ad, ap); i += ap;
    o[i++] = 0x03; o[i++] = 0xA0;                        /* attStmt: {} */
    m_big_len = put_sw(o, i, SW_NO_ERROR);
    return m_big_len;
}

/* authenticatorGetAssertion — verifies the allow-list credential is ours, then
 * signs authData | clientDataHash. rpId(1), clientDataHash(2), allowList(3). */
static uint16_t ctap_get_assertion(const uint8_t *d, uint16_t len){
    cbor_t c = { d, d + len };
    uint8_t m; uint64_t np;
    if (!cbor_head(&c, &m, &np) || m != 5) return ctap_err(CTAP2_ERR_INVALID_CBOR);

    const uint8_t *rpid = NULL, *cdh = NULL, *credId = NULL;
    uint64_t rpid_len = 0, cdh_len = 0, credId_len = 0;
    for (uint64_t i = 0; i < np; i++) {
        uint8_t km; uint64_t key;
        if (!cbor_head(&c, &km, &key) || km != 0) return ctap_err(CTAP2_ERR_INVALID_CBOR);
        if (key == 1) {                                  /* rpId */
            if (!cbor_str(&c, &rpid, &rpid_len)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
        } else if (key == 2) {                           /* clientDataHash */
            if (!cbor_str(&c, &cdh, &cdh_len)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
        } else if (key == 3) {                           /* allowList: first id */
            uint8_t am; uint64_t an;
            if (!cbor_head(&c, &am, &an) || am != 4) return ctap_err(CTAP2_ERR_INVALID_CBOR);
            for (uint64_t j = 0; j < an; j++) {
                uint8_t em; uint64_t en;
                if (!cbor_head(&c, &em, &en) || em != 5) return ctap_err(CTAP2_ERR_INVALID_CBOR);
                for (uint64_t k = 0; k < en; k++) {
                    const uint8_t *ks; uint64_t kl;
                    if (!cbor_str(&c, &ks, &kl)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
                    if (key_is(ks, kl, "id") && !credId) {
                        if (!cbor_str(&c, &credId, &credId_len)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
                    } else if (!cbor_skip(&c)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
                }
            }
        } else if (!cbor_skip(&c)) return ctap_err(CTAP2_ERR_INVALID_CBOR);
    }
    if (!rpid || !cdh || cdh_len != 32) return ctap_err(CTAP2_ERR_MISSING_PARAMETER);
    if (!credId || credId_len != KH_LEN) return ctap_err(CTAP2_ERR_NO_CREDENTIALS);

    uint8_t rpIdHash[32]; sha256_t sc;
    sha256_init(&sc); sha256_upd(&sc, rpid, rpid_len); sha256_fin(&sc, rpIdHash);

    const uint8_t *nonce = credId, *mac = credId + 32;
    uint8_t want[32]; derive_mac(rpIdHash, nonce, want);
    if (memcmp(want, mac, 32) != 0) return ctap_err(CTAP2_ERR_NO_CREDENTIALS);  /* not ours */
    uint8_t priv[32]; derive_priv(rpIdHash, nonce, priv);

    m_ctr++; ctr_save();
    uint8_t sc4[4]; sc4_of(m_ctr, sc4);

    uint8_t ad[37];                                      /* rpIdHash | flags(UP) | signCount */
    memcpy(ad, rpIdHash, 32); ad[32] = 0x01; memcpy(ad + 33, sc4, 4);
    uint8_t h[32];
    sha256_init(&sc); sha256_upd(&sc, ad, 37); sha256_upd(&sc, cdh, 32); sha256_fin(&sc, h);
    uint8_t sig_rs[64], sig_der[72];
    uECC_Curve C = uECC_secp256r1();
    if (!uECC_sign(priv, h, 32, sig_rs, C)) return ctap_err(CTAP2_ERR_OPERATION_DENIED);
    uint16_t sl = der_sig(sig_rs, sig_der);

    /* response {1:{id,type}, 2:authData, 3:signature} */
    uint8_t *o = m_big; uint16_t i = 0;
    o[i++] = CTAP2_OK;
    o[i++] = 0xA3;
    o[i++] = 0x01; o[i++] = 0xA2;
    o[i++] = 0x62; o[i++]='i'; o[i++]='d'; o[i++] = 0x58; o[i++] = KH_LEN; memcpy(o + i, credId, KH_LEN); i += KH_LEN;
    o[i++] = 0x64; o[i++]='t'; o[i++]='y'; o[i++]='p'; o[i++]='e';
    o[i++] = 0x6A; memcpy(o + i, "public-key", 10); i += 10;
    o[i++] = 0x02; o[i++] = 0x58; o[i++] = 37; memcpy(o + i, ad, 37); i += 37;
    o[i++] = 0x03; o[i++] = 0x58; o[i++] = (uint8_t)sl; memcpy(o + i, sig_der, sl); i += sl;
    m_big_len = put_sw(o, i, SW_NO_ERROR);
    return m_big_len;
}

/* CTAP2 command dispatch. `d` = command byte + CBOR; `len` includes the cmd. */
static uint16_t ctap2_dispatch(const uint8_t *d, uint16_t len){
    if (!d || len < 1) return ctap_err(CTAP1_ERR_INVALID_LENGTH);
    uint8_t cmd = d[0];
    NRF_LOG_INFO("ctap2 cmd=%02X len=%u", cmd, len);   /* trace; drop later */
    switch (cmd) {
    case CTAP_CMD_GET_INFO:
        m_big[0] = CTAP2_OK;
        memcpy(m_big + 1, GETINFO_CBOR, sizeof(GETINFO_CBOR));
        m_big_len = put_sw(m_big, 1 + sizeof(GETINFO_CBOR), SW_NO_ERROR);
        return m_big_len;
    case CTAP_CMD_MAKE_CRED:
        return ctap_make_credential(d + 1, len - 1);
    case CTAP_CMD_GET_ASSERT:
        return ctap_get_assertion(d + 1, len - 1);
    default:
        return ctap_err(CTAP1_ERR_INVALID_CMD);
    }
}

/* APDU dispatch → writes to m_big, returns total length (incl SW). */
static uint16_t u2f_process(const uint8_t *a, uint16_t n){
    m_ctap2_resp = false;
    if (n < 4) { m_big_len = put_sw(m_big,0,SW_WRONG_LENGTH); return m_big_len; }
    uint8_t cla=a[0], ins=a[1], p1=a[2];
    const uint8_t *body; uint16_t lc;
    if (!apdu_parse(a,n,&body,&lc)) { m_big_len = put_sw(m_big,0,SW_WRONG_LENGTH); return m_big_len; }

    /* ISO SELECT by name (CLA 00, INS A4, P1 04) — answer FIDO_2_0 so the
     * platform drives CTAP2; a U2F-only reader that insists on U2F_V2 won't
     * engage, which is the accepted trade for phone support. */
    if (cla == 0x00 && ins == ISO_INS_SELECT) {
        if (p1 == 0x04 && body && lc >= sizeof(U2F_AID) &&
                memcmp(body, U2F_AID, sizeof(U2F_AID)) == 0) {
            memcpy(m_big, FIDO2_V, sizeof(FIDO2_V));
            m_big_len = put_sw(m_big, sizeof(FIDO2_V), SW_NO_ERROR);
        } else {
            m_big_len = put_sw(m_big, 0, SW_FILE_NOT_FOUND);
        }
        return m_big_len;
    }

    /* CTAP2: NFCCTAP_MSG (CLA 80, INS 10) carries cmd byte + CBOR. */
    if (cla == 0x80 && ins == NFCCTAP_MSG) {
        m_ctap2_resp = true;                 /* single-frame response */
        return ctap2_dispatch(body, lc);
    }

    /* U2F / CTAP1 fallback (CLA 00). */
    if (cla == 0x00) {
        switch (ins) {
        case U2F_INS_VERSION:
            memcpy(m_big, U2F_V2, sizeof(U2F_V2));
            m_big_len = put_sw(m_big, sizeof(U2F_V2), SW_NO_ERROR);
            return m_big_len;
        case U2F_INS_REGISTER:
            return (m_big_len = do_register(body, lc, m_big));
        case U2F_INS_AUTHENTICATE:
            return (m_big_len = do_authenticate(p1, body, lc, m_big));
        }
    }

    m_big_len = put_sw(m_big, 0, SW_INS_NOT_SUPPORTED);
    return m_big_len;
}

/* Emit the next response chunk (ISO7816 chaining). If more remains, the chunk
 * ends with 61 XX and the reader follows up with GET RESPONSE (00 C0 ..). */
static void emit_chunk(void){
    uint16_t remain = m_big_len - m_big_off;
    m_tcl.m_tx_chaining = false;          /* U2F path never layer-4 chains */
    /* U2F/CTAP1 path: 58-byte ISO7816 GET-RESPONSE chunks (fits a 64-byte-FIFO
     * reader). CTAP2 responses use layer-4 chaining instead (see emit_ctap). */
    uint16_t max = 58;
    if (remain <= max) {
        memcpy(m_tcl.m_resp_buf, m_big + m_big_off, remain);
        m_tcl.m_resp_len = remain;
        m_big_off = m_big_len;                        /* done */
    } else {
        /* send `max` payload bytes (no SW yet) then 61 XX */
        memcpy(m_tcl.m_resp_buf, m_big + m_big_off, max);
        m_big_off += max;
        uint16_t left = m_big_len - m_big_off - 2;    /* bytes still owed (excl final SW) */
        uint8_t xx = left > 0xFF ? 0x00 : (uint8_t)left;
        m_tcl.m_resp_buf[max]   = 0x61;
        m_tcl.m_resp_buf[max+1] = xx;
        m_tcl.m_resp_len = max + 2;
    }
    m_tcl.m_response_ready = true;
}

/* Hand the whole CTAP2 response to the engine for ISO-DEP layer-4 chaining:
 * it goes out in <=58-byte I-block fragments, each ACKed by the reader. This
 * works for a 64-byte-FIFO reader (a second CU) and for a phone alike, unlike a
 * single large frame or ISO7816 61 XX (which this phone won't continue). */
static void emit_ctap(void){
    uint16_t len = m_big_len;
    if (len > NFC_14A_4_MAX_APDU) len = NFC_14A_4_MAX_APDU;   /* CTAP resp fits (<=~211) */
    memcpy(m_tcl.m_resp_buf, m_big, len);
    m_tcl.m_resp_len = len;

    /* Fragment to the reader's advertised frame size (RATS FSDI) minus PCB+CRC.
     * A phone (FSD 256) takes the whole response in one frame — no chaining. A
     * 64-byte-FIFO reader (a second CU) advertises a small FSD and gets it in
     * chained I-block fragments it can actually receive. */
    uint16_t fsd = nfc_tag_14a_get_reader_fsd();
    uint16_t frag = (fsd > 3) ? (fsd - 3) : 58;              /* 1 PCB + 2 CRC */
    if (frag > NFC_14A_4_MAX_APDU) frag = NFC_14A_4_MAX_APDU;
    m_tcl.m_tx_off      = 0;
    m_tcl.m_tx_frag     = frag;
    m_tcl.m_tx_chaining = (len > frag);
    m_tcl.m_response_ready = true;
}

/* ===================================================================== */
/*  ISO-DEP handler (ISR) — delegate framing to the 14a_4 engine          */
/* ===================================================================== */
static void u2f_cb_state(uint8_t *data, uint16_t szBits){
    /* nfc_14a delivers the frame length in BITS; the 14a_4 engine works in
     * bytes. ISO-DEP frames are byte-aligned, so divide. */
    uint16_t szBytes = szBits / 8;
    if (!nfc_tag_14a_4_base_handler(&m_tcl, data, szBytes)) return;

    /* Complete APDU assembled. Hold the reader with S(WTX) and build the answer
     * in on_tick — far too slow for the ISR once ECDSA is involved. */
    nfc_tag_14a_4_base_respond(&m_tcl);
}

static void u2f_cb_reset(void){
    nfc_tag_14a_4_reset_state(&m_tcl);
    m_big_len = 0; m_big_off = 0;
}

static nfc_tag_14a_handler_t s_handler = {
    .get_coll_res = u2f_get_coll_res,
    .cb_state     = u2f_cb_state,
    .cb_reset     = u2f_cb_reset,
};

/* ===================================================================== */
/*  Lifecycle                                                             */
/* ===================================================================== */
static standalone_rc_t on_enter(const uint8_t *cfg, size_t cfg_len){
    (void)cfg; (void)cfg_len;

    uECC_set_rng(u2f_rng);

    /* master key: load, or create on first use */
    uint16_t mkl = sizeof(m_mk);
    if (!fds_read_sync(U2F_FDS_FILE, U2F_FDS_KEY_MK, &mkl, m_mk) || mkl != sizeof(m_mk)) {
        if (!u2f_rng(m_mk, sizeof(m_mk))) return STANDALONE_RC_INVALID_STATE;
        fds_write_sync(U2F_FDS_FILE, U2F_FDS_KEY_MK, sizeof(m_mk), m_mk);
    }
    uint16_t cl = sizeof(m_ctr);
    if (!fds_read_sync(U2F_FDS_FILE, U2F_FDS_KEY_CTR, &cl, (uint8_t *)&m_ctr) || cl != sizeof(m_ctr))
        m_ctr = 0;

    /* attestation key: provisioned (FDS) overrides the compiled fallback */
    uint16_t apl = sizeof(m_att_priv);
    if (!fds_read_sync(U2F_FDS_FILE, U2F_FDS_KEY_ATT_PRIV, &apl, m_att_priv) || apl != sizeof(m_att_priv))
        memcpy(m_att_priv, U2F_ATT_PRIV_DEFAULT, sizeof(m_att_priv));

    if (!u2f_rng(m_uid, sizeof(m_uid))) return STANDALONE_RC_INVALID_STATE;
    m_uid[0] = 0x08;   /* RID-style first byte; avoids 0x88 cascade marker clash */

    nfc_tag_14a_4_reset_state(&m_tcl);
    m_big_len = 0; m_big_off = 0;

    nfc_tag_14a_set_handler(&s_handler);
    nfc_tag_14a_set_relay_hold(true);    /* keep FRAMEDELAYMAX wide for slow ECDSA */
    nfc_tag_14a_sense_switch(false);
    nfc_tag_14a_sense_switch(true);

    standalone_led_set_mode_color(STANDALONE_MODE_U2F, RGB_BLUE);
    standalone_led_solid();
    NRF_LOG_INFO("u2f: armed ctr=%lu", (unsigned long)m_ctr);
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_exit(void){
    nfc_tag_14a_set_relay_hold(false);
    nfc_tag_14a_set_frame_delay_max(0x00001000UL);
    nfc_tag_14a_set_state(NFC_TAG_STATE_14A_IDLE);
    memset(m_mk, 0, sizeof(m_mk));
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_tick(uint32_t now_ms){
    (void)now_ms;
    if (!m_tcl.m_apdu_pending) return STANDALONE_RC_OK;
    m_tcl.m_apdu_pending = false;

    /* The NFCT RX leaves the 2-byte ISO14443 CRC on the frame (hardware CRC
     * strip is off and the 14a_4 layer doesn't remove it), so drop it before
     * parsing — otherwise a body-less APDU's absent Lc reads the CRC as an
     * extended length and fails. */
    uint16_t alen = m_tcl.m_apdu_len >= 2 ? m_tcl.m_apdu_len - 2 : 0;

    NRF_LOG_INFO("rx alen=%u", alen);   /* debug: raw inbound APDU — drop later */
    NRF_LOG_HEXDUMP_INFO(m_tcl.m_apdu_buf, alen > 32 ? 32 : alen);

    uint8_t cla = alen >= 1 ? m_tcl.m_apdu_buf[0] : 0;
    uint8_t ins = alen >= 2 ? m_tcl.m_apdu_buf[1] : 0;
    /* Chained-response continuation: ISO GET RESPONSE (00 C0) for U2F, or
     * NFCCTAP_GETRESPONSE (80 11) for CTAP2 — both signalled by our 61 XX. */
    bool getresp = (cla == 0x00 && ins == ISO_INS_GET_RESPONSE) ||
                   (cla == 0x80 && ins == NFCCTAP_GETRESPONSE);
    if (getresp && m_big_off < m_big_len) {
        emit_chunk();
        return STANDALONE_RC_OK;
    }
    u2f_process(m_tcl.m_apdu_buf, alen);
    NRF_LOG_INFO("u2f tx len=%u b0=%02X", m_big_len, m_big[0]);
    if (m_ctap2_resp) {
        emit_ctap();                  /* CTAP2: layer-4 chained response */
    } else {
        m_big_off = 0;
        emit_chunk();                 /* U2F: 61 XX GET-RESPONSE chunks */
    }
    return STANDALONE_RC_OK;
}

static standalone_rc_t on_button(standalone_button_evt_t evt){ (void)evt; return STANDALONE_RC_OK; }

const standalone_mode_iface_t mode_u2f_iface = {
    .id               = STANDALONE_MODE_U2F,
    .name             = "u2f",
    .writes_tag       = false,
    .writes_slot      = false,
    .wants_tick       = true,
    .tick_interval_ms = 5,          /* answer APDUs promptly within the WTX window */
    .on_enter         = on_enter,
    .on_exit          = on_exit,
    .on_button        = on_button,
    .on_tick          = on_tick,
    .get_result_size  = NULL,
    .read_result      = NULL,
    .clear_result     = NULL,
    .ensure_loaded    = NULL,
};
