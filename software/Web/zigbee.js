"use strict";
/* zigbee.js - host-side parsing of 802.15.4 / Zigbee frames from the `zigbee`
 * standalone mode (STANDALONE_MODE_ZIGBEE, mode 13). Ported faithfully from
 * software/script/zb_parse.py + cli_zigbee.py (pure functions, no device
 * access there either -- this file only decodes bytes already fetched by
 * canary.js's fetchSaved()).
 *
 * Frames are MPDUs without the FCS. Layouts follow IEEE 802.15.4 (MAC FCF)
 * and the Zigbee NWK header; the NWK header is cleartext even when the
 * payload is secured. Anything not understood is reported as null/"unparsed"
 * instead of guessed, same as the Python side.
 *
 * Extended (64-bit) addresses use BigInt (JS Number can't hold 64 bits
 * exactly) -- Python's arbitrary-precision int.from_bytes(...,"little")
 * is mirrored with bytesToBigIntLE()/fmtIeee() below.
 */

/* ---------------------------------------------------------------------
 * AES-128 single-block encrypt (textbook FIPS-197), used only to build the
 * CCM* keystream/CBC-MAC blocks below. Web Crypto's SubtleCrypto has no raw
 * ECB single-block primitive, and this page must keep working standalone/
 * offline, so no external crypto library either.
 * ------------------------------------------------------------------- */
const AES_SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];
const AES_RCON = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36];

function aesKeyExpansion128(key){   // key: 16 bytes -> 176-byte (44-word) schedule
  const Nk=4, Nr=10, w=new Uint8Array(16*(Nr+1));
  w.set(key,0);
  for(let i=Nk;i<4*(Nr+1);i++){
    let t0=w[(i-1)*4], t1=w[(i-1)*4+1], t2=w[(i-1)*4+2], t3=w[(i-1)*4+3];
    if(i%Nk===0){
      const r0=t1,r1=t2,r2=t3,r3=t0;   // RotWord
      t0=AES_SBOX[r0]^AES_RCON[i/Nk]; t1=AES_SBOX[r1]; t2=AES_SBOX[r2]; t3=AES_SBOX[r3];
    }
    w[i*4]=w[(i-Nk)*4]^t0; w[i*4+1]=w[(i-Nk)*4+1]^t1; w[i*4+2]=w[(i-Nk)*4+2]^t2; w[i*4+3]=w[(i-Nk)*4+3]^t3;
  }
  return w;
}
const gmul2 = x => ((x<<1) ^ ((x&0x80)?0x1b:0)) & 0xFF;
function aesEncryptBlock(key, block){   // key:16B, block:16B -> 16B, both plain arrays
  const w=aesKeyExpansion128(key);
  const s=block.slice(0,16);
  const addRK=round=>{ for(let i=0;i<16;i++) s[i]^=w[round*16+i]; };
  const subBytes=()=>{ for(let i=0;i<16;i++) s[i]=AES_SBOX[s[i]]; };
  const shiftRows=()=>{
    const t=s.slice();
    for(let r=1;r<4;r++) for(let c=0;c<4;c++) s[c*4+r]=t[((c+r)%4)*4+r];
  };
  const mixColumns=()=>{
    for(let c=0;c<4;c++){
      const a0=s[c*4],a1=s[c*4+1],a2=s[c*4+2],a3=s[c*4+3];
      s[c*4]   = gmul2(a0) ^ (gmul2(a1)^a1) ^ a2 ^ a3;
      s[c*4+1] = a0 ^ gmul2(a1) ^ (gmul2(a2)^a2) ^ a3;
      s[c*4+2] = a0 ^ a1 ^ gmul2(a2) ^ (gmul2(a3)^a3);
      s[c*4+3] = (gmul2(a0)^a0) ^ a1 ^ a2 ^ gmul2(a3);
    }
  };
  addRK(0);
  for(let round=1;round<=9;round++){ subBytes(); shiftRows(); mixColumns(); addRK(round); }
  subBytes(); shiftRows(); addRK(10);
  return s;
}

/* ---------------------------------------------------------------------
 * AES-CCM* (RFC 3610-style construction, L=2 -> 2-byte length field, 4-byte
 * MIC), mirroring zb_parse.py's ccm_decrypt() byte for byte. Everything here
 * works on plain number[] byte arrays (same convention as the rest of this
 * console), not Uint8Array/ArrayBuffer.
 * ------------------------------------------------------------------- */
function xorBytes(a,b){ const n=Math.min(a.length,b.length), o=new Array(n); for(let i=0;i<n;i++) o[i]=a[i]^b[i]; return o; }
function ccmDecrypt(key, nonce, aad, ct, mic){
  // key:16B, nonce:13B, aad/ct/mic: plain byte arrays
  const blk = b => aesEncryptBlock(key, b);
  const ctr = i => { const b=new Array(16).fill(0); b[0]=1; for(let k=0;k<13;k++) b[1+k]=nonce[k];
    b[14]=(i>>8)&0xFF; b[15]=i&0xFF; return blk(b); };
  const pt=[];
  for(let o=0;o<ct.length;o+=16){
    const ks=ctr(Math.floor(o/16)+1);
    const chunk=ct.slice(o,Math.min(o+16,ct.length));
    pt.push(...xorBytes(chunk,ks));
  }
  const flags=(aad.length ? 0x40:0) | (((mic.length-2)/2)<<3) | 1;
  const b0=new Array(16).fill(0); b0[0]=flags; for(let k=0;k<13;k++) b0[1+k]=nonce[k];
  b0[14]=(pt.length>>8)&0xFF; b0[15]=pt.length&0xFF;
  let x=blk(b0);
  let data=[];
  if(aad.length) data.push((aad.length>>8)&0xFF, aad.length&0xFF, ...aad);
  while(data.length%16!==0) data.push(0);
  const ptPadded=pt.slice();
  while(ptPadded.length%16!==0) ptPadded.push(0);
  data=data.concat(ptPadded);
  for(let o=0;o<data.length;o+=16) x=blk(xorBytes(x,data.slice(o,o+16)));
  const s0=ctr(0);
  const tag=xorBytes(x.slice(0,mic.length), s0.slice(0,mic.length));
  let ok=tag.length===mic.length;
  for(let i=0;i<tag.length && ok;i++) if(tag[i]!==mic[i]) ok=false;
  return {pt, micOk:ok};
}

/* ---------------------------------------------------------------------
 * Candidate NWK/APS keys. Public, documented well-known Zigbee keys -- see
 * zb_parse.py/cli_zigbee.py's module docstrings for sourcing. Not secrets.
 * ------------------------------------------------------------------- */
function hexToBytes(h){ const out=[]; for(let i=0;i+1<h.length;i+=2) out.push(parseInt(h.substr(i,2),16)); return out; }
const ZIGBEE_DEFAULT_KEY = hexToBytes("5a6967426565416c6c69616e63653039");   // ZigBeeAlliance09 (HA default TC link key)
const ZLL_MASTER_KEY     = hexToBytes("9f5595f10257c8a96573ab53ee2d4c0d");
const ZLL_CERT_ENC_KEY   = hexToBytes("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
const ZLL_CERT_LINK_KEY  = hexToBytes("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
const NWK_FALLBACK_KEYS = [
  ["default key (ZigBeeAlliance09)", ZIGBEE_DEFAULT_KEY],
  ["ZLL master key", ZLL_MASTER_KEY],
  ["ZLL certification link key", ZLL_CERT_LINK_KEY],
];
const APS_JOIN_KEYS = [
  ["ZigBeeAlliance09 (HA default TC link key)", ZIGBEE_DEFAULT_KEY],
  ["ZLL master key", ZLL_MASTER_KEY],
  ["ZLL certification link key", ZLL_CERT_LINK_KEY],
];

/* ---------------------------------------------------------------------
 * OUI vendor lookup. zb_parse.py ships a full IEEE MA-L registry as a
 * separate .tsv file; that file isn't pulled into this static web console
 * (no bulk-fetching a giant external OUI database here), so this is just
 * its small built-in fallback table -- same 5 entries, same source.
 * ------------------------------------------------------------------- */
const OUI_VENDORS = {
  "000D6F": "Ember/Silicon Labs", "00124B": "Texas Instruments",
  "0013A2": "MaxStream/Digi (XBee)", "00158D": "Jennic/NXP", "C09B9E": "Silicon Labs",
};
function bytesToBigIntLE(bytes){ let v=0n; for(let i=bytes.length-1;i>=0;i--) v=(v<<8n)|BigInt(bytes[i]); return v; }
function ouiVendor(eui64){   // eui64: BigInt
  const oui=((eui64>>40n)&0xFFFFFFn).toString(16).toUpperCase().padStart(6,"0");
  return OUI_VENDORS[oui] || null;
}
function fmtIeee(v){   // v: BigInt -> canonical big-endian colon hex, same as zb_parse.py's fmt_ieee
  const bytes=[]; let x=v;
  for(let i=0;i<8;i++){ bytes.unshift(Number(x & 0xFFn)); x >>= 8n; }
  return bytes.map(b=>b.toString(16).padStart(2,"0")).join(":");
}

/* ---------------------------------------------------------------------
 * Record framing: u8 channel, u8 lqi_raw, u8 len, u8 data[len] (see
 * mode_zigbee.c, REC_HDR=3).
 * ------------------------------------------------------------------- */
function parseZigbeeRecords(blob){
  const out=[]; let i=0;
  while(i+3<=blob.length){
    const ch=blob[i], lqi=blob[i+1], ln=blob[i+2];
    if(i+3+ln>blob.length) break;
    out.push({channel:ch, lqi, frame:blob.slice(i+3,i+3+ln)});
    i+=3+ln;
  }
  return out;
}

const FRAME_TYPES = {0:"beacon",1:"data",2:"ack",3:"command"};

function zbAddr(buf, off, mode){   // mode 2 = short (u16), 3 = extended (BigInt)
  const n = mode===2 ? 2 : 8;
  if(off+n>buf.length) return [null, off];
  if(n===2) return [buf[off] | (buf[off+1]<<8), off+2];
  return [bytesToBigIntLE(buf.slice(off,off+8)), off+8];
}

function parseMac(f){
  if(f.length<2) return null;
  const fcf=f[0] | (f[1]<<8);
  const m = {
    type: fcf&7, security: !!(fcf&8), ackReq: !!(fcf&0x20),
    panidComp: !!(fcf&0x40), seqSuppr: !!(fcf&0x100),
    ie: !!(fcf&0x200), dstMode: (fcf>>10)&3,
    version: (fcf>>12)&3, srcMode: (fcf>>14)&3,
    seq: null, dstPan: null, dst: null, srcPan: null, src: null,
    payloadOff: null, ok: false,
  };
  let off=2;
  if(!m.seqSuppr){
    if(f.length<3) return m;
    m.seq=f[2]; off=3;
  }
  if(m.dstMode===1 || m.srcMode===1) return m;   // reserved address mode
  if(m.dstMode){
    if(off+2>f.length) return m;
    m.dstPan = f[off] | (f[off+1]<<8); off+=2;
    const [dst,off2]=zbAddr(f,off,m.dstMode);
    if(dst===null) return m;
    m.dst=dst; off=off2;
  }
  if(m.srcMode){
    if(!(m.panidComp && m.dstMode)){
      if(off+2>f.length) return m;
      m.srcPan = f[off] | (f[off+1]<<8); off+=2;
    } else m.srcPan = m.dstPan;
    const [src,off2]=zbAddr(f,off,m.srcMode);
    if(src===null) return m;
    m.src=src; off=off2;
  }
  m.payloadOff=off;
  m.ok=true;
  return m;
}

function parseBeacon(f, m){   // Zigbee beacon payload (15 bytes), plain beacons only
  if(!m || !m.ok || m.type!==0 || m.security || m.ie) return null;
  const o=m.payloadOff;
  if(o+4>f.length) return null;
  const sf=f[o] | (f[o+1]<<8);
  const gts=f[o+2], pend=f[o+3];
  if((gts&7) || pend) return null;   // GTS descriptors / pending addresses present
  const p=f.slice(o+4);
  if(p.length<15 || p[0]!==0) return null;
  return {
    coordinator: !!(sf&0x4000), permitJoin: !!(sf&0x8000),
    stackProfile: p[1]&0xF, nwkVer: p[1]>>4,
    routerCap: !!(p[2]&4), depth: (p[2]>>3)&0xF, edCap: !!(p[2]&0x80),
    epid: bytesToBigIntLE(p.slice(3,11)),
    nwkUpdateId: p[14],
  };
}

function parseAux(p, o){
  if(o+5>p.length) return null;
  const ctrl=p[o];
  const a = {ctrl, keyId:(ctrl>>3)&3, counter:(p[o+1]|(p[o+2]<<8)|(p[o+3]<<16)|(p[o+4]<<24))>>>0,
    srcIeee: null, keySeq: null};
  let e=o+5;
  if(ctrl & 0x20){
    if(e+8>p.length) return null;
    a.srcIeee = bytesToBigIntLE(p.slice(e,e+8)); e+=8;
  }
  if(a.keyId===1){
    if(e+1>p.length) return null;
    a.keySeq=p[e]; e+=1;
  }
  a.end=e;
  return a;
}

function parseNwk(f, m){   // NWK header of a data frame (MAC payload). Unsecured MAC frames only.
  if(!m || !m.ok || m.type!==1 || m.security) return null;
  const p=f.slice(m.payloadOff);
  if(p.length<8) return null;
  const fcf=p[0] | (p[1]<<8);
  const n = {
    ftype: fcf&3, proto:(fcf>>2)&0xF, security: !!(fcf&0x200),
    dst: p[2]|(p[3]<<8), src: p[4]|(p[5]<<8), radius: p[6], seq: p[7],
    dstIeee: null, srcIeee: null,
  };
  let o=8;
  if(fcf & 0x800){
    if(o+8>p.length) return null;
    n.dstIeee = bytesToBigIntLE(p.slice(o,o+8)); o+=8;
  }
  if(fcf & 0x1000){
    if(o+8>p.length) return null;
    n.srcIeee = bytesToBigIntLE(p.slice(o,o+8)); o+=8;
  }
  if((fcf & 0x400) || (fcf & 0x100)){   // source route / multicast: header not walked
    n.hdrLen=null;
    return n;
  }
  n.hdrLen=o;
  n.aux=null;
  if(n.security) n.aux=parseAux(p,o);
  return n;
}

function nwkDecrypt(f, m, n, key){
  if(!n || !n.aux || n.hdrLen==null) return null;
  const a=n.aux;
  const src = a.srcIeee!=null ? a.srcIeee : n.srcIeee;
  if(src==null || key.length!==16) return null;
  const p=f.slice(m.payloadOff);
  const ctrl=(a.ctrl & ~7) | 5;
  const nonce=[];
  let sv=src; for(let i=0;i<8;i++){ nonce.push(Number(sv & 0xFFn)); sv>>=8n; }
  nonce.push(a.counter&0xFF,(a.counter>>8)&0xFF,(a.counter>>16)&0xFF,(a.counter>>24)&0xFF);
  nonce.push(ctrl);
  const hdr = p.slice(0,n.hdrLen).concat([ctrl], p.slice(n.hdrLen+1, a.end));
  const body = p.slice(a.end);
  if(body.length<4) return null;
  const r=ccmDecrypt(key, nonce, hdr, body.slice(0,body.length-4), body.slice(body.length-4));
  return [r.pt, r.micOk];
}

/* ---------------------------------------------------------------------
 * APS layer -- only enough to catch a Transport-Key command travelling
 * cleartext at the NWK layer during a device's join (see cli_zigbee.py's
 * dump command / parse_transport_key's docstring on sourcing/confidence).
 * ------------------------------------------------------------------- */
const APS_CMD_TRANSPORT_KEY = 0x05;
const TRANSPORT_KEY_TYPES = {
  0x00:"trust-center master key", 0x01:"standard network key",
  0x02:"application master key", 0x03:"application link key",
  0x04:"trust-center link key", 0x05:"high-security network key",
};

function parseAps(p){
  if(p.length<2) return null;
  const fcf=p[0];
  const a = {
    ftype: fcf&3, delivery:(fcf>>2)&3, ackFormat: !!(fcf&0x10),
    security: !!(fcf&0x20), ackReq: !!(fcf&0x40), extHeader: !!(fcf&0x80),
    counter: p[1], aux: null, hdrLen: null,
  };
  if(a.extHeader) return a;          // fragmentation framing, not handled
  if(a.ftype!==1) return a;          // data/ack/interpan: fields not parsed
  let o=2;
  if(a.security){
    const aux=parseAux(p,o);
    if(aux===null) return a;
    a.aux=aux; o=aux.end;
  }
  a.hdrLen=o;
  return a;
}

function apsDecrypt(p, a, key){
  if(!a || !a.aux || a.hdrLen==null) return null;
  const aux=a.aux;
  if(aux.srcIeee==null || key.length!==16) return null;
  const ctrl=(aux.ctrl & ~7) | 5;
  const nonce=[];
  let sv=aux.srcIeee; for(let i=0;i<8;i++){ nonce.push(Number(sv & 0xFFn)); sv>>=8n; }
  nonce.push(aux.counter&0xFF,(aux.counter>>8)&0xFF,(aux.counter>>16)&0xFF,(aux.counter>>24)&0xFF);
  nonce.push(ctrl);
  const hdr = p.slice(0,a.hdrLen).slice();
  hdr[2]=ctrl;   // force the level bits in the aux ctrl byte (position 2: APS fcf+counter are 0,1)
  const body=p.slice(a.hdrLen);
  if(body.length<4) return null;
  const r=ccmDecrypt(key, nonce, hdr, body.slice(0,body.length-4), body.slice(body.length-4));
  return [r.pt, r.micOk];
}

function parseTransportKey(plain){
  if(plain.length<2 || plain[0]!==APS_CMD_TRANSPORT_KEY) return null;
  const keyType=plain[1];
  const r = {keyType, keyTypeName: TRANSPORT_KEY_TYPES[keyType] || ("type "+keyType)};
  if(keyType===0x01 && plain.length>=2+16+1+8+8){
    const o=2;
    r.key=plain.slice(o,o+16);
    r.seq=plain[o+16];
    r.dstIeee=bytesToBigIntLE(plain.slice(o+17,o+25));
    r.srcIeee=bytesToBigIntLE(plain.slice(o+25,o+33));
    r.decoded=true;
  } else {
    r.decoded=false;
    r.raw=plain.slice(2);
  }
  return r;
}

/* ---------------------------------------------------------------------
 * One-line decode, mirroring zb_parse.py's describe_frame().
 * ------------------------------------------------------------------- */
function describeZigbeeFrame(ch, lqi, f){
  const m=parseMac(f);
  let line = "ch"+ch+" lqi="+lqi+" len="+f.length+" ";
  if(!m) return line+"short: "+zbHex(f);
  line += FRAME_TYPES[m.type] || ("type"+m.type);
  if(!m.ok) return line+" (header not parsed)";
  if(m.seq!==null) line += " seq="+m.seq;
  if(m.dst!==null) line += " dst="+(m.dstPan!=null?"0x"+m.dstPan.toString(16).padStart(4,"0"):"?")+":"+zbAddrHex(m.dst);
  if(m.src!==null) line += " src="+(m.srcPan!=null?"0x"+m.srcPan.toString(16).padStart(4,"0"):"?")+":"+zbAddrHex(m.src);
  if(m.security) line += " [mac-secured]";
  const b=parseBeacon(f,m), n=parseNwk(f,m);
  if(b){
    line += " EPID="+fmtIeee(b.epid)+" profile="+b.stackProfile+" depth="+b.depth+" join="+(b.permitJoin?"y":"n");
  } else if(n){
    const ftypeName = ["data","cmd","?","interpan"][n.ftype];
    line += " nwk["+ftypeName+" 0x"+n.src.toString(16).padStart(4,"0")+"->0x"+n.dst.toString(16).padStart(4,"0")+" r="+n.radius+" s="+n.seq+(n.security?" nwk-secured":"")+"]";
    for(const [tag,ieee] of [["src",n.srcIeee],["dst",n.dstIeee]]){
      if(ieee!=null){
        const vendor=ouiVendor(ieee);
        line += " "+tag+"-ieee="+fmtIeee(ieee)+(vendor?" ("+vendor+")":"");
      }
    }
  }
  return line;
}
function zbAddrHex(a){ return "0x"+a.toString(16); }   // works for both Number (short addr) and BigInt (extended)
function zbHex(bytes){ return bytes.map(b=>b.toString(16).padStart(2,"0")).join(""); }

/* ---------------------------------------------------------------------
 * Render into <ul id="saved"> -- a `dump`-style view: each frame decoded +
 * hex, best-effort NWK decrypt with the well-known fallback keys, and APS
 * Transport-Key capture (network-key recovery) when a join is present in
 * the capture. Mirrors cli_zigbee.py's `dump` command, minus the -k custom
 * key field (nothing in this console's generic CFG framework carries a
 * separate "decrypt key" that isn't the mode's own radio config) and minus
 * the time-boxed scan/devices aggregation (this console drains the device
 * log once per Fetch click, like every other mode, rather than polling for
 * a fixed --time window).
 * ------------------------------------------------------------------- */
function renderZigbee(recs){
  const ul = document.getElementById("saved");
  ul.textContent = "";
  const pans = new Set();
  for(const r of recs){
    const m = parseMac(r.frame);
    if(m && m.ok && m.srcPan!=null && m.srcPan!==0xFFFF) pans.add(m.srcPan);
  }
  if(pans.size){
    const li=document.createElement("li"); li.className="ev l1";
    const top=document.createElement("div"); top.className="top";
    const s=document.createElement("strong"); s.textContent = pans.size+" PAN(s) seen";
    top.append(s);
    const d=document.createElement("div"); d.className="det";
    d.textContent = [...pans].map(p=>"0x"+p.toString(16).padStart(4,"0")).join(", ");
    li.append(top,d); ul.append(li);
  }
  recs.forEach(r=>{
    const m=parseMac(r.frame);
    const n=m ? parseNwk(r.frame,m) : null;
    const li=document.createElement("li"); li.className="ev"+(m&&m.security?" l2":"");
    const top=document.createElement("div"); top.className="top";
    const s=document.createElement("strong"); s.textContent="ch"+r.channel+"  "+(FRAME_TYPES[m&&m.type]||"frame");
    const tm=document.createElement("time"); tm.textContent="lqi "+r.lqi+" · len "+r.frame.length;
    top.append(s,tm);
    const d=document.createElement("div"); d.className="det";
    d.textContent = describeZigbeeFrame(r.channel, r.lqi, r.frame);
    li.append(top,d);
    const hexLine=document.createElement("div"); hexLine.className="det"; hexLine.textContent=zbHex(r.frame);
    li.append(hexLine);
    if(n && n.aux){
      for(const [label,key] of NWK_FALLBACK_KEYS){
        const res=nwkDecrypt(r.frame,m,n,key);
        if(res){
          const [pt,ok]=res;
          const e=document.createElement("div"); e.className="det";
          e.textContent="nwk payload ["+label+", "+(ok?"MIC ok":"MIC FAIL")+"]: "+zbHex(pt);
          li.append(e);
          if(ok) break;
        }
      }
    }
    // Join-time key recovery: an APS Transport-Key command travels as NWK
    // data that's cleartext at the NWK layer but secured at the APS layer
    // under a TC link key -- decrypting that reveals the real NWK key.
    if(n && n.ftype===0 && !n.security && n.hdrLen!=null){
      const apsPayload = r.frame.slice(m.payloadOff + n.hdrLen);
      const a = parseAps(apsPayload);
      if(a && a.ftype===1 && a.security && a.aux){
        for(const [label,key] of APS_JOIN_KEYS){
          const res=apsDecrypt(apsPayload, a, key);
          if(res && res[0] && res[0][0]===APS_CMD_TRANSPORT_KEY){
            const tk=parseTransportKey(res[0]);
            const ok=res[1];
            const e=document.createElement("div"); e.className="det";
            e.textContent="*** APS Transport Key ["+label+", "+(ok?"MIC ok":"MIC FAIL")+"] type="+tk.keyTypeName+" ***"+
              (tk.decoded ? ("\n    network key: "+zbHex(tk.key)+" seq="+tk.seq+" dst="+fmtIeee(tk.dstIeee)+" src="+fmtIeee(tk.srcIeee))
                          : ("\n    (key type not decoded) raw="+zbHex(tk.raw)));
            li.append(e);
            if(ok) break;
          }
        }
      }
    }
    ul.append(li);
  });
}
