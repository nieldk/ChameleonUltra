"use strict";
/* disasm_thumb.js -- a small ARM Thumb / Thumb-2 (ARMv7E-M) disassembler for
 * `hw gdb disassemble`. Covers the instruction classes that actually show up
 * in this firmware (verified against the real build, see note below) --
 * not the full ISA. Anything outside that falls back to ".word 0xXXXX" /
 * ".word 0xXXXXXXXX" rather than guessing, so a gap is visible, not wrong.
 *
 * Cross-checked against Capstone's Thumb-2 decoder on firmware/application.bin
 * during development (not shipped; Capstone has no browser build and this
 * file only needs to read code off a live Chameleon over mem-read). Register
 * names, condition codes and operand formatting follow GNU binutils/gdb
 * convention (lowercase, "r0".."r12", sp/lr/pc, "#imm", "[rn, #off]").
 *
 * Wrapped in its own IIFE and exposing only disassembleThumb globally --
 * canary.js/fullcmd.js/terminal.js share one global scope (none of them are
 * modules), and this file's own helpers (hex, regList, ...) would otherwise
 * collide with same-named globals already declared there (canary.js has its
 * own unrelated `hex`).
 */
(function(){

// r9/r10/r11/r12 use the APCS names binutils/gdb print by default (sb/sl/fp/ip)
// -- found by diffing against real firmware.bin: "movhi ip, r0" was coming
// out as "mov r12, r0", same instruction, different register name.
const REGN = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","sb","sl","fp","ip","sp","lr","pc"];
// binutils/gdb print the unsigned-comparison aliases "hs"/"lo" for the
// carry-set/carry-clear conditions, not "cs"/"cc" -- found against real
// firmware.bin ("bcs 0x..." was coming out where gdb shows "bhs 0x...").
const CONDN = ["eq","ne","hs","lo","mi","pl","vs","vc","hi","ls","ge","lt","gt","le","al","nv"];

function sext(v, bits){ const m = 1 << (bits-1); return (v & (m-1)) - (v & m); }
function hex(v, w){ let s=(v<0?(v+0x100000000):v).toString(16); while(s.length<w) s="0"+s; return "0x"+s; }
function signedHex(v){ return v<0 ? "-0x"+(-v).toString(16) : "0x"+v.toString(16); }
function regList(mask){
  const parts=[]; let i=0;
  while(i<16){
    if(mask&(1<<i)){
      let j=i; while(j+1<16 && (mask&(1<<(j+1)))) j++;
      parts.push(j>i ? REGN[i]+"-"+REGN[j] : REGN[i]);
      i=j+1;
    } else i++;
  }
  return "{"+parts.join(", ")+"}";
}

/* ---- Thumb-1 (16-bit) ------------------------------------------------- */
function decode16(w, addr){
  const op = (b,n)=> (w>>>b)&((1<<n)-1);

  // Shift/add/sub/move (000ooxxx xxxxxxxx) and format-1/2
  if((w>>>13)===0b000){
    const opc = op(11,2), sub = op(10,1);
    const rd = op(0,3), rs = op(3,3);
    if(opc===0b00 || opc===0b01){ // LSL/LSR imm (opc 00 LSL, 01 LSR); shift 0b10 handled below
      const imm = op(6,5);
      const mnem = opc===0b00 ? "lsls" : "lsrs";
      if(opc===0b00 && imm===0) return {size:2, text:"movs "+REGN[rd]+", "+REGN[rs]};
      return {size:2, text:mnem+" "+REGN[rd]+", "+REGN[rs]+", #"+imm};
    }
    if(opc===0b10){ // ASR imm, or ADD/SUB reg/imm3 (format 2) share this space via bit12
      if(op(12,1)===0){
        const imm = op(6,5);
        return {size:2, text:"asrs "+REGN[rd]+", "+REGN[rs]+", #"+imm};
      }
    }
    if(opc===0b11){
      const rn = op(6,3);
      const mnem = ["adds","subs","adds","subs"][sub*2 + op(9,1)]; // placeholder, refined below
    }
  }
  // Re-decode with precise ARM-ARM groupings (clearer than the fallthrough above):
  if((w>>>11)===0b00000){ const imm=op(6,5), rs=op(3,3), rd=op(0,3); return {size:2, text: imm===0? "movs "+REGN[rd]+", "+REGN[rs] : "lsls "+REGN[rd]+", "+REGN[rs]+", #"+imm}; }
  if((w>>>11)===0b00001){ const imm=op(6,5), rs=op(3,3), rd=op(0,3); return {size:2, text:"lsrs "+REGN[rd]+", "+REGN[rs]+", #"+(imm===0?32:imm)}; }
  if((w>>>11)===0b00010){ const imm=op(6,5), rs=op(3,3), rd=op(0,3); return {size:2, text:"asrs "+REGN[rd]+", "+REGN[rs]+", #"+(imm===0?32:imm)}; }
  if((w>>>9)===0b0001100){ const rm=op(6,3), rn=op(3,3), rd=op(0,3); return {size:2, text:"adds "+REGN[rd]+", "+REGN[rn]+", "+REGN[rm]}; }
  if((w>>>9)===0b0001101){ const rm=op(6,3), rn=op(3,3), rd=op(0,3); return {size:2, text:"subs "+REGN[rd]+", "+REGN[rn]+", "+REGN[rm]}; }
  if((w>>>9)===0b0001110){ const imm=op(6,3), rn=op(3,3), rd=op(0,3); return {size:2, text:"adds "+REGN[rd]+", "+REGN[rn]+", #"+imm}; }
  if((w>>>9)===0b0001111){ const imm=op(6,3), rn=op(3,3), rd=op(0,3); return {size:2, text:"subs "+REGN[rd]+", "+REGN[rn]+", #"+imm}; }
  if((w>>>11)===0b00100){ const rd=op(8,3), imm=op(0,8); return {size:2, text:"movs "+REGN[rd]+", #"+hex(imm,2)}; }
  if((w>>>11)===0b00101){ const rd=op(8,3), imm=op(0,8); return {size:2, text:"cmp "+REGN[rd]+", #"+hex(imm,2)}; }
  if((w>>>11)===0b00110){ const rd=op(8,3), imm=op(0,8); return {size:2, text:"adds "+REGN[rd]+", #"+hex(imm,2)}; }
  if((w>>>11)===0b00111){ const rd=op(8,3), imm=op(0,8); return {size:2, text:"subs "+REGN[rd]+", #"+hex(imm,2)}; }

  if((w>>>10)===0b010000){ // data-processing register, 16 ops
    const opc=op(6,4), rm=op(3,3), rdn=op(0,3);
    const names=["ands","eors","lsls","lsrs","asrs","adcs","sbcs","rors","tst","rsbs","cmp","cmn","orrs","muls","bics","mvns"];
    if(opc===8) return {size:2, text:"tst "+REGN[rdn]+", "+REGN[rm]};
    if(opc===9) return {size:2, text:"rsbs "+REGN[rdn]+", "+REGN[rm]+", #0"};
    if(opc===10) return {size:2, text:"cmp "+REGN[rdn]+", "+REGN[rm]};
    if(opc===11) return {size:2, text:"cmn "+REGN[rdn]+", "+REGN[rm]};
    if(opc===13) return {size:2, text:"muls "+REGN[rdn]+", "+REGN[rm]+", "+REGN[rdn]};
    return {size:2, text:names[opc]+" "+REGN[rdn]+", "+REGN[rm]};
  }
  if((w>>>10)===0b010001){ // special data: ADD/CMP/MOV hi, BX, BLX
    const opc=op(8,2), d_hi=op(7,1), rm=op(3,4);
    const rdn = (d_hi<<3)|op(0,3);
    if(opc===0) return {size:2, text:"add "+REGN[rdn]+", "+REGN[rm]};
    if(opc===1) return {size:2, text:"cmp "+REGN[rdn]+", "+REGN[rm]};
    if(opc===2) return {size:2, text:"mov "+REGN[rdn]+", "+REGN[rm]};
    if(opc===3){
      if(d_hi===0) return {size:2, text:"bx "+REGN[rm]};
      return {size:2, text:"blx "+REGN[rm]};
    }
  }
  if((w>>>11)===0b01001){ const rt=op(8,3), imm=op(0,8)<<2; return {size:2, text:"ldr "+REGN[rt]+", [pc, #"+hex(imm,0)+"]", pcRel:imm}; }
  if((w>>>9)===0b0101000){ const rm=op(6,3),rn=op(3,3),rt=op(0,3); return {size:2, text:"str "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+"]"}; }
  if((w>>>9)===0b0101001){ const rm=op(6,3),rn=op(3,3),rt=op(0,3); return {size:2, text:"strh "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+"]"}; }
  if((w>>>9)===0b0101010){ const rm=op(6,3),rn=op(3,3),rt=op(0,3); return {size:2, text:"strb "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+"]"}; }
  if((w>>>9)===0b0101011){ const rm=op(6,3),rn=op(3,3),rt=op(0,3); return {size:2, text:"ldrsb "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+"]"}; }
  if((w>>>9)===0b0101100){ const rm=op(6,3),rn=op(3,3),rt=op(0,3); return {size:2, text:"ldr "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+"]"}; }
  if((w>>>9)===0b0101101){ const rm=op(6,3),rn=op(3,3),rt=op(0,3); return {size:2, text:"ldrh "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+"]"}; }
  if((w>>>9)===0b0101110){ const rm=op(6,3),rn=op(3,3),rt=op(0,3); return {size:2, text:"ldrb "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+"]"}; }
  if((w>>>9)===0b0101111){ const rm=op(6,3),rn=op(3,3),rt=op(0,3); return {size:2, text:"ldrsh "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+"]"}; }
  if((w>>>11)===0b01100){ const imm=op(6,5)<<2,rn=op(3,3),rt=op(0,3); return {size:2, text:"str "+REGN[rt]+", ["+REGN[rn]+", #"+hex(imm,0)+"]"}; }
  if((w>>>11)===0b01101){ const imm=op(6,5)<<2,rn=op(3,3),rt=op(0,3); return {size:2, text:"ldr "+REGN[rt]+", ["+REGN[rn]+", #"+hex(imm,0)+"]"}; }
  if((w>>>11)===0b01110){ const imm=op(6,5),rn=op(3,3),rt=op(0,3); return {size:2, text:"strb "+REGN[rt]+", ["+REGN[rn]+", #"+hex(imm,0)+"]"}; }
  if((w>>>11)===0b01111){ const imm=op(6,5),rn=op(3,3),rt=op(0,3); return {size:2, text:"ldrb "+REGN[rt]+", ["+REGN[rn]+", #"+hex(imm,0)+"]"}; }
  if((w>>>11)===0b10000){ const imm=op(6,5)<<1,rn=op(3,3),rt=op(0,3); return {size:2, text:"strh "+REGN[rt]+", ["+REGN[rn]+", #"+hex(imm,0)+"]"}; }
  if((w>>>11)===0b10001){ const imm=op(6,5)<<1,rn=op(3,3),rt=op(0,3); return {size:2, text:"ldrh "+REGN[rt]+", ["+REGN[rn]+", #"+hex(imm,0)+"]"}; }
  if((w>>>11)===0b10010){ const rt=op(8,3),imm=op(0,8)<<2; return {size:2, text:"str "+REGN[rt]+", [sp, #"+hex(imm,0)+"]"}; }
  if((w>>>11)===0b10011){ const rt=op(8,3),imm=op(0,8)<<2; return {size:2, text:"ldr "+REGN[rt]+", [sp, #"+hex(imm,0)+"]"}; }
  if((w>>>11)===0b10100){ const rd=op(8,3),imm=op(0,8)<<2; return {size:2, text:"adr "+REGN[rd]+", #"+hex(imm,0), pcRel:imm, isAdr:true}; }
  if((w>>>11)===0b10101){ const rd=op(8,3),imm=op(0,8)<<2; return {size:2, text:"add "+REGN[rd]+", sp, #"+hex(imm,0)}; }

  if((w>>>12)===0b1011){
    // "Miscellaneous 16-bit instructions". lo (bits11:8) must be matched
    // EXACTLY for each sub-family below -- the previous version used loose
    // masks (e.g. (lo&0b1110)===0b0010 for sxt/uxt) that also matched CBZ/
    // CBNZ/PUSH/POP's own lo values, silently misdecoding real CBZ/CBNZ as
    // sxth/rev/push/pop/sub-sp and real IT/hints as POP. Every value below
    // (including the add-vs-sub split via bit7, not a second lo value) was
    // re-derived from real firmware.bin instructions via Capstone, not from
    // memory of the ARM ARM.
    const lo=op(8,4);
    if(lo===0b0000){ const sub=op(7,1), imm=op(0,7)<<2; return {size:2, text:(sub?"sub sp, sp, #":"add sp, sp, #")+hex(imm,0)}; }
    if(lo===0b0010){ const op1=op(6,2),rm=op(3,3),rd=op(0,3);
      const nm=["sxth","sxtb","uxth","uxtb"][op1]; return {size:2, text:nm+" "+REGN[rd]+", "+REGN[rm]}; }
    if(lo===0b1010){ const op1=op(6,2),rm=op(3,3),rd=op(0,3);
      const nm=["rev","rev16",null,"revsh"][op1]; return {size:2, text:(nm||"?")+" "+REGN[rd]+", "+REGN[rm]}; }
    if((lo>>1)===0b010){ const r=op(8,1),mask=op(0,8); return {size:2, text:"push "+regList(mask|(r?(1<<14):0))}; }
    if((lo>>1)===0b110){ const r=op(8,1),mask=op(0,8); return {size:2, text:"pop "+regList(mask|(r?(1<<15):0))}; }
    if(lo===0b0001 || lo===0b0011 || lo===0b1001 || lo===0b1011){
      const nz=(lo>>3)&1, i1=op(9,1), rn=op(0,3), imm5=op(3,5);
      const target = addr+4 + ((i1<<6)|(imm5<<1));
      return {size:2, text:(nz?"cbnz ":"cbz ")+REGN[rn]+", "+hex(target,0), branch:target};
    }
    if(lo===0b1110){ const imm=op(0,8); return {size:2, text:"bkpt #"+imm}; }
    if(lo===0b1111){
      const opA=op(4,4), opB=op(0,4);
      if(opB===0) return {size:2, text: opA===0?"nop": opA===1?"yield": opA===2?"wfe": opA===3?"wfi": opA===4?"sev":"hint #"+opA};
      return {size:2, text:"it", itCond:opA, itMask:opB}; // text finished by the caller, which expands the t/e letters
    }
    // lo 0110/0111/1000: CPS and a reserved slot -- not implemented, falls
    // through to the ".short" fallback below rather than a wrong decode.
  }
  if((w>>>12)===0b1010){
    if(op(11,1)===0){ const rt=op(8,3),imm=op(0,8)<<2; return {size:2, text:"ldr "+REGN[rt]+", [pc, #"+hex(imm,0)+"]", pcRel:imm}; }
  }
  if((w>>>12)===0b1100){
    const l=op(11,1), rn=op(8,3), mask=op(0,8);
    return {size:2, text:(l?"ldm ":"stm ")+REGN[rn]+"!, "+regList(mask)};
  }
  if((w>>>12)===0b1101){
    const cond=op(8,4);
    if(cond===0b1111) return {size:2, text:"svc #"+op(0,8)};
    if(cond===0b1110) return {size:2, text:"udf #"+op(0,8)};
    const target = addr+4+sext(op(0,8),8)*2;
    return {size:2, text:"b"+CONDN[cond]+" "+hex(target,0), branch:target};
  }
  if((w>>>11)===0b11100){ const target=addr+4+sext(op(0,11),11)*2; return {size:2, text:"b "+hex(target,0), branch:target}; }
  return null;
}

/* ---- Thumb-2 (32-bit) -------------------------------------------------- */
function decode32(w1, w2, addr){
  const op1=(w1>>>11)&0x3, op=(a,n)=>(w1>>>a)&((1<<n)-1);
  const op2 = (a,n)=>(w2>>>a)&((1<<n)-1);

  // BL / B.W (uncond) / BLX immediate: bit15 of w2 is the family gate; bit14
  // and bit12 (bit13 is J1, part of the offset, not a mode bit) select the
  // sub-type. Verified against real firmware.bin via Capstone: bl has
  // (bit14,bit12)=(1,1), unconditional b.w has (0,1); blx(imm) -- (x,0) per
  // the ARM ARM -- doesn't occur in this firmware so is untested here.
  // bit12 of w2 must also be checked here: conditional B.W (next block) also
  // has bit15=1, and without the bit12 guard this block ran first and ate
  // every conditional branch too (verified against real firmware: beq.w/
  // bne.w/etc were coming out as "blx"). bl/b.w(uncond) both have bit12=1;
  // conditional B.W has bit12=0.
  if((w1>>>11)===0b11110 && op2(15,1)===1 && op2(12,1)===1){
    const S=op(10,1), imm10=op(0,10);
    const J1=op2(13,1), J2=op2(11,1), imm11=op2(0,11);
    const I1=1-(J1^S), I2=1-(J2^S);
    let imm = (S<<24)|(I1<<23)|(I2<<22)|(imm10<<12)|(imm11<<1);
    imm = sext(imm, 25);
    const target = (addr+4+imm)>>>0;
    const bit14=op2(14,1);
    const mnem = bit14===1 ? "bl " : "b.w ";
    return {size:4, text:mnem+hex(target,0), branch:target};
  }
  // B.W conditional (11110 S cond imm6, 10 J1 0 J2 imm11). cond 1110/1111 are
  // NOT valid conditions here (found against real firmware.bin: NOP.W and
  // DSB, both encoded in this same bit-space as "miscellaneous control
  // instructions", were coming out as "bal.w"/wrong targets) -- those two
  // cond values route to a different instruction class this decoder doesn't
  // implement, so fall through to the honest ".word" fallback instead.
  if((w1>>>11)===0b11110 && (w2 & 0xD000)===0x8000 && op(6,4)<14){
    const S=op(10,1), cond=op(6,4), imm6=op(0,6);
    const J1=op2(13,1), J2=op2(11,1), imm11=op2(0,11);
    let imm=(S<<20)|(J2<<19)|(J1<<18)|(imm6<<12)|(imm11<<1);
    imm = sext(imm, 21);
    const target=(addr+4+imm)>>>0;
    return {size:4, text:"b"+CONDN[cond]+".w "+hex(target,0), branch:target};
  }
  // MOV/MVN/data-proc modified-immediate (op1=01 or 00, op=0xx, 11110 i 0 op Rn 0 imm3 Rd imm8)
  if((w1>>>11)===0b11110 && op(9,1)===0 /* not 1x -> that's data-proc-plain-binary below handled separately */){
    const i=op(10,1), S=op(4,1), rn=op(0,4), opc=op(5,4);
    const imm3=op2(12,3), rd=op2(8,4), imm8=op2(0,8);
    const imm12=(i<<11)|(imm3<<8)|imm8;
    // Thumb_ExpandImm per ARM ARM; only used for display when op uses the carry-less constant
    function expandImm(v){
      // Thumb_ExpandImm, ARM ARM A5.3.2. Bug (found against real firmware.bin
      // via Capstone, movls.w lr,#0x50000000 was coming out as #0xa0): the
      // "which form" selector is bits11:10 of the 12-bit field, NOT bits9:8
      // -- using bits9:8 skipped the three byte-replication forms entirely
      // whenever bits11:10 happened to be 00, routing them into the rotate
      // path instead.
      const top2 = (v>>>10)&0x3;   // bits11:10
      if(top2===0){
        const sub = (v>>>8)&0x3;    // bits9:8
        const byte = v&0xFF;
        if(sub===0) return byte;
        if(sub===1) return ((byte<<16)|byte)>>>0;
        if(sub===2) return ((byte<<24)|(byte<<8))>>>0;
        return ((byte<<24)|(byte<<16)|(byte<<8)|byte)>>>0;
      }
      const rot = (v>>>7)&0x1F;     // bits11:7
      const base = 0x80|(v&0x7F);
      return rot===0 ? base : ((base>>>rot)|(base<<(32-rot)))>>>0;
    }
    const immVal = expandImm(imm12);
    const names={0:"and",1:"bic",2:"orr",3:"orn",4:"eor",8:"add",0xA:"adc",0xB:"sbc",0xD:"sub",0xE:"rsb"};
    const S_s = S?"s":"";
    if(opc===0x2 && rn===0xF) return {size:4, text:"mov"+S_s+".w "+REGN[rd]+", #"+hex(immVal,0)};
    if(opc===0x3 && rn===0xF) return {size:4, text:"mvn"+S_s+".w "+REGN[rd]+", #"+hex(immVal,0)};
    if(opc===0x0 && rd===0xF && S) return {size:4, text:"tst "+REGN[rn]+", #"+hex(immVal,0)};
    if(opc===0x4 && rd===0xF && S) return {size:4, text:"teq "+REGN[rn]+", #"+hex(immVal,0)};
    if(opc===0x8 && rd===0xF && S) return {size:4, text:"cmn "+REGN[rn]+", #"+hex(immVal,0)};
    if(opc===0xD && rd===0xF && S) return {size:4, text:"cmp "+REGN[rn]+", #"+hex(immVal,0)};
    if(names[opc]) return {size:4, text:names[opc]+S_s+".w "+REGN[rd]+", "+REGN[rn]+", #"+hex(immVal,0)};
    return {size:4, text:".word "+hex(w1,4)+" "+hex(w2,4)+"  ; data-proc-imm opc="+opc.toString(16)};
  }
  // MOVW/MOVT, ADD/SUB(W) with plain 12-bit immediate (11110 i 1 op Rn 0 imm3 Rd imm8)
  if((w1>>>11)===0b11110 && op(9,1)===1){
    const i=op(10,1), opc=op(4,5), rn=op(0,4);
    const imm3=op2(12,3), rd=op2(8,4), imm8=op2(0,8);
    if(opc===0b00100){ const imm16=(i<<11)|(imm3<<8)|imm8; const v=(rn<<12)|imm16;
      return {size:4, text:"movw "+REGN[rd]+", #"+hex(v,0)}; }
    // MOVT is opc 0b01100 (NOT 0b10100, which is SBFX below -- verified against
    // real decoded firmware.bin via Capstone; 0b10100 for "movt" was a bug).
    if(opc===0b01100){ const imm16=(i<<11)|(imm3<<8)|imm8; const v=(rn<<12)|imm16;
      return {size:4, text:"movt "+REGN[rd]+", #"+hex(v,0)}; }
    if(opc===0b00000){ const imm12=(i<<11)|(imm3<<8)|imm8; return {size:4, text:(rn===0xF?"adr ":"addw ")+REGN[rd]+", "+(rn===0xF?"":REGN[rn]+", ")+"#"+hex(imm12,0)}; }
    if(opc===0b01010){ const imm12=(i<<11)|(imm3<<8)|imm8; return {size:4, text:(rn===0xF?"adr ":"subw ")+REGN[rd]+", "+(rn===0xF?"":REGN[rn]+", ")+"#"+hex(imm12,0)}; }
    // SBFX/UBFX ("Data-processing (plain binary immediate)" group, bitfield
    // extract sub-form): imm3:imm2 is the lsb, widthm1+1 is the width.
    if(opc===0b10100 || opc===0b11100){
      const imm2=op2(6,2), widthm1=op2(0,5);
      const lsb=(imm3<<2)|imm2, width=widthm1+1;
      return {size:4, text:(opc===0b10100?"sbfx ":"ubfx ")+REGN[rd]+", "+REGN[rn]+", #"+lsb+", #"+width};
    }
    return {size:4, text:".word "+hex(w1,4)+" "+hex(w2,4)+"  ; data-proc-plainimm opc="+opc.toString(16)};
  }
  // Shift by register, T2: 111110100 S type(2) Rn | 1111 Rd 0000 Rm -- verified
  // against real firmware ("lsl.w r2, r6, r2" etc; this is a DIFFERENT top-level
  // group (11111) from the "shifted register" data-proc group (11101) below,
  // so there's no overlap between the two checks.
  // rn!==0xF excludes SXTB.W/SXTH.W/UXTB.W/UXTH.W below, which share this
  // same 9-bit prefix (found against real firmware.bin: "uxtb.w"/"uxth.w"
  // were coming out as "lsrs.w"/etc with Rn read as PC) -- a real
  // shift-by-register always has a genuine Rn to shift, so Rn=1111 can't
  // be one.
  if((w1>>>7) === 0b111110100 && op(0,4)!==0xF){
    const S=op(6,1), ty=op(4,2), rn=op(0,4);
    const rd=op2(8,4), rm=op2(0,4);
    const names=["lsl","lsr","asr","ror"];
    return {size:4, text:names[ty]+(S?"s":"")+".w "+REGN[rd]+", "+REGN[rn]+", "+REGN[rm]};
  }
  // SXTB.W/SXTH.W/UXTB.W/UXTH.W (same 9-bit prefix as shift-by-register
  // above, but with Rn fixed to 1111 since there's no register operand to
  // shift by -- just Rd, Rm and an optional ROR #0/8/16/24). Field layout
  // (bit6=size, bit4=U) derived from real firmware.bin UXTB.W/UXTH.W bytes;
  // SXTB.W/SXTH.W don't occur in this firmware so that half is untested.
  if((w1>>>7) === 0b111110100 && op(0,4)===0xF){
    const size=op(6,1), u=op(4,1);
    const rd=op2(8,4), rm=op2(0,4), rot=op2(4,2)*8;
    const nm=(u?"uxt":"sxt")+(size?"b":"h");
    return {size:4, text:nm+".w "+REGN[rd]+", "+REGN[rm]+(rot?", ror #"+rot:"")};
  }
  // Load/store single data item (byte/half/word, signed-extending loads, and
  // the PC-relative literal form). Verified field layout against real
  // firmware.bin via Capstone (op(7,1) selects the imm12 sub-form vs the
  // register/imm8 sub-forms -- an earlier version of this check used the
  // wrong bit and silently fell back to ".word" for plain STR.W/LDR.W etc).
  // bits10:9 of w1 must also be 00 here: top5=11111 alone is shared with the
  // long-multiply/divide group (bits10:9=01) and others -- without this gate,
  // UMULL/MUL/SMLABB/CLZ (real firmware.bin instructions) were being
  // swallowed here and misdecoded as ldrsh.w/etc.
  if((w1>>>12)===0b1111 && op(9,2)===0b00){
    const sizeOp = op(5,2);     // bits6:5: 00 byte, 01 half, 10 word
    const L = op(4,1);          // 0 store, 1 load (ignored for signed-extend loads)
    const signed = op(8,1);     // 1 = sign-extending load group (ldrsb/ldrsh)
    const rn = op(0,4);
    const rt = op2(12,4);
    const kindNames = [["strb","ldrb"],["strh","ldrh"],["str","ldr"]];
    if(sizeOp<=2){
      const mnemBase = signed ? (sizeOp===0?"ldrsb":sizeOp===1?"ldrsh":null) : kindNames[sizeOp][L];
      if(mnemBase && rn===0xF){ // PC-relative literal: always unsigned imm12, U at bit7
        const U=op(7,1), imm12=op2(0,12);
        const off = U? imm12 : -imm12;
        return {size:4, text:mnemBase+".w "+REGN[rt]+", [pc, #"+signedHex(off)+"]", pcRel:off};
      }
      if(mnemBase){
        if(op(7,1)===1){ // T3: unsigned imm12, [Rn, #imm12], no writeback
          const imm12 = op2(0,12);
          return {size:4, text:mnemBase+".w "+REGN[rt]+", ["+REGN[rn]+", #"+hex(imm12,0)+"]"};
        }
        if(op2(6,6)===0){ // register offset, optional LSL #0-3
          const rm=op2(0,4), lsl=op2(4,2);
          return {size:4, text:mnemBase+".w "+REGN[rt]+", ["+REGN[rn]+", "+REGN[rm]+(lsl?", lsl #"+lsl:"")+"]"};
        }
        // T4: signed imm8 with P/U/W (bit11 of w2 set, distinguishing this
        // from the register-offset form above)
        const imm8=op2(0,8), p=op2(10,1), u=op2(9,1), wb=op2(8,1);
        const off = u? imm8 : -imm8;
        const text = p
          ? mnemBase+" "+REGN[rt]+", ["+REGN[rn]+", #"+signedHex(off)+"]"+(wb?"!":"")
          : mnemBase+" "+REGN[rt]+", ["+REGN[rn]+"], #"+signedHex(off);
        return {size:4, text};
      }
    }
  }
  // LDRD/STRD immediate -- bit6=1 is the real family gate (verified against
  // real firmware.bin: the previous bit7 check was wrong and coincidentally
  // also matched most POP.W/LDM.W/STM.W encodings, since bit7 there is
  // unrelated to this group -- it's part of the load/multiple "op" field
  // below). bit8=1 further separates this from TBB/TBH, which share bit6=1
  // but have their own dedicated, more specific check further down.
  if((w1>>>9)===0b1110100 && op(6,1)===1 && op(8,1)===1){
    const P=op(8,1),U=op(7,1)===1,W=op(5,1),L=op(4,1),rn=op(0,4);
    const rt=op2(12,4), rt2=op2(8,4), imm8=op2(0,8)<<2;
    const off = U?imm8:-imm8;
    const mnem=(L?"ldrd":"strd");
    return {size:4, text:mnem+" "+REGN[rt]+", "+REGN[rt2]+", ["+REGN[rn]+", #"+signedHex(off)+"]"+(P?(W?"!":""):"")};
  }
  // LDM.W/STM.W and their PUSH.W/POP.W (Rn=sp) aliases -- bit6=0 here (the
  // LDRD/STRD/TBB family above all have bit6=1). "dir" (bits8:7) selects
  // increment-after (01, used by LDM and by the as-STM-alias case seen in
  // this firmware) vs decrement-before (10, used by PUSH.W/STMDB); L(bit4)
  // picks load/store, W(bit5) is writeback, independent of direction --
  // verified against real pop.w/push.w/ldm.w/stm.w bytes; the earlier
  // version conflated bit8 with "the push/pop selector" and inverted the
  // writeback-suffix logic, so e.g. real POP.W (bit8=0) never matched the
  // push/pop branch at all and printed as "stmdb.w"/"ldm.w" garbage instead.
  if((w1>>>9)===0b1110100 && op(6,1)===0){
    const dir=op(7,2), L=op(4,1), W=op(5,1), rn=op(0,4);
    const mask=op2(0,16);
    const isIA = dir===0b01, isDB = dir===0b10;
    if(rn===13 && isIA && L===1 && W===1) return {size:4, text:"pop.w "+regList(mask)};
    if(rn===13 && isDB && L===0 && W===1) return {size:4, text:"push.w "+regList(mask)};
    const dirSuffix = isDB ? "db.w " : ".w ";
    return {size:4, text:(L?"ldm":"stm")+dirSuffix+REGN[rn]+(W?"!":"")+", "+regList(mask)};
  }
  // TBB/TBH (111010001101 Rn, 1111 0000 000H Rm)
  if((w1>>>4)===0b111010001101 && op2(5,7)===0 && op2(4,1)===0){
    const rn=op(0,4), rm=op2(0,4), H=op2(4,1);
    return {size:4, text:(H?"tbh [":"tbb [")+REGN[rn]+", "+REGN[rm]+(H?", lsl #1]":"]")};
  }
  // SDIV/UDIV (111110111 001 Rn 1111 Rd 1111 Rm) and (...011...)
  if((w1>>>4)===0b111110111001 || (w1>>>4)===0b111110111011){
    const rn=op(0,4), rd=op2(8,4), rm=op2(0,4);
    const signedDiv=(w1>>>4)===0b111110111001;
    return {size:4, text:(signedDiv?"sdiv ":"udiv ")+REGN[rd]+", "+REGN[rn]+", "+REGN[rm]};
  }
  // Shifted-register data processing (1110101 0 ooo S Rn 0 imm2 Rd imm3 type Rm)
  if((w1>>>9)===0b1110101){
    const opc=op(5,4), S=op(4,1), rn=op(0,4);
    const rd=op2(8,4), rm=op2(0,4);
    const imm2=op2(6,2), ty=op2(4,2), imm3=op2(12,3);
    const shamt=(imm3<<2)|imm2;
    const names={0:"and",1:"bic",2:"orr",3:"orn",4:"eor",8:"add",0xA:"adc",0xB:"sbc",0xD:"sub",0xE:"rsb"};
    const shn=["lsl","lsr","asr","ror"][ty];
    const shiftTxt = shamt? ", "+shn+" #"+shamt : "";
    // ORR with Rn=1111 -> MOV(.W)/shift-mnemonic; ORN with Rn=1111 -> MVN(.W).
    // Rd/Rn/shamt layout confirmed against real firmware.bin: "lsl.w fp, r3, #2".
    if(opc===0x2 && rn===0xF) return {size:4, text:(shamt? shn+".w "+REGN[rd]+", "+REGN[rm]+", #"+shamt : "mov.w "+REGN[rd]+", "+REGN[rm])};
    if(opc===0x3 && rn===0xF) return {size:4, text:"mvn"+(S?"s":"")+".w "+REGN[rd]+", "+REGN[rm]+shiftTxt};
    // Rd=1111,S=1 flags-only forms: AND->TST, EOR->TEQ, ADD->CMN, SUB->CMP.
    if(rd===0xF && S===1){
      const cmpNames={0:"tst",4:"teq",8:"cmn",0xD:"cmp"};
      if(cmpNames[opc]) return {size:4, text:cmpNames[opc]+".w "+REGN[rn]+", "+REGN[rm]+shiftTxt};
    }
    if(names[opc]) return {size:4, text:names[opc]+(S?"s":"")+".w "+REGN[rd]+", "+REGN[rn]+", "+REGN[rm]+shiftTxt};
  }
  // MUL / MLA / MLS (111110110000 Rn 0000 Rd 0000 Rm -> MUL; 1111 Rd... -> MLA/MLS have Ra field)
  if((w1>>>4)===0b111110110000){
    const rn=op(0,4), ra=op2(12,4), rd=op2(8,4), rm=op2(0,4), op2b=op2(4,1);
    if(ra===0xF) return {size:4, text:"mul "+REGN[rd]+", "+REGN[rn]+", "+REGN[rm]};
    return {size:4, text:(op2b?"mls ":"mla ")+REGN[rd]+", "+REGN[rn]+", "+REGN[rm]+", "+REGN[ra]};
  }
  return null;
}

// IT-block letter expansion (ARM ARM A7.7.37 DecodeITBlock, direct form):
// walk mask bits from bit3 down; the lowest set bit is the terminator and
// stops the scan (no letter for it); every bit above it is 't' when it
// equals cond's own LSB, else 'e'. Verified against real "itt"/"ite"/"itte"/
// "ittte"/"itee"/"itet" instructions in firmware.bin via Capstone.
function itLetters(cond, mask){
  const letters=[];
  for(let bit=3; bit>=1; bit--){
    if((mask & ((1<<bit)-1)) === 0) break;   // this bit is the terminator
    letters.push(((mask>>>bit)&1) === (cond&1) ? "t" : "e");
  }
  return letters;
}

/* Disassemble `bytes` (Array/Uint8Array of raw memory) starting at `addr`.
 * Returns a list of {addr, size, bytes, text}; a 32-bit Thumb-2 instruction
 * that only has its first halfword in range yields one ".word" fallback line
 * for the available bytes rather than reading past the buffer.
 *
 * Tracks IT-block state across the walk: each instruction that follows an IT
 * is only conditionally executed, so its condition is fused onto the
 * mnemonic the way gdb/objdump do (e.g. "movne", "rsbls.w") -- including
 * dropping the always-flag-setting 16-bit "s" suffix, which the ISA doesn't
 * actually apply when the instruction is conditional. */
function disassembleThumb(bytes, addr, count){
  const out=[];
  let off=0;
  let itPending=[];   // queued cond-code (index into CONDN) per upcoming IT'd instruction
  while(off < bytes.length && out.length < count){
    const w1 = bytes[off] | (bytes[off+1]<<8);
    const is32 = ((w1>>>11)&0x1F)===0b11101 || ((w1>>>11)&0x1F)===0b11110 || ((w1>>>11)&0x1F)===0b11111;
    let r=null, size=2, raw;
    if(is32 && off+3<bytes.length){
      const w2 = bytes[off+2] | (bytes[off+3]<<8);
      r = decode32(w1, w2, addr+off);
      size = 4;
      raw=[bytes[off],bytes[off+1],bytes[off+2],bytes[off+3]];
      if(!r) r = {size:4, text:".word "+hex(w1,4)+" "+hex(w2,4)};
    } else if(is32){
      r = {size:2, text:".short "+hex(w1,4)+"  ; truncated 32-bit instruction"};
      size=2; raw=[bytes[off],bytes[off+1]];
    } else {
      r = decode16(w1, addr+off);
      size = 2;
      raw=[bytes[off],bytes[off+1]];
      if(!r) r = {size:2, text:".short "+hex(w1,4)};
    }
    let text = r.text;
    if(r.itCond!==undefined){
      const letters = itLetters(r.itCond, r.itMask);
      text = "it"+letters.join("")+" "+CONDN[r.itCond];
      // The printed name's own leading "t" (in "it", "itt", "itte", ...) is
      // itself the first conditional instruction's letter -- itLetters only
      // returns the letters AFTER that mandatory one, so the pending queue
      // needs it prepended, or "itte" (3 conditional instructions: t,t,e)
      // only queued 2 (found against real firmware.bin: the first of three
      // instructions after an itte came back with no condition at all, and
      // the other two were shifted one slot off).
      itPending = ["t", ...letters].map(l => l==="t" ? r.itCond : (r.itCond^1));
    } else if(itPending.length){
      const cond = CONDN[itPending.shift()];
      const sp = text.indexOf(" ");
      let mnem = sp>=0 ? text.slice(0,sp) : text;
      const rest = sp>=0 ? text.slice(sp) : "";
      let wSuffix = "";
      if(mnem.endsWith(".w")){ wSuffix=".w"; mnem=mnem.slice(0,-2); }
      // 16-bit Thumb-1 encodings that always set flags (movs/lsls/adds/...)
      // don't actually update them when executed conditionally under IT --
      // binutils/gdb drop the trailing 's' and fuse the condition onto the
      // bare root instead (e.g. "movne", not "movsne"); the cond is inserted
      // before any ".w" (e.g. "rsb.w"+ls -> "rsbls.w", not "rsb.wls").
      // Found against real firmware.bin: my old "  ; cond" trailing-comment
      // form never matched gdb/objdump's fused mnemonic convention at all.
      if(!wSuffix && mnem.endsWith("s")) mnem = mnem.slice(0,-1);
      text = mnem+cond+wSuffix+rest;
    }
    out.push({addr: addr+off, size: r.size, bytes: raw, text});
    off += r.size;
  }
  return out;
}

if(typeof module !== "undefined" && module.exports) module.exports = { disassembleThumb };
else window.disassembleThumb = disassembleThumb;

})();
