
#ifndef _ORC_ARM_H_
#define _ORC_ARM_H_

#include <orc/orc.h>

ORC_BEGIN_DECLS

#ifdef ORC_ENABLE_UNSTABLE_API

typedef enum {
  ORC_ARM_A1 = ORC_GP_REG_BASE+0,
  ORC_ARM_A2,
  ORC_ARM_A3,
  ORC_ARM_A4,
  ORC_ARM_V1,
  ORC_ARM_V2,
  ORC_ARM_V3,
  ORC_ARM_V4,
  ORC_ARM_V5,
  ORC_ARM_V6,
  ORC_ARM_V7,
  ORC_ARM_V8,
  ORC_ARM_IP,
  ORC_ARM_SP,
  ORC_ARM_LR,
  ORC_ARM_PC
} OrcArmRegister;

typedef enum {
  ORC_ARM64_R0 = ORC_GP_REG_BASE+0,
  ORC_ARM64_R1,
  ORC_ARM64_R2,
  ORC_ARM64_R3,
  ORC_ARM64_R4,
  ORC_ARM64_R5,
  ORC_ARM64_R6,
  ORC_ARM64_R7,
  ORC_ARM64_R8,
  ORC_ARM64_R9,
  ORC_ARM64_R10,
  ORC_ARM64_R11,
  ORC_ARM64_R12,
  ORC_ARM64_R13,
  ORC_ARM64_R14,
  ORC_ARM64_R15,
  ORC_ARM64_IP0,
  ORC_ARM64_IP1,
  ORC_ARM64_R18,
  ORC_ARM64_R19,
  ORC_ARM64_R20,
  ORC_ARM64_R21,
  ORC_ARM64_R22,
  ORC_ARM64_R23,
  ORC_ARM64_R24,
  ORC_ARM64_R25,
  ORC_ARM64_R26,
  ORC_ARM64_R27,
  ORC_ARM64_R28,
  ORC_ARM64_FP,
  ORC_ARM64_LR,
  ORC_ARM64_SP,
} OrcArm64Register;

typedef enum {
  ORC_ARM64_REG_32 = 32,
  ORC_ARM64_REG_64 = 64
} OrcArm64RegBits;

typedef enum {
  ORC_ARM_DP_AND = 0,
  ORC_ARM_DP_EOR,
  ORC_ARM_DP_SUB,
  ORC_ARM_DP_RSB,
  ORC_ARM_DP_ADD,
  ORC_ARM_DP_ADC,
  ORC_ARM_DP_SBC,
  ORC_ARM_DP_RSC,
  ORC_ARM_DP_TST,
  ORC_ARM_DP_TEQ,
  ORC_ARM_DP_CMP,
  ORC_ARM_DP_CMN,
  ORC_ARM_DP_ORR,
  ORC_ARM_DP_MOV,
  ORC_ARM_DP_BIC,
  ORC_ARM_DP_MVN
} OrcArmDP;

typedef enum {
  /** arithmetic */
  ORC_ARM64_DP_ADD = 0,
  ORC_ARM64_DP_CMN, /** alias of ADDS */
  ORC_ARM64_DP_SUB,
  ORC_ARM64_DP_CMP, /** alias of SUBS */
  /** logical */
  ORC_ARM64_DP_AND,
  ORC_ARM64_DP_ORR,
  ORC_ARM64_DP_EOR,
  ORC_ARM64_DP_TST, /** alias of ANDS */
  /** bitfield */
  ORC_ARM64_DP_SBFM,
  ORC_ARM64_DP_BFM,
  ORC_ARM64_DP_UBFM,
  /** extract */
  ORC_ARM64_DP_EXTR
} OrcArm64DP;

typedef enum {
  ORC_ARM64_MEM_STR = 0,
  ORC_ARM64_MEM_LDR
} OrcArm64Mem;

typedef enum {
  ORC_ARM64_TYPE_IMM = 0,
  ORC_ARM64_TYPE_REG,
  ORC_ARM64_TYPE_EXT
} OrcArm64Type;

typedef enum {
  ORC_ARM64_EXTEND_UXTB,
  ORC_ARM64_EXTEND_UXTH,
  ORC_ARM64_EXTEND_UXTW,
  ORC_ARM64_EXTEND_UXTX,
  ORC_ARM64_EXTEND_SXTB,
  ORC_ARM64_EXTEND_SXTH,
  ORC_ARM64_EXTEND_SXTW,
  ORC_ARM64_EXTEND_SXTX,
} OrcArm64Extend;

typedef enum {
  ORC_ARM_COND_EQ = 0,
  ORC_ARM_COND_NE,
  ORC_ARM_COND_CS,
  ORC_ARM_COND_CC,
  ORC_ARM_COND_MI,
  ORC_ARM_COND_PL,
  ORC_ARM_COND_VS,
  ORC_ARM_COND_VC,
  ORC_ARM_COND_HI,
  ORC_ARM_COND_LS,
  ORC_ARM_COND_GE,
  ORC_ARM_COND_LT,
  ORC_ARM_COND_GT,
  ORC_ARM_COND_LE,
  ORC_ARM_COND_AL,
} OrcArmCond;

typedef enum {
  ORC_ARM_LSL,
  ORC_ARM_LSR,
  ORC_ARM_ASR,
  ORC_ARM_ROR
} OrcArmShift;

ORC_API unsigned long orc_arm_get_cpu_flags (void);

ORC_API void orc_arm_emit (OrcCompiler *compiler, orc_uint32 insn);
ORC_API void orc_arm_emit_bx_lr (OrcCompiler *compiler);
ORC_API const char * orc_arm_reg_name (int reg);
ORC_API const char * orc_arm_cond_name (OrcArmCond cond);
ORC_API void orc_arm_emit_load_imm (OrcCompiler *compiler, int dest, int imm);

ORC_API void orc_arm_emit_add (OrcCompiler *compiler, int dest, int src1, int src2);
ORC_API void orc_arm_emit_sub (OrcCompiler *compiler, int dest, int src1, int src2);
ORC_API void orc_arm_emit_add_imm (OrcCompiler *compiler, int dest, int src1, int value);
ORC_API void orc_arm_emit_and_imm (OrcCompiler *compiler, int dest, int src1, int value);
ORC_API void orc_arm_emit_sub_imm (OrcCompiler *compiler, int dest, int src1, int value, int record);
ORC_API void orc_arm_emit_asr_imm (OrcCompiler *compiler, int dest, int src1, int value);
ORC_API void orc_arm_emit_lsl_imm (OrcCompiler *compiler, int dest, int src1, int value);
ORC_API void orc_arm_emit_cmp_imm (OrcCompiler *compiler, int src1, int value);
ORC_API void orc_arm_emit_cmp (OrcCompiler *compiler, int src1, int src2);
ORC_API void orc_arm_emit_mov (OrcCompiler *compiler, int dest, int src);

ORC_API void orc_arm_emit_align (OrcCompiler *compiler, int align_shift);
ORC_API void orc_arm_emit_label (OrcCompiler *compiler, int label);
ORC_API void orc_arm_emit_push (OrcCompiler *compiler, int regs, orc_uint32 vregs);
ORC_API void orc_arm_emit_pop (OrcCompiler *compiler, int regs, orc_uint32 vregs);
ORC_API void orc_arm_emit_branch (OrcCompiler *compiler, int cond, int label);
ORC_API void orc_arm_emit_data (OrcCompiler *compiler, orc_uint32 data);

ORC_API void orc_arm_loadb (OrcCompiler *compiler, int dest, int src1, int offset);
ORC_API void orc_arm_storeb (OrcCompiler *compiler, int dest, int offset, int src1);
ORC_API void orc_arm_loadw (OrcCompiler *compiler, int dest, int src1, int offset);
ORC_API void orc_arm_storew (OrcCompiler *compiler, int dest, int offset, int src1);
ORC_API void orc_arm_loadl (OrcCompiler *compiler, int dest, int src1, int offset);
ORC_API void orc_arm_storel (OrcCompiler *compiler, int dest, int offset, int src1);

ORC_API void orc_arm_emit_load_reg (OrcCompiler *compiler, int dest, int src1, int offset);
ORC_API void orc_arm_emit_store_reg (OrcCompiler *compiler, int src, int dest, int offset);

ORC_API void orc_arm_add_fixup (OrcCompiler *compiler, int label, int type);
ORC_API void orc_arm_do_fixups (OrcCompiler *compiler);

ORC_API void orc_arm_emit_dp (OrcCompiler *p, int type, OrcArmCond cond, OrcArmDP opcode,
    int S, int Rd, int Rn, int Rm, int shift, orc_uint32 val);
ORC_API void orc_arm_emit_par (OrcCompiler *p, int op, int mode, OrcArmCond cond,
    int Rd, int Rn, int Rm);
ORC_API void orc_arm_emit_xt (OrcCompiler *p, int op, OrcArmCond cond,
    int Rd, int Rn, int Rm, int r8);
ORC_API void orc_arm_emit_pkh (OrcCompiler *p, int op, OrcArmCond cond,
    int Rd, int Rn, int Rm, int sh);
ORC_API void orc_arm_emit_sat (OrcCompiler *p, int op, OrcArmCond cond,
    int Rd, int sat, int Rm, int sh, int asr);
ORC_API void orc_arm_emit_rv (OrcCompiler *p, int op, OrcArmCond cond,
    int Rd, int Rm);
ORC_API void orc_arm_emit_nop (OrcCompiler *compiler);

ORC_API void orc_arm_flush_cache (OrcCode *code);

/* ALL cpus */
/* data procesing instructions */
/* <op>{<cond>}{s} {<Rd>}, <Rn>, #imm */
#define orc_arm_emit_and_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_AND,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_eor_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_EOR,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_sub_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_SUB,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_rsb_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_RSB,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_add_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_ADD,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_adc_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_ADC,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_sbc_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_SBC,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_rsc_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_RSC,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_tst_i(p,cond,Rn,imm)             orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_TST,1, 0,Rn,0,0,imm)
#define orc_arm_emit_teq_i(p,cond,Rn,imm)             orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_TEQ,1, 0,Rn,0,0,imm)
#define orc_arm_emit_cmp_i(p,cond,Rn,imm)             orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_CMP,1, 0,Rn,0,0,imm)
#define orc_arm_emit_cmn_i(p,cond,Rn,imm)             orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_CMN,1, 0,Rn,0,0,imm)
#define orc_arm_emit_orr_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_ORR,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_mov_i(p,cond,S,Rd,imm)           orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_MOV,S,Rd, 0,0,0,imm)
#define orc_arm_emit_bic_i(p,cond,S,Rd,Rn,imm)        orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_BIC,S,Rd,Rn,0,0,imm)
#define orc_arm_emit_mvn_i(p,cond,S,Rd,imm)           orc_arm_emit_dp(p,0,cond,ORC_ARM_DP_MVN,S,Rd, 0,0,0,imm)

/* <op>{<cond>}{s} {<Rd>}, <Rn>, <Rm> */
#define orc_arm_emit_and_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_AND,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_eor_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_EOR,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_sub_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_SUB,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_rsb_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_RSB,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_add_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_ADD,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_adc_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_ADC,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_sbc_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_SBC,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_rsc_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_RSC,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_tst_r(p,cond,Rn,Rm)              orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_TST,1, 0,Rn,Rm,0,0)
#define orc_arm_emit_teq_r(p,cond,Rn,Rm)              orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_TEQ,1, 0,Rn,Rm,0,0)
#define orc_arm_emit_cmp_r(p,cond,Rn,Rm)              orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_CMP,1, 0,Rn,Rm,0,0)
#define orc_arm_emit_cmn_r(p,cond,Rn,Rm)              orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_CMN,1, 0,Rn,Rm,0,0)
#define orc_arm_emit_orr_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_ORR,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_mov_r(p,cond,S,Rd,Rm)            orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_MOV,S,Rd, 0,Rm,0,0)
#define orc_arm_emit_bic_r(p,cond,S,Rd,Rn,Rm)         orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_BIC,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_mvn_r(p,cond,S,Rd,Rm)            orc_arm_emit_dp(p,1,cond,ORC_ARM_DP_MVN,S,Rd, 0,Rm,0,0)

/* <op>{<cond>}{s} {<Rd>}, <Rn>, <Rm>, [LSL|LSR|ASR] #imm */
#define orc_arm_emit_and_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_AND,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_eor_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_EOR,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_sub_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_SUB,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_rsb_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_RSB,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_add_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_ADD,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_adc_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_ADC,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_sbc_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_SBC,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_rsc_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_RSC,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_tst_rsi(p,cond,Rn,Rm,sh,im)      orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_TST,1, 0,Rn,Rm,sh,im)
#define orc_arm_emit_teq_rsi(p,cond,Rn,Rm,sh,im)      orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_TEQ,1, 0,Rn,Rm,sh,im)
#define orc_arm_emit_cmp_rsi(p,cond,Rn,Rm,sh,im)      orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_CMP,1, 0,Rn,Rm,sh,im)
#define orc_arm_emit_cmn_rsi(p,cond,Rn,Rm,sh,im)      orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_CMN,1, 0,Rn,Rm,sh,im)
#define orc_arm_emit_orr_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_ORR,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_mov_rsi(p,cond,S,Rd,Rm,sh,im)    orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_MOV,S,Rd, 0,Rm,sh,im)
#define orc_arm_emit_bic_rsi(p,cond,S,Rd,Rn,Rm,sh,im) orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_BIC,S,Rd,Rn,Rm,sh,im)
#define orc_arm_emit_mvn_rsi(p,cond,S,Rd,Rm,sh,im)    orc_arm_emit_dp(p,2,cond,ORC_ARM_DP_MVN,S,Rd, 0,Rm,sh,im)

/* <op>{<cond>}{s} {<Rd>}, <Rn>, <Rm>, [LSL|LSR|ASR] <Rs> */
#define orc_arm_emit_and_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_AND,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_eor_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_EOR,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_sub_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_SUB,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_rsb_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_RSB,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_add_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_ADD,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_adc_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_ADC,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_sbc_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_SBC,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_rsc_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_RSC,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_tst_rsr(p,cond,Rn,Rm,sh,Rs)      orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_TST,1, 0,Rn,Rm,sh,Rs)
#define orc_arm_emit_teq_rsr(p,cond,Rn,Rm,sh,Rs)      orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_TEQ,1, 0,Rn,Rm,sh,Rs)
#define orc_arm_emit_cmp_rsr(p,cond,Rn,Rm,sh,Rs)      orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_CMP,1, 0,Rn,Rm,sh,Rs)
#define orc_arm_emit_cmn_rsr(p,cond,Rn,Rm,sh,Rs)      orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_CMN,1, 0,Rn,Rm,sh,Rs)
#define orc_arm_emit_orr_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_ORR,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_mov_rsr(p,cond,S,Rd,Rm,sh,Rs)    orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_MOV,S,Rd, 0,Rm,sh,Rs)
#define orc_arm_emit_bic_rsr(p,cond,S,Rd,Rn,Rm,sh,Rs) orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_BIC,S,Rd,Rn,Rm,sh,Rs)
#define orc_arm_emit_mvn_rsr(p,cond,S,Rd,Rm,sh,Rs)    orc_arm_emit_dp(p,3,cond,ORC_ARM_DP_MVN,S,Rd, 0,Rm,sh,Rs)

/* <op>{<cond>}{s} {<Rd>,} <Rn>, <Rm>, RRX */
#define orc_arm_emit_and_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_AND,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_eor_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_EOR,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_sub_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_SUB,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_rsb_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_RSB,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_add_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_ADD,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_adc_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_ADC,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_sbc_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_SBC,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_rsc_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_RSC,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_tst_rrx(p,cond,Rn,Rm)            orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_TST,1, 0,Rn,Rm,0,0)
#define orc_arm_emit_teq_rrx(p,cond,Rn,Rm)            orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_TEQ,1, 0,Rn,Rm,0,0)
#define orc_arm_emit_cmp_rrx(p,cond,Rn,Rm)            orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_CMP,1, 0,Rn,Rm,0,0)
#define orc_arm_emit_cmn_rrx(p,cond,Rn,Rm)            orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_CMN,1, 0,Rn,Rm,0,0)
#define orc_arm_emit_orr_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_ORR,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_mov_rrx(p,cond,S,Rd,Rm)          orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_MOV,S,Rd, 0,Rm,0,0)
#define orc_arm_emit_bic_rrx(p,cond,S,Rd,Rn,Rm)       orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_BIC,S,Rd,Rn,Rm,0,0)
#define orc_arm_emit_mvn_rrx(p,cond,S,Rd,Rm)          orc_arm_emit_dp(p,4,cond,ORC_ARM_DP_MVN,S,Rd, 0,Rm,0,0)

/* parallel instructions */
#define orc_arm_emit_sadd16(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,0,0,cond,Rd,Rn,Rm)
#define orc_arm_emit_qadd16(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,0,1,cond,Rd,Rn,Rm)
#define orc_arm_emit_shadd16(p,cond,Rd,Rn,Rm)         orc_arm_emit_par(p,0,2,cond,Rd,Rn,Rm)
#define orc_arm_emit_uadd16(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,0,3,cond,Rd,Rn,Rm)
#define orc_arm_emit_uqadd16(p,cond,Rd,Rn,Rm)         orc_arm_emit_par(p,0,4,cond,Rd,Rn,Rm)
#define orc_arm_emit_uhadd16(p,cond,Rd,Rn,Rm)         orc_arm_emit_par(p,0,5,cond,Rd,Rn,Rm)

#define orc_arm_emit_saddsubx(p,cond,Rd,Rn,Rm)        orc_arm_emit_par(p,1,0,cond,Rd,Rn,Rm)
#define orc_arm_emit_qaddsubx(p,cond,Rd,Rn,Rm)        orc_arm_emit_par(p,1,1,cond,Rd,Rn,Rm)
#define orc_arm_emit_shaddsubx(p,cond,Rd,Rn,Rm)       orc_arm_emit_par(p,1,2,cond,Rd,Rn,Rm)
#define orc_arm_emit_uaddsubx(p,cond,Rd,Rn,Rm)        orc_arm_emit_par(p,1,3,cond,Rd,Rn,Rm)
#define orc_arm_emit_uqaddsubx(p,cond,Rd,Rn,Rm)       orc_arm_emit_par(p,1,4,cond,Rd,Rn,Rm)
#define orc_arm_emit_uhaddsubx(p,cond,Rd,Rn,Rm)       orc_arm_emit_par(p,1,5,cond,Rd,Rn,Rm)

#define orc_arm_emit_ssubaddx(p,cond,Rd,Rn,Rm)        orc_arm_emit_par(p,2,0,cond,Rd,Rn,Rm)
#define orc_arm_emit_qsubaddx(p,cond,Rd,Rn,Rm)        orc_arm_emit_par(p,2,1,cond,Rd,Rn,Rm)
#define orc_arm_emit_shsubaddx(p,cond,Rd,Rn,Rm)       orc_arm_emit_par(p,2,2,cond,Rd,Rn,Rm)
#define orc_arm_emit_usubaddx(p,cond,Rd,Rn,Rm)        orc_arm_emit_par(p,2,3,cond,Rd,Rn,Rm)
#define orc_arm_emit_uqsubaddx(p,cond,Rd,Rn,Rm)       orc_arm_emit_par(p,2,4,cond,Rd,Rn,Rm)
#define orc_arm_emit_uhsubaddx(p,cond,Rd,Rn,Rm)       orc_arm_emit_par(p,2,5,cond,Rd,Rn,Rm)

#define orc_arm_emit_ssub16(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,3,0,cond,Rd,Rn,Rm)
#define orc_arm_emit_qsub16(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,3,1,cond,Rd,Rn,Rm)
#define orc_arm_emit_shsub16(p,cond,Rd,Rn,Rm)         orc_arm_emit_par(p,3,2,cond,Rd,Rn,Rm)
#define orc_arm_emit_usub16(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,3,3,cond,Rd,Rn,Rm)
#define orc_arm_emit_uqsub16(p,cond,Rd,Rn,Rm)         orc_arm_emit_par(p,3,4,cond,Rd,Rn,Rm)
#define orc_arm_emit_uhsub16(p,cond,Rd,Rn,Rm)         orc_arm_emit_par(p,3,5,cond,Rd,Rn,Rm)

#define orc_arm_emit_sadd8(p,cond,Rd,Rn,Rm)           orc_arm_emit_par(p,4,0,cond,Rd,Rn,Rm)
#define orc_arm_emit_qadd8(p,cond,Rd,Rn,Rm)           orc_arm_emit_par(p,4,1,cond,Rd,Rn,Rm)
#define orc_arm_emit_shadd8(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,4,2,cond,Rd,Rn,Rm)
#define orc_arm_emit_uadd8(p,cond,Rd,Rn,Rm)           orc_arm_emit_par(p,4,3,cond,Rd,Rn,Rm)
#define orc_arm_emit_uqadd8(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,4,4,cond,Rd,Rn,Rm)
#define orc_arm_emit_uhadd8(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,4,5,cond,Rd,Rn,Rm)

#define orc_arm_emit_ssub8(p,cond,Rd,Rn,Rm)           orc_arm_emit_par(p,5,0,cond,Rd,Rn,Rm)
#define orc_arm_emit_qsub8(p,cond,Rd,Rn,Rm)           orc_arm_emit_par(p,5,1,cond,Rd,Rn,Rm)
#define orc_arm_emit_shsub8(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,5,2,cond,Rd,Rn,Rm)
#define orc_arm_emit_usub8(p,cond,Rd,Rn,Rm)           orc_arm_emit_par(p,5,3,cond,Rd,Rn,Rm)
#define orc_arm_emit_uqsub8(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,5,4,cond,Rd,Rn,Rm)
#define orc_arm_emit_uhsub8(p,cond,Rd,Rn,Rm)          orc_arm_emit_par(p,5,5,cond,Rd,Rn,Rm)

/* selection */
#define orc_arm_emit_sel(p,cond,Rd,Rn,Rm)             orc_arm_emit_par(p,6,6,cond,Rd,Rn,Rm)

/* saturating add */
#define orc_arm_emit_qadd(p,cond,Rd,Rn,Rm)            orc_arm_emit_par(p,7,7, cond,Rd,Rn,Rm)
#define orc_arm_emit_qsub(p,cond,Rd,Rn,Rm)            orc_arm_emit_par(p,8,8, cond,Rd,Rn,Rm)
#define orc_arm_emit_qdadd(p,cond,Rd,Rn,Rm)           orc_arm_emit_par(p,7,9, cond,Rd,Rn,Rm)
#define orc_arm_emit_qdsub(p,cond,Rd,Rn,Rm)           orc_arm_emit_par(p,8,10,cond,Rd,Rn,Rm)

/* extend instructions */
/* with ROR #r8, r8 should be a multiple of 8 */
#define orc_arm_emit_sxtb16_r8(p,cond,Rd,Rm,r8)       orc_arm_emit_xt(p,0, cond,Rd,15,Rm,r8)
#define orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,r8)         orc_arm_emit_xt(p,1, cond,Rd,15,Rm,r8)
#define orc_arm_emit_sxth_r8(p,cond,Rd,Rm,r8)         orc_arm_emit_xt(p,2, cond,Rd,15,Rm,r8)
#define orc_arm_emit_uxtb16_r8(p,cond,Rd,Rm,r8)       orc_arm_emit_xt(p,3, cond,Rd,15,Rm,r8)
#define orc_arm_emit_uxtb_r8(p,cond,Rd,Rm,r8)         orc_arm_emit_xt(p,4, cond,Rd,15,Rm,r8)
#define orc_arm_emit_uxth_r8(p,cond,Rd,Rm,r8)         orc_arm_emit_xt(p,5, cond,Rd,15,Rm,r8)
#define orc_arm_emit_sxtab16_r8(p,cond,Rd,Rn,Rm,r8)   orc_arm_emit_xt(p,6, cond,Rd,Rn,Rm,r8)
#define orc_arm_emit_sxtab_r8(p,cond,Rd,Rn,Rm,r8)     orc_arm_emit_xt(p,7, cond,Rd,Rn,Rm,r8)
#define orc_arm_emit_sxtah_r8(p,cond,Rd,Rn,Rm,r8)     orc_arm_emit_xt(p,8, cond,Rd,Rn,Rm,r8)
#define orc_arm_emit_uxtab16_r8(p,cond,Rd,Rn,Rm,r8)   orc_arm_emit_xt(p,9, cond,Rd,Rn,Rm,r8)
#define orc_arm_emit_uxtab_r8(p,cond,Rd,Rn,Rm,r8)     orc_arm_emit_xt(p,10,cond,Rd,Rn,Rm,r8)
#define orc_arm_emit_uxtah_r8(p,cond,Rd,Rn,Rm,r8)     orc_arm_emit_xt(p,11,cond,Rd,Rn,Rm,r8)
/* with out rotate */
#define orc_arm_emit_sxtb16(p,cond,Rd,Rm)             orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_sxtb(p,cond,Rd,Rm)               orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_sxth(p,cond,Rd,Rm)               orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_uxtb16(p,cond,Rd,Rm)             orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_uxtb(p,cond,Rd,Rm)               orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_uxth(p,cond,Rd,Rm)               orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_sxtab16(p,cond,Rd,Rn,Rm)         orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_sxtab(p,cond,Rd,Rn,Rm)           orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_sxtah(p,cond,Rd,Rn,Rm)           orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_uxtab16(p,cond,Rd,Rn,Rm)         orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_uxtab(p,cond,Rd,Rn,Rm)           orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)
#define orc_arm_emit_uxtah(p,cond,Rd,Rn,Rm)           orc_arm_emit_sxtb_r8(p,cond,Rd,Rm,0)

/* misc instructions */

/* packing */
#define orc_arm_emit_pkhbt(p,cond,Rd,Rn,Rm)           orc_arm_emit_pkh(p,0,cond,Rd,Rn,Rm,0)
#define orc_arm_emit_pkhtb(p,cond,Rd,Rn,Rm)           orc_arm_emit_pkh(p,1,cond,Rd,Rn,Rm,0)
/* with  [LSL|ASR] #imm */
#define orc_arm_emit_pkhbt_s(p,cond,Rd,Rn,Rm,lsl)     orc_arm_emit_pkh(p,0,cond,Rd,Rn,Rm,lsl)
#define orc_arm_emit_pkhtb_s(p,cond,Rd,Rn,Rm,asr)     orc_arm_emit_pkh(p,1,cond,Rd,Rn,Rm,asr)

/* saturation */
#define orc_arm_emit_ssat(p,cond,Rd,sat,Rm)           orc_arm_emit_sat(p,0,cond,Rd,sat,Rm,0, 0)
#define orc_arm_emit_usat(p,cond,Rd,sat,Rm)           orc_arm_emit_sat(p,1,cond,Rd,sat,Rm,0, 0)
#define orc_arm_emit_ssat_lsl(p,cond,Rd,sat,Rm,sh)    orc_arm_emit_sat(p,0,cond,Rd,sat,Rm,sh,0)
#define orc_arm_emit_usat_lsl(p,cond,Rd,sat,Rm,sh)    orc_arm_emit_sat(p,1,cond,Rd,sat,Rm,sh,0)
#define orc_arm_emit_ssat_asr(p,cond,Rd,sat,Rm,sh)    orc_arm_emit_sat(p,0,cond,Rd,sat,Rm,sh,1)
#define orc_arm_emit_usat_asr(p,cond,Rd,sat,Rm,sh)    orc_arm_emit_sat(p,1,cond,Rd,sat,Rm,sh,1)
#define orc_arm_emit_ssat16(p,cond,Rd,sat,Rm)         orc_arm_emit_sat(p,2,cond,Rd,sat,Rm,0, 0)
#define orc_arm_emit_usat16(p,cond,Rd,sat,Rm)         orc_arm_emit_sat(p,3,cond,Rd,sat,Rm,0, 0)

/* reversing */
#define orc_arm_emit_rev(p,cond,Rd,Rm)                orc_arm_emit_rv (p,0,cond,Rd,Rm)
#define orc_arm_emit_rev16(p,cond,Rd,Rm)              orc_arm_emit_rv (p,1,cond,Rd,Rm)

/** AArch64 */

ORC_API const char * orc_arm64_reg_name (int reg, OrcArm64RegBits bits);
ORC_API void orc_arm64_emit_am (OrcCompiler *p, OrcArm64RegBits bits, OrcArm64DP opcode,
    OrcArm64Type type, int opt, int Rd, int Rn, int Rm, orc_uint64 val);
ORC_API void orc_arm64_emit_lg (OrcCompiler *p, OrcArm64RegBits bits, OrcArm64DP opcode,
    OrcArm64Type type, int opt, int Rd, int Rn, int Rm, orc_uint64 val);
ORC_API void orc_arm64_emit_bfm (OrcCompiler *p, OrcArm64RegBits bits, OrcArm64DP opcode,
    int Rn, int Rd, orc_uint32 immr, orc_uint32 imms);
ORC_API void orc_arm64_emit_extr (OrcCompiler *p, OrcArm64RegBits bits,
    int Rd, int Rn, int Rm, orc_uint32 imm);
ORC_API void orc_arm64_emit_mem (OrcCompiler *p, OrcArm64RegBits bits, OrcArm64Mem opcode,
    OrcArm64Type type, int opt, int Rt, int Rn, int Rm, orc_uint64 val);
/** @todo add arm64-specific helper functions if needed */

/** ORC_ARM64_DP_LSL/ASR/ASR/ROR */
/** ORC_ARM64_TYPE_IMM; aliases of ORC_ARM64_DP_SBFM,UBFM,EXTR */
#define orc_arm64_emit_lsl_imm(p,bits,Rd,Rn,imm) \
  orc_arm64_emit_bfm(p,bits,ORC_ARM64_DP_UBFM,Rd,Rn,imm,imm-1)
#define orc_arm64_emit_lsr_imm(p,bits,Rd,Rn,imm) \
  orc_arm64_emit_bfm(p,bits,ORC_ARM64_DP_UBFM,Rd,Rn,imm,0x1f)
#define orc_arm64_emit_asr_imm(p,bits,Rd,Rn,imm) \
  orc_arm64_emit_bfm(p,bits,ORC_ARM64_DP_ORC_ARM64_DP_SBFM,Rd,Rn,imm,0x1f)
#define orc_arm64_emit_ror_imm(p,bits,Rd,Rn,imm) \
  orc_arm64_emit_extr(p,bits,Rd,Rn,Rn,imm)

/** memory access instructions */

/** ORC_ARM64_MEM_STR */
/** ORC_ARM64_TYPE_REG */
#define orc_arm64_emit_store_reg(p,b,Rt,Rn,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_STR,ORC_ARM64_TYPE_REG,0,Rt,Rn,0,imm)
#define orc_arm64_emit_store_pre(p,b,Rt,Rn,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_STR,ORC_ARM64_TYPE_REG,1,Rt,Rn,0,imm)
#define orc_arm64_emit_store_post(p,b,Rt,Rn,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_STR,ORC_ARM64_TYPE_REG,2,Rt,Rn,0,imm)
/** ORC_ARM64_TYPE_EXT */
#define orc_arm64_emit_store_uxtw(p,b,Rt,Rn,Rm,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_STR,ORC_ARM64_TYPE_EXT,ORC_ARM64_EXTEND_UXTW,Rt,Rn,Rm,imm)
#define orc_arm64_emit_store_lsl(p,b,Rt,Rn,Rm,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_STR,ORC_ARM64_TYPE_EXT,ORC_ARM64_EXTEND_UXTX,Rt,Rn,Rm,imm)
#define orc_arm64_emit_store_sxtw(p,b,Rt,Rn,Rm,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_STR,ORC_ARM64_TYPE_EXT,ORC_ARM64_EXTEND_SXTW,Rt,Rn,Rm,imm)
#define orc_arm64_emit_store_sxtx(p,b,Rt,Rn,Rm,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_STR,ORC_ARM64_TYPE_EXT,ORC_ARM64_EXTEND_SXTX,Rt,Rn,Rm,imm)

/** ORC_ARM64_MEM_LDR */
/** ORC_ARM64_TYPE_IMM */
#define orc_arm64_emit_load_imm(p,b,Rt,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_IMM,0,Rt,0,0,imm)
#define orc_arm64_emit_load_label(p,b,Rt,label) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_IMM,label,Rt,0,0,0)
/** ORC_ARM64_TYPE_REG */
#define orc_arm64_emit_load_reg(p,b,Rt,Rn,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_REG,0,Rt,Rn,0,imm)
#define orc_arm64_emit_load_pre(p,b,Rt,Rn,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_REG,1,Rt,Rn,0,imm)
#define orc_arm64_emit_load_post(p,b,Rt,Rn,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_REG,2,Rt,Rn,0,imm)
/** ORC_ARM64_TYPE_EXT */
#define orc_arm64_emit_load_uxtw(p,b,Rt,Rn,Rm,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_EXT,ORC_ARM64_EXTEND_UXTW,Rt,Rn,Rm,imm)
#define orc_arm64_emit_load_lsl(p,b,Rt,Rn,Rm,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_EXT,ORC_ARM64_EXTEND_UXTX,Rt,Rn,Rm,imm)
#define orc_arm64_emit_load_sxtw(p,b,Rt,Rn,Rm,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_EXT,ORC_ARM64_EXTEND_SXTW,Rt,Rn,Rm,imm)
#define orc_arm64_emit_load_sxtx(p,b,Rt,Rn,Rm,imm) \
  orc_arm64_emit_mem(p,b,ORC_ARM64_MEM_LDR,ORC_ARM64_TYPE_EXT,ORC_ARM64_EXTEND_SXTX,Rt,Rn,Rm,imm)

#endif

ORC_END_DECLS

#endif

