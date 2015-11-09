/*
 *
 * Copyright 2015 - mrmacete <mrmacete@protonmail.ch>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "bpf.h"


#define EMIT_CJMP(op, addr, f) \
                (op)->type =  R_ANAL_OP_TYPE_CJMP;\
                (op)->jump = (addr) + 8 + (f)->jt * 8;\
                (op)->fail = (addr) + 8 + (f)->jf * 8;

#define NEW_SRC_DST(op) \
                (op)->src[0] = r_anal_value_new ();\
                (op)->dst = r_anal_value_new ();

#define SET_REG_SRC_DST(op, _src, _dst) \
                NEW_SRC_DST((op));\
                (op)->src[0]->reg = r_reg_get (anal->reg, (_src), R_REG_TYPE_GPR);\
                (op)->dst->reg = r_reg_get (anal->reg, (_dst), R_REG_TYPE_GPR);\

#define SET_REG_DST_IMM(op, _dst, _imm) \
                NEW_SRC_DST((op));\
                (op)->dst->reg = r_reg_get (anal->reg, (_dst), R_REG_TYPE_GPR);\
                (op)->src[0]->imm = (_imm);\

#define SET_A_SRC(op) \
                (op)->src[0] = r_anal_value_new ();\
                (op)->src[0]->reg = r_reg_get (anal->reg, "A", R_REG_TYPE_GPR);


#define INSIDE_M(k) ((k) >= 0 && (k) <= 16)

#define esilprintf(op, fmt, arg...) r_strbuf_setf (&(op)->esil, (fmt), ##arg)

static const char* M[] = {
    "M[0]",
    "M[1]",
    "M[2]",
    "M[3]",
    "M[4]",
    "M[5]",
    "M[6]",
    "M[7]",
    "M[8]",
    "M[9]",
    "M[10]",
    "M[11]",
    "M[12]",
    "M[13]",
    "M[14]",
    "M[15]"
};

static int bpf_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
    RBpfSockFilter * f = (RBpfSockFilter*) data;
    memset (op, '\0', sizeof (RAnalOp));
    op->jump = UT64_MAX;
    op->fail = UT64_MAX;
    op->ptr = op->val = UT64_MAX;
    op->type = R_ANAL_OP_TYPE_UNK;
    op->size = 8;
    op->addr = addr;

    r_strbuf_init (&op->esil);


    switch (f->code) {
    case BPF_RET | BPF_K:
    case BPF_RET | BPF_A:
    case BPF_RET | BPF_X:
        op->type = R_ANAL_OP_TYPE_RET;
        break;
    case BPF_MISC_TAX:
        op->type = R_ANAL_OP_TYPE_MOV;
        SET_REG_SRC_DST (op, "A", "X");
        esilprintf (op, "A,X,=");
        break;
    case BPF_MISC_TXA:
        op->type = R_ANAL_OP_TYPE_MOV;
        SET_REG_SRC_DST (op, "X", "A");
        esilprintf (op, "X,A,=");
        break;
    case BPF_ST:
        op->type = R_ANAL_OP_TYPE_MOV;
        break;
    case BPF_STX:
        op->type = R_ANAL_OP_TYPE_MOV;
        break;
    case BPF_LD_W | BPF_ABS:
        op->type = R_ANAL_OP_TYPE_LOAD;
        //op = r_bpf_op_table[BPF_LD_W];
        //fmt = "[%d]";
        break;
    case BPF_LD_H | BPF_ABS:
        op->type = R_ANAL_OP_TYPE_LOAD;
        //op = r_bpf_op_table[BPF_LD_H];
        //fmt = "[%d]";
        break;
    case BPF_LD_B | BPF_ABS:
        op->type = R_ANAL_OP_TYPE_LOAD;
        //op = r_bpf_op_table[BPF_LD_B];
        //fmt = "[%d]";
        break;
    case BPF_LD_W | BPF_IND:
        op->type = R_ANAL_OP_TYPE_LOAD;
        //op = r_bpf_op_table[BPF_LD_W];
        //fmt = "[x+%d]";
        break;
    case BPF_LD_H | BPF_IND:
        op->type = R_ANAL_OP_TYPE_LOAD;
        //op = r_bpf_op_table[BPF_LD_H];
        //fmt = "[x+%d]";
        break;
    case BPF_LD_B | BPF_IND:
        op->type = R_ANAL_OP_TYPE_LOAD;
        //op = r_bpf_op_table[BPF_LD_B];
        //fmt = "[x+%d]";
        break;
    case BPF_LD | BPF_IMM:
        op->type = R_ANAL_OP_TYPE_MOV;
        op->val = f->k;
        SET_REG_DST_IMM (op, "A", f->k);
        esilprintf (op, "0x%08"PFMT64x",A,=", f->k);
        break;
    case BPF_LDX | BPF_IMM:
        op->type = R_ANAL_OP_TYPE_MOV;
        op->val = f->k;
        SET_REG_DST_IMM (op, "X", f->k);
        esilprintf (op, "0x%08"PFMT64x",X,=", f->k);
        break;
    case BPF_LDX_B | BPF_MSH:
        op->type = R_ANAL_OP_TYPE_LOAD;
        break;
    case BPF_LD | BPF_MEM:
        op->type = R_ANAL_OP_TYPE_MOV;
        if (INSIDE_M (f->k)) {
            SET_REG_SRC_DST (op, M[f->k], "A");
            esilprintf (op, "M[%"PFMT64d"],A,=", f->k);
        } else {
            op->type = R_ANAL_OP_TYPE_ILL;
        }
        break;
    case BPF_LDX | BPF_MEM:
        op->type = R_ANAL_OP_TYPE_MOV;
        if (INSIDE_M (f->k)) {
            SET_REG_SRC_DST (op, M[f->k], "X");
            esilprintf (op, "M[%"PFMT64d"],X,=", f->k);
        } else {
            op->type = R_ANAL_OP_TYPE_ILL;
        }
        break;
    case BPF_JMP_JA:
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = addr + 8 + f->k * 8;
        esilprintf (op, "%"PFMT64d",pc,=", op->jump);

        break;
    case BPF_JMP_JGT | BPF_X:
    case BPF_JMP_JGT | BPF_K:
        EMIT_CJMP (op, addr, f);
        op->cond = R_ANAL_COND_GT;
        op->val = f->k;
        esilprintf (op, "%"PFMT64d",A,>,?{,%"PFMT64d",pc,=,BREAK,},%"PFMT64d",pc,=",
                    op->val, op->jump, op->fail );
        break;
    case BPF_JMP_JGE | BPF_X:
    case BPF_JMP_JGE | BPF_K:
        EMIT_CJMP (op, addr, f);
        op->cond = R_ANAL_COND_GE;
        op->val = f->k;
        esilprintf (op, "%"PFMT64d",A,>=,?{,%"PFMT64d",pc,=,BREAK,},%"PFMT64d",pc,=",
                    op->val, op->jump, op->fail );
        break;
    case BPF_JMP_JEQ | BPF_X:
    case BPF_JMP_JEQ | BPF_K:
        EMIT_CJMP (op, addr, f);
        op->cond = R_ANAL_COND_EQ;
        op->val = f->k;
        esilprintf (op, "%"PFMT64d",A,==,?{,%"PFMT64d",pc,=,BREAK,},%"PFMT64d",pc,=",
                    op->val, op->jump, op->fail );
        break;
    case BPF_JMP_JSET | BPF_X:
    case BPF_JMP_JSET | BPF_K:
        EMIT_CJMP (op, addr, f);
        op->val = f->k;
        esilprintf (op, "%"PFMT64d",A,&,?{,%"PFMT64d",pc,=,BREAK,},%"PFMT64d",pc,=",
                    op->val, op->jump, op->fail );
        break;
    case BPF_ALU_NEG:
        op->type = R_ANAL_OP_TYPE_NOT;
        esilprintf (op, "A,A,~=");
        SET_REG_SRC_DST (op, "A", "A");
        break;
    case BPF_ALU_LSH | BPF_X:
    case BPF_ALU_LSH | BPF_K:
        op->type = R_ANAL_OP_TYPE_SHL;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,<<=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,<<=");
        }
        break;
    case BPF_ALU_RSH | BPF_X:
    case BPF_ALU_RSH | BPF_K:
        op->type = R_ANAL_OP_TYPE_SHR;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,>>=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,>>=");
        }
        break;
    case BPF_ALU_ADD | BPF_X:
    case BPF_ALU_ADD | BPF_K:
        op->type = R_ANAL_OP_TYPE_ADD;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A+=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,+=");
        }
        break;
    case BPF_ALU_SUB | BPF_X:
    case BPF_ALU_SUB | BPF_K:
        op->type = R_ANAL_OP_TYPE_SUB;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,-=", f->k);

        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,-=");
        }
        break;
    case BPF_ALU_MUL | BPF_X:
    case BPF_ALU_MUL | BPF_K:
        op->type = R_ANAL_OP_TYPE_MUL;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,*=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,*=");
        }
        break;
    case BPF_ALU_DIV | BPF_X:
    case BPF_ALU_DIV | BPF_K:
        op->type = R_ANAL_OP_TYPE_DIV;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,/=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,/=");
        }
        break;
    case BPF_ALU_MOD | BPF_X:
    case BPF_ALU_MOD | BPF_K:
        op->type = R_ANAL_OP_TYPE_MOD;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,%%=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,%%=");
        }
        break;
    case BPF_ALU_AND | BPF_X:
    case BPF_ALU_AND | BPF_K:
        op->type = R_ANAL_OP_TYPE_AND;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,&=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,&=");
        }
        break;
    case BPF_ALU_OR | BPF_X:
    case BPF_ALU_OR | BPF_K:
        op->type = R_ANAL_OP_TYPE_OR;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,|=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,|,A,=");
        }
        break;
    case BPF_ALU_XOR | BPF_X:
    case BPF_ALU_XOR | BPF_K:
        op->type = R_ANAL_OP_TYPE_XOR;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
            SET_REG_DST_IMM (op, "A", f->k);
            esilprintf (op, "%"PFMT64d",A,^=", f->k);
        } else {
            SET_REG_SRC_DST (op, "X", "A");
            esilprintf (op, "X,A,^=");
        }
        break;
    default:
        op->type = R_ANAL_OP_TYPE_ILL;
        break;
    }

    return op->size;
}

static int set_reg_profile(RAnal *anal) {
    const char *p =
    "=PC    pc\n"
    "gpr    A        .32 0   0\n"
    "gpr    X        .32 4   0\n"
    "gpr    M[0]     .32 8   0\n"
    "gpr    M[1]     .32 12   0\n"
    "gpr    M[2]     .32 16   0\n"
    "gpr    M[3]     .32 20   0\n"
    "gpr    M[4]     .32 24   0\n"
    "gpr    M[5]     .32 28   0\n"
    "gpr    M[6]     .32 32   0\n"
    "gpr    M[7]     .32 36   0\n"
    "gpr    M[8]     .32 40   0\n"
    "gpr    M[9]     .32 44   0\n"
    "gpr    M[10]    .32 48   0\n"
    "gpr    M[11]    .32 52   0\n"
    "gpr    M[12]    .32 56   0\n"
    "gpr    M[13]    .32 60   0\n"
    "gpr    M[14]    .32 64   0\n"
    "gpr    M[15]    .32 68   0\n"
    "gpr    pc       .64 72   0\n";
    return r_reg_set_profile_string (anal->reg, p);
}


struct r_anal_plugin_t r_anal_plugin_bpf = {
    .name = "bpf",
    .desc = "Berkely packet filter analysis plugin",
    .license = "GPLv2",
    .arch = NULL,
    .bits = 64,
    .esil = true,
    .init = NULL,
    .fini = NULL,
    .op = &bpf_anal,
    .set_reg_profile = &set_reg_profile,
    .fingerprint_bb = NULL,
    .fingerprint_fcn = NULL,
    .diff_bb = NULL,
    .diff_fcn = NULL,
    .diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
    .type = R_LIB_TYPE_ANAL,
    .data = &r_anal_plugin_bpf,
    .version = R2_VERSION
};
#endif