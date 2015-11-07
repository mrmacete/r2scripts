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

static int bpf_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
    RBpfSockFilter * f = (RBpfSockFilter*) data;
    memset (op, '\0', sizeof (RAnalOp));
    op->size = 8;
    op->addr = addr;
    op->type = R_ANAL_OP_TYPE_UNK;

    switch (f->code) {
    case BPF_RET | BPF_K:
    case BPF_RET | BPF_A:
    case BPF_RET | BPF_X:
        op->type = R_ANAL_OP_TYPE_RET;
        break;
    case BPF_MISC_TAX:
        op->type = R_ANAL_OP_TYPE_MOV;
        break;
    case BPF_MISC_TXA:
        op->type = R_ANAL_OP_TYPE_MOV;
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
        //op = r_bpf_op_table[BPF_LD_W];
        //fmt = "#%#x";
        break;
    case BPF_LDX | BPF_IMM:
        op->type = R_ANAL_OP_TYPE_MOV;
        op->val = f->k;
        //op = r_bpf_op_table[BPF_LDX];
        //fmt = "#%#x";
        break;
    case BPF_LDX_B | BPF_MSH:
        op->type = R_ANAL_OP_TYPE_LOAD;
        //op = r_bpf_op_table[BPF_LDX_B];
        //fmt = "4*([%d]&0xf)";
        break;
    case BPF_LD | BPF_MEM:
        op->type = R_ANAL_OP_TYPE_MOV;
        //op = r_bpf_op_table[BPF_LD_W];
        //fmt = "M[%d]";
        break;
    case BPF_LDX | BPF_MEM:
        op->type = R_ANAL_OP_TYPE_MOV;
        //op = r_bpf_op_table[BPF_LDX];
        //fmt = "M[%d]";
        break;
    case BPF_JMP_JA:
        op->type = R_ANAL_OP_TYPE_JMP;
        op->jump = addr + 8 + f->k * 8;
        //op = r_bpf_op_table[BPF_JMP_JA];
        //fmt = "%d";
        //val = a->pc + 8 + f->k * 8;
        break;
    case BPF_JMP_JGT | BPF_X:
    case BPF_JMP_JGT | BPF_K:
        EMIT_CJMP (op, addr, f);
        op->cond = R_ANAL_COND_GT;
        op->val = f->k;
        //op = r_bpf_op_table[BPF_JMP_JGT];
        //fmt = "#%#x";
        break;
    case BPF_JMP_JGE | BPF_X:
    case BPF_JMP_JGE | BPF_K:
        EMIT_CJMP (op, addr, f);
        op->cond = R_ANAL_COND_GE;
        op->val = f->k;
        //op = r_bpf_op_table[BPF_JMP_JGE];
        //fmt = "#%#x";
        break;
    case BPF_JMP_JEQ | BPF_X:
    case BPF_JMP_JEQ | BPF_K:
        EMIT_CJMP (op, addr, f);
        op->cond = R_ANAL_COND_EQ;
        op->val = f->k;
        //op = r_bpf_op_table[BPF_JMP_JEQ];
        //fmt = "#%#x";
        break;
    case BPF_JMP_JSET | BPF_X:
    case BPF_JMP_JSET | BPF_K:
        EMIT_CJMP (op, addr, f);
        op->val = f->k;
        //op = r_bpf_op_table[BPF_JMP_JSET];
        //fmt = "#%#x";
        break;
    case BPF_ALU_NEG:
        //op = r_bpf_op_table[BPF_ALU_NEG];
        //fmt = "";
        break;
    case BPF_ALU_LSH | BPF_X:
    case BPF_ALU_LSH | BPF_K:
        op->type = R_ANAL_OP_TYPE_SHL;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_LSH];
        //fmt = "#%d";
        break;
    case BPF_ALU_RSH | BPF_X:
    case BPF_ALU_RSH | BPF_K:
        op->type = R_ANAL_OP_TYPE_SHR;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        
        //op = r_bpf_op_table[BPF_ALU_RSH];
        //fmt = "#%d";
        break;
    case BPF_ALU_ADD | BPF_X:
    case BPF_ALU_ADD | BPF_K:
        op->type = R_ANAL_OP_TYPE_ADD;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_ADD];
        //fmt = "#%d";
        break;
    case BPF_ALU_SUB | BPF_X:
    case BPF_ALU_SUB | BPF_K:
        op->type = R_ANAL_OP_TYPE_SUB;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_SUB];
        //fmt = "#%d";
        break;
    case BPF_ALU_MUL | BPF_X:
    case BPF_ALU_MUL | BPF_K:
        op->type = R_ANAL_OP_TYPE_MUL;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_MUL];
        //fmt = "#%d";
        break;
    case BPF_ALU_DIV | BPF_X:
    case BPF_ALU_DIV | BPF_K:
        op->type = R_ANAL_OP_TYPE_DIV;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_DIV];
        //fmt = "#%d";
        break;
    case BPF_ALU_MOD | BPF_X:
    case BPF_ALU_MOD | BPF_K:
        op->type = R_ANAL_OP_TYPE_MOD;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_MOD];
        //fmt = "#%d";
        break;
    case BPF_ALU_AND | BPF_X:
    case BPF_ALU_AND | BPF_K:
        op->type = R_ANAL_OP_TYPE_AND;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_AND];
        //fmt = "#%#x";
        break;
    case BPF_ALU_OR | BPF_X:
    case BPF_ALU_OR | BPF_K:
        op->type = R_ANAL_OP_TYPE_OR;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_OR];
        //fmt = "#%#x";
        break;
    case BPF_ALU_XOR | BPF_X:
    case BPF_ALU_XOR | BPF_K:
        op->type = R_ANAL_OP_TYPE_XOR;
        if (BPF_SRC(f->code) == BPF_K) {
            op->val = f->k;
        }
        //op = r_bpf_op_table[BPF_ALU_XOR];
        //fmt = "#%#x";
        break;
    default:
        op->type = R_ANAL_OP_TYPE_ILL;
        break;
    }

    return op->size;
}

struct r_anal_plugin_t r_anal_plugin_bpf = {
    .name = "bpf",
    .desc = "Berkely packet filter analysis plugin",
    .license = "GPLv2",
    .arch = R_SYS_ARCH_NONE,
    .bits = 64,
    .init = NULL,
    .fini = NULL,
    .op = &bpf_anal,
    .set_reg_profile = NULL,
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