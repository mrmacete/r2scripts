/*
 * Most of this is copied and pasted from linux source.
 *
 * Copyright 2015 - mrmacete <mrmacete@protonmail.ch>
 * Licensed under the GNU General Public License, version 2.0 (GPLv2)
 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "bpf.h"

static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, int len) {
	const char *op, *fmt;
	RBpfSockFilter * f = (RBpfSockFilter*)buf;
	int val = f->k;
	char vbuf[256];

	switch (f->code) {
	case BPF_RET | BPF_K:
		op = r_bpf_op_table[BPF_RET];
		fmt = "#%#x";
		break;
	case BPF_RET | BPF_A:
		op = r_bpf_op_table[BPF_RET];
		fmt = "a";
		break;
	case BPF_RET | BPF_X:
		op = r_bpf_op_table[BPF_RET];
		fmt = "x";
		break;
	case BPF_MISC_TAX:
		op = r_bpf_op_table[BPF_MISC_TAX];
		fmt = "";
		break;
	case BPF_MISC_TXA:
		op = r_bpf_op_table[BPF_MISC_TXA];
		fmt = "";
		break;
	case BPF_ST:
		op = r_bpf_op_table[BPF_ST];
		fmt = "M[%d]";
		break;
	case BPF_STX:
		op = r_bpf_op_table[BPF_STX];
		fmt = "M[%d]";
		break;
	case BPF_LD_W | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "[%d]";
		break;
	case BPF_LD_H | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_H];
		fmt = "[%d]";
		break;
	case BPF_LD_B | BPF_ABS:
		op = r_bpf_op_table[BPF_LD_B];
		fmt = "[%d]";
		break;
	case BPF_LD_W | BPF_LEN:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "#len";
		break;
	case BPF_LD_W | BPF_IND:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "[x+%d]";
		break;
	case BPF_LD_H | BPF_IND:
		op = r_bpf_op_table[BPF_LD_H];
		fmt = "[x+%d]";
		break;
	case BPF_LD_B | BPF_IND:
		op = r_bpf_op_table[BPF_LD_B];
		fmt = "[x+%d]";
		break;
	case BPF_LD | BPF_IMM:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "#%#x";
		break;
	case BPF_LDX | BPF_IMM:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "#%#x";
		break;
	case BPF_LDX_B | BPF_MSH:
		op = r_bpf_op_table[BPF_LDX_B];
		fmt = "4*([%d]&0xf)";
		break;
	case BPF_LD | BPF_MEM:
		op = r_bpf_op_table[BPF_LD_W];
		fmt = "M[%d]";
		break;
	case BPF_LDX | BPF_MEM:
		op = r_bpf_op_table[BPF_LDX];
		fmt = "M[%d]";
		break;
	case BPF_JMP_JA:
		op = r_bpf_op_table[BPF_JMP_JA];
		fmt = "%d";
		val = a->pc + 8 + f->k * 8;
		break;
	case BPF_JMP_JGT | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JGT];
		fmt = "x";
		break;
	case BPF_JMP_JGT | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JGT];
		fmt = "#%#x";
		break;
	case BPF_JMP_JGE | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JGE];
		fmt = "x";
		break;
	case BPF_JMP_JGE | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JGE];
		fmt = "#%#x";
		break;
	case BPF_JMP_JEQ | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JEQ];
		fmt = "x";
		break;
	case BPF_JMP_JEQ | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JEQ];
		fmt = "#%#x";
		break;
	case BPF_JMP_JSET | BPF_X:
		op = r_bpf_op_table[BPF_JMP_JSET];
		fmt = "x";
		break;
	case BPF_JMP_JSET | BPF_K:
		op = r_bpf_op_table[BPF_JMP_JSET];
		fmt = "#%#x";
		break;
	case BPF_ALU_NEG:
		op = r_bpf_op_table[BPF_ALU_NEG];
		fmt = "";
		break;
	case BPF_ALU_LSH | BPF_X:
		op = r_bpf_op_table[BPF_ALU_LSH];
		fmt = "x";
		break;
	case BPF_ALU_LSH | BPF_K:
		op = r_bpf_op_table[BPF_ALU_LSH];
		fmt = "#%d";
		break;
	case BPF_ALU_RSH | BPF_X:
		op = r_bpf_op_table[BPF_ALU_RSH];
		fmt = "x";
		break;
	case BPF_ALU_RSH | BPF_K:
		op = r_bpf_op_table[BPF_ALU_RSH];
		fmt = "#%d";
		break;
	case BPF_ALU_ADD | BPF_X:
		op = r_bpf_op_table[BPF_ALU_ADD];
		fmt = "x";
		break;
	case BPF_ALU_ADD | BPF_K:
		op = r_bpf_op_table[BPF_ALU_ADD];
		fmt = "#%d";
		break;
	case BPF_ALU_SUB | BPF_X:
		op = r_bpf_op_table[BPF_ALU_SUB];
		fmt = "x";
		break;
	case BPF_ALU_SUB | BPF_K:
		op = r_bpf_op_table[BPF_ALU_SUB];
		fmt = "#%d";
		break;
	case BPF_ALU_MUL | BPF_X:
		op = r_bpf_op_table[BPF_ALU_MUL];
		fmt = "x";
		break;
	case BPF_ALU_MUL | BPF_K:
		op = r_bpf_op_table[BPF_ALU_MUL];
		fmt = "#%d";
		break;
	case BPF_ALU_DIV | BPF_X:
		op = r_bpf_op_table[BPF_ALU_DIV];
		fmt = "x";
		break;
	case BPF_ALU_DIV | BPF_K:
		op = r_bpf_op_table[BPF_ALU_DIV];
		fmt = "#%d";
		break;
	case BPF_ALU_MOD | BPF_X:
		op = r_bpf_op_table[BPF_ALU_MOD];
		fmt = "x";
		break;
	case BPF_ALU_MOD | BPF_K:
		op = r_bpf_op_table[BPF_ALU_MOD];
		fmt = "#%d";
		break;
	case BPF_ALU_AND | BPF_X:
		op = r_bpf_op_table[BPF_ALU_AND];
		fmt = "x";
		break;
	case BPF_ALU_AND | BPF_K:
		op = r_bpf_op_table[BPF_ALU_AND];
		fmt = "#%#x";
		break;
	case BPF_ALU_OR | BPF_X:
		op = r_bpf_op_table[BPF_ALU_OR];
		fmt = "x";
		break;
	case BPF_ALU_OR | BPF_K:
		op = r_bpf_op_table[BPF_ALU_OR];
		fmt = "#%#x";
		break;
	case BPF_ALU_XOR | BPF_X:
		op = r_bpf_op_table[BPF_ALU_XOR];
		fmt = "x";
		break;
	case BPF_ALU_XOR | BPF_K:
		op = r_bpf_op_table[BPF_ALU_XOR];
		fmt = "#%#x";
		break;
	default:
		op = "invalid";
		fmt = "%#x";
		val = f->code;
		break;
	}

	memset(vbuf, 0, sizeof(vbuf));
	snprintf(vbuf, sizeof(vbuf), fmt, val);
	vbuf[sizeof(vbuf) - 1] = 0;

	if ((BPF_CLASS(f->code) == BPF_JMP && BPF_OP(f->code) != BPF_JA))
		sprintf (r_op->buf_asm, "%s %s, 0x%08"PFMT64x", 0x%08"PFMT64x"", op, vbuf,
			  a->pc + 8 + f->jt * 8, a->pc + 8 + f->jf * 8);
	else
		sprintf (r_op->buf_asm, "%s %s", op, vbuf);

	return r_op->size = 8;
}

RAsmPlugin r_asm_plugin_bpf = {
	.name = "bpf",
	.desc = "Berkeley Packet Filter disassembler",
	.license = "GPLv2",
	.arch = "bpf",
	.bits = 64,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_bpf,
	.version = R2_VERSION
};
#endif