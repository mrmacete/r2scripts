/* MIT - Copyright 2017 - mrmacete */

#include <r_core.h>
#include <r_bin.h>
#include <r_lib.h>
#include <r_io.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "r_ggpack.h"

static bool check_bytes(const ut8 *b, ut64 length) {
	ut32 index_offset = r_read_le32 (b);
	ut32 index_magic = r_read_be32 (b + index_offset);
	if (index_magic != 0x01020304) {
		return false;
	}

	ut32 plo = r_read_le32 (b + index_offset + 8);
	if (b[index_offset + plo] != 7) {
		return false;
	}

	return true;
}

static void *load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return R_NOTNULL;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret || !arch || !arch->buf) {
		free (ret);
		return NULL;
	}
	ret->file = strdup (arch->file);
	ret->type = strdup ("ggpack");
	ret->has_va = 0;
	return ret;
}

static RList *entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	if ((ptr = R_NEW0 (RBinAddr))) {
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList *symbols(RBinFile *arch) {
	RList *result = r_list_newf ((RListFree)free);
	if (!result) {
		return NULL;
	}

	int i;
	RIO * io = arch->rbin->iob.io;
	RIOGGPack *rg = io->desc->data;

	for (i = 0; i < rg->index->length; i++) {
		RGGPackIndexEntry * entry = rg->index->entries[i];

		RBinSymbol *sym = R_NEW0 (RBinSymbol);
		if (!sym) {
			r_list_free (result);
			return NULL;
		}

		sym->name = strdup (entry->file_name);
		sym->paddr = sym->vaddr = entry->offset;
		sym->size = entry->size;
		sym->ordinal = 0;

		r_list_append (result, sym);
	}

	return result;
}

static RList *strings(RBinFile *arch) {
	return NULL;
}

static RList* sections(RBinFile *arch) {
	RList *result = r_list_newf ((RListFree)free);
	if (!result) {
		return NULL;
	}

	int i;
	RIO * io = arch->rbin->iob.io;
	RIOGGPack *rg = io->desc->data;

	for (i = 0; i < rg->index->length; i++) {
		RGGPackIndexEntry * entry = rg->index->entries[i];

		RBinSection *section = R_NEW0 (RBinSection);
		strncpy (section->name, entry->file_name, R_BIN_SIZEOF_STRINGS);
		section->size = section->vsize = entry->size;
		section->paddr = section->vaddr = entry->offset;
		section->add = true;
		section->is_data = true;
		section->srwx = 6;

		r_list_append (result, section);
	}

	return result;
}

RBinPlugin r_bin_plugin_ggpack = {
	.name = "ggpack",
	.desc = "ggpack bin goodies",
	.license = "MIT",
	.load_bytes = &load_bytes,
	//.entries = &entries,
	.symbols = &symbols,
	//.sections = &sections,
	.check_bytes = &check_bytes,
	.info = &info,
	//.strings = &strings,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ggpack,
	.version = R2_VERSION
};
#endif

