/* MIT - Copyright 2017 - mrmacete */

#include <r_core.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "r_ggpack.h"

#define ENABLE_DEBUG 0

#if ENABLE_DEBUG
	#define dbg_log(...) eprintf(__VA_ARGS__)
#else
	#define dbg_log(...)
#endif

extern RIOPlugin r_io_plugin_ggpack;

#define BRUTE_VERSIONS 2
static const ut8 magic_bytes[BRUTE_VERSIONS][16] = {
	{ 0x4f, 0xd0, 0xa0, 0xac, 0x4a, 0x5b, 0xb9, 0xe5, 0x93, 0x79, 0x45, 0xa5, 0xc1, 0xcb, 0x31, 0x93 },
	{ 0x4f, 0xd0, 0xa0, 0xac, 0x4a, 0x56, 0xb9, 0xe5, 0x93, 0x79, 0x45, 0xa5, 0xc1, 0xcb, 0x31, 0x93 },
};

#define HAS_GG_INDEX_HEADER(x) (x[0] == 1 && x[1] == 2 && x[2] == 3 && x[3] == 4)

static int r_io_ggpack_read_entry(RIOGGPack *rg, RIO *io, RIODesc *fd, ut8 *buf, int count, RGGPackIndexEntry * entry);
static int r_io_ggpack_write_entry(RIOGGPack *rg, RIO *io, RIODesc *fd, const ut8 *buf, int count, RGGPackIndexEntry * entry);
static bool r_io_ggpack_create_index(RIOGGPack *rg);

static RGGPackIndexEntry *r_ggpack_entry_new(char * name, ut32 offset, ut32 size);
static void r_ggpack_entry_free(RGGPackIndexEntry * e);

static RGGPackIndex * r_ggpack_index_new(RList * entry_list);
static void r_ggpack_index_free(RGGPackIndex * index);
static int r_ggpack_index_search(RGGPackIndex *index, ut32 offset);

static ut8 gg_sample_buffer(RIOGGPack *rg, ut8 *buffer, ut32 index, ut32 displace);
static void gg_deobfuscate(RIOGGPack *rg, ut8 * out_buffer, ut8 *buffer,
			   ut32 key_offset, ut32 key_size, ut32 buf_offset, ut32 buf_size);
static void gg_obfuscate(RIOGGPack *rg, ut8 * out_buffer, ut8 *buffer,
			   ut32 key_offset, ut32 key_size, ut32 buf_offset, ut32 buf_size);
static char * r_ggpack_read_str(ut8 * index_buffer, ut32 offset);
static ut32 fread_le32(FILE *f);

static RIOGGPack *r_io_ggpack_new(void) {
	RIOGGPack *rg = R_NEW0 (RIOGGPack);
	if (!rg) {
		return NULL;
	}

	rg->index = NULL;
	rg->file_name = NULL;
	rg->file = NULL;
	rg->version = 0;

	return rg;
}

static void r_io_ggpack_free(RIOGGPack *rg) {
	if (!rg) {
		return;
	}

	if (rg->file) {
		fclose (rg->file);
	}
	if (rg->file_name) {
		R_FREE (rg->file_name);
	}
	if (rg->index) {
		r_ggpack_index_free (rg->index);
	}

	R_FREE (rg);
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return strncmp (pathname, "ggpack://", 9) == 0;
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	RIOGGPack *rg;

	rg = r_io_ggpack_new ();
	if (!rg) {
		goto error;
	}

	if (!__check (io, pathname, false)) {
		goto error;
	}

	rg->file_name = strdup (pathname + 9);
	rg->file = fopen (rg->file_name, (mode & R_IO_RW) ? "rb+": "rb");
	if (!rg->file) {
		goto error;
	}

	if (!r_io_ggpack_create_index (rg)) {
		goto error;
	}

	RIODesc *desc = r_io_desc_new (io, &r_io_plugin_ggpack, pathname, rw, mode, rg);

	return desc;

error:
	r_io_ggpack_free (rg);

	return NULL;
}

static int __close(RIODesc *fd) {
	RIOGGPack *rg;

	if (!fd || !fd->data) {
		return -1;
	}

	rg = fd->data;

	r_io_ggpack_free (fd->data);
	fd->data = NULL;

	return 0;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	RIOGGPack *rg;
	if (!fd || !fd->data) {
		return -1;
	}
	rg = fd->data;

	int i = R_MAX (0, r_ggpack_index_search(rg->index, io->off));

	RGGPackIndexEntry * entry;
	do {
		entry = rg->index->entries[i];
		r_io_ggpack_read_entry (rg, io, fd, buf, count, entry);
		i++;
	} while ((i < rg->index->length) && (entry->offset + entry->size) < (io->off + count));

	return count;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOGGPack *rg = NULL;

	if (!fd || !fd->data) {
		return io->off;
	}

	rg = fd->data;

	switch (whence) {
	case SEEK_SET:
		io->off = offset;
		break;
	case SEEK_CUR:
		io->off += (int) offset;
		break;
	case SEEK_END:
		{
			RGGPackIndexEntry * lastEntry = rg->index->entries[rg->index->length-1];
			io->off = lastEntry->offset + lastEntry->size;
			break;
		}
	}
	return io->off;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOGGPack *rg;
	if (!fd || !fd->data) {
		return -1;
	}
	rg = fd->data;

	int i = R_MAX (0, r_ggpack_index_search(rg->index, io->off));

	RGGPackIndexEntry * entry;
	do {
		entry = rg->index->entries[i];
		r_io_ggpack_write_entry (rg, io, fd, buf, count, entry);
		i++;
	} while ((i < rg->index->length) && (entry->offset + entry->size) < (io->off + count));

	return count;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 count) {
	return false;
}

static int __system(RIO *io, RIODesc *fd, const char *command) {
	RIOGGPack *rg;
	const char *value;

	if (!fd || !fd->data) {
		return -1;
	}

	if (!strcmp (command, "help") || !strcmp (command, "h") || !strcmp (command, "?")) {
		io->cb_printf ("ggpack commands available via =!\n"
			"?                          Show this help\n"
		);
		return true;
	}

	rg = fd->data;

	return 0;
}

static int r_io_ggpack_read_entry(RIOGGPack *rg, RIO *io, RIODesc *fd, ut8 *buf, int count, RGGPackIndexEntry * entry) {
	ut32 entry_start = entry->offset;
	ut32 entry_end = entry->offset + entry->size;
	ut32 read_end = io->off + count;

	// TODO remove this "inside" shit
	bool inside = entry_start <= read_end && entry_end >= io->off;
	if (!inside) {
		return 0;
	}

	ut32 start_gap = (entry_start > io->off) ? entry_start - io->off : 0;
	ut32 real_count = R_MIN (entry_end, read_end) - R_MAX (entry_start, io->off);

	if (entry->is_obfuscated) {
		if (io->off > entry_start) {
			ut8 * dbuf = malloc (real_count+1);
			fseek (rg->file, io->off-1 + start_gap, SEEK_SET);
			fread (dbuf, 1, real_count+1, rg->file);
			gg_deobfuscate (rg, buf + start_gap, dbuf, entry_start, entry->size, io->off + start_gap, real_count+1);
			R_FREE (dbuf);
		} else {
			fseek (rg->file, io->off + start_gap, SEEK_SET);
			fread (buf + start_gap, 1, real_count, rg->file);
			gg_deobfuscate (rg, NULL, buf+start_gap, entry_start, entry->size, io->off + start_gap, real_count);
		}
	} else {
		fseek (rg->file, io->off + start_gap, SEEK_SET);
		fread (buf + start_gap, 1, real_count, rg->file);
	}

	return real_count;
}

static int r_io_ggpack_write_entry(RIOGGPack *rg, RIO *io, RIODesc *fd, const ut8 *buf, int count, RGGPackIndexEntry * entry) {
	ut32 entry_start = entry->offset;
	ut32 entry_end = entry->offset + entry->size;
	ut32 write_end = io->off + count;
	ut32 rest_size = entry_end - write_end;

	// TODO remove this "inside" shit
	bool inside = entry_start <= write_end && entry_end >= io->off;
	if (!inside) {
		return 0;
	}

	ut32 start_gap = (entry_start > io->off) ? entry_start - io->off : 0;
	ut32 real_count = R_MIN (entry_end, write_end) - R_MAX (entry_start, io->off);
	if (real_count == 0) {
		return 0;
	}

	ut8 *dbuf, *wbuf;;
	if (entry->is_obfuscated) {
		if (io->off > entry_start) {
			dbuf = malloc(real_count + 1 + rest_size);
			wbuf = dbuf + 1;
			fseek (rg->file, io->off + start_gap - 1, SEEK_SET);
			fread (dbuf, 1, 1, rg->file);
			memcpy (wbuf, buf + start_gap, real_count);

			if (rest_size > 0) {
				ut64 saved_off = io->off;
				io->off = write_end;
				__read (io, fd, wbuf + real_count, rest_size);
				io->off = saved_off;
			}

			gg_obfuscate (rg, NULL, dbuf, entry_start, entry->size, io->off + start_gap, real_count + 1 + rest_size);
		} else {
			wbuf = dbuf = malloc(real_count + rest_size);
			memcpy (dbuf, buf + start_gap, real_count);

			if (rest_size > 0) {
				ut64 saved_off = io->off;
				io->off = write_end;
				__read (io, fd, wbuf + real_count, rest_size);
				io->off = saved_off;
			}

			gg_obfuscate (rg, NULL, dbuf, entry_start, entry->size, io->off + start_gap, real_count + rest_size);
		}
	} else {
		wbuf = dbuf = (ut8 *) buf + start_gap;
	}

	fseek (rg->file, io->off + start_gap, SEEK_SET);
	fwrite (wbuf, 1, real_count + rest_size, rg->file);

	R_FREE (dbuf);

	return real_count;
}

static bool r_io_ggpack_create_index(RIOGGPack *rg) {
#define EXPECT(var_, entry_, cond_) \
	if (cond_) {\
		if (strcmp (var_, entry_) != 0) {\
			dbg_log ("expected '"entry_"', got '%s'\n", var_);\
			goto nice_error;\
		} else {\
			plo += 4;\
			var_ = r_ggpack_read_str (index_buffer, plo);\
			if (var_ == NULL) {\
				break;\
			}\
			skip_cursor++;\
		}\
	}

	ut8 *index_buffer = NULL;

	fseek (rg->file, 0, SEEK_SET);

	rg->index_offset = fread_le32 (rg->file);
	rg->index_size = fread_le32 (rg->file);

	if (rg->index_size != 0) {
		index_buffer = malloc (rg->index_size);
		if (!index_buffer) {
			goto bad_error;
		}
	}

read_direcory:
	fseek (rg->file, rg->index_offset, SEEK_SET);
	fread (index_buffer, 1, rg->index_size, rg->file);

	gg_deobfuscate (rg, NULL, index_buffer, rg->index_offset, rg->index_size, rg->index_offset, rg->index_size);

	if (!HAS_GG_INDEX_HEADER (index_buffer)) {
		goto nice_error;
	}

	ut32 plo = r_read_le32(index_buffer + 8);
	if (index_buffer[plo] != 7) {
		goto nice_error;
	}

	plo++;

	RList * entries = r_list_new ();
	int skip_cursor = 0;
	RGGPackIndexEntry * previous_entry;

	do {
		char * name = r_ggpack_read_str (index_buffer, plo);
		if (name == NULL) {
			break;
		}

		EXPECT (name, "files", skip_cursor == 0);
		EXPECT (name, "filename", skip_cursor == 1);
		dbg_log ("\nname is %s\n", name);

		plo += 4;

		char * offset_str = r_ggpack_read_str (index_buffer, plo);
		EXPECT (offset_str, "offset", skip_cursor == 2);
		dbg_log ("offset is %s\n", offset_str);

		ut32 offset = strtoul (offset_str, NULL, 10);
		if (offset == 0) {
			if (!previous_entry || !previous_entry->offset || !previous_entry->size) {
				dbg_log ("unrecoverably missing offset");
				goto nice_error;
			}
			offset = previous_entry->offset + previous_entry->size;
			if (!previous_entry->size) {
				if (!previous_entry->offset) {
					dbg_log ("unrecoverably missing size");
					goto nice_error;
				}
				previous_entry->size = offset - previous_entry->offset;
			}
			RGGPackIndexEntry * entry = r_ggpack_entry_new (name, offset, 0);
			r_list_append (entries, entry);
			previous_entry = entry;
			continue;
		}
		if (!previous_entry->size) {
			if (!previous_entry->offset) {
				dbg_log ("unrecoverably missing size");
				goto nice_error;
			}
			previous_entry->size = offset - previous_entry->offset;
		}

		plo += 4;

		char * size_str = r_ggpack_read_str (index_buffer, plo);
		EXPECT (size_str, "size", skip_cursor == 3);
		dbg_log ("size is %s\n", size_str);

		ut32 size = strtoul (size_str, NULL, 10);
		if (size == 0) {
			plo -= 4;
			size = offset - previous_entry->offset;
		}

		plo += 4;

		RGGPackIndexEntry * entry = r_ggpack_entry_new (name, offset, size);
		r_list_append (entries, entry);
		previous_entry = entry;
	} while (true);

	RGGPackIndexEntry * index_entry = r_ggpack_entry_new ("index directory", rg->index_offset, rg->index_size);
	r_list_append (entries, index_entry);

	RGGPackIndexEntry * header_entry = r_ggpack_entry_new ("header", 0, 8);
	header_entry->is_obfuscated = false;
	r_list_prepend (entries, header_entry);

	rg->index = r_ggpack_index_new (entries);
	r_list_free (entries);
	if (!rg->index) {
		goto bad_error;
	}

	R_FREE (index_buffer);

	return true;

nice_error:
	if (rg->version < BRUTE_VERSIONS) {
		rg->version++;
		dbg_log ("retry with version %d\n", rg->version);
		goto read_direcory;
	}

bad_error:
	if (index_buffer) {
		R_FREE (index_buffer);
	}

	return false;
}

static RGGPackIndexEntry *r_ggpack_entry_new(char * name, ut32 offset, ut32 size) {
	RGGPackIndexEntry *e = R_NEW0 (RGGPackIndexEntry);
	if (!e) {
		return NULL;
	}

	if (name) {
		e->file_name = strdup(name);
	}
	e->offset = offset;
	e->size = size;
	e->is_obfuscated = true;

	return e;
}

static void r_ggpack_entry_free(RGGPackIndexEntry * e) {
	if (!e) {
		return;
	}

	if (e->file_name) {
		R_FREE (e->file_name);
	}

	R_FREE(e);
}

static RGGPackIndex * r_ggpack_index_new(RList * entry_list) {
	RGGPackIndex * index = NULL;

	if (!entry_list) {
		goto error;
	}

	index = R_NEW0 (RGGPackIndex);
	if (!index) {
		goto error;
	}
	index->length = 0;
	index->entries = NULL;

	RListIter * iter;
	RGGPackIndexEntry * entry;
	int length = r_list_length (entry_list);

	if (length == 0) {
		goto error;
	}

	index->entries = (RGGPackIndexEntry **) malloc (length * sizeof (void *));

	r_list_foreach (entry_list, iter, entry) {
		bool is_valid = !entry->is_obfuscated || (entry->offset != 0 && entry->size != 0);
		if (!is_valid) {
			dbg_log ("incomplete entry: '%s'\n", entry->file_name);
			goto error;
		}
		index->entries[index->length++] = entry;
	}

	return index;

error:
	if (index) {
		r_ggpack_index_free (index);
	}

	return NULL;
}

static void r_ggpack_index_free(RGGPackIndex * index) {
	if (!index) {
		return;
	}

	if (index->entries) {
		int i;
		for (i = 0; i < index->length; i++) {
			r_ggpack_entry_free (index->entries[i]);
		}
	}

	R_FREE (index);
}

static int r_ggpack_index_search(RGGPackIndex *index, ut32 offset) {
	int imid;
	int imin = 0;
	int imax = index->length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		RGGPackIndexEntry * entry = index->entries[imid];
		if ((entry->offset + entry->size) <= offset) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	RGGPackIndexEntry * minEntry = index->entries[imin];
	if ((imax == imin) && (minEntry->offset <= offset) && ((minEntry->offset + minEntry->size) > offset)) {
		return imin;
	}
	return -1;
}

static void gg_deobfuscate(RIOGGPack *rg, ut8 * out_buffer, ut8 *buffer,
			   ut32 key_offset, ut32 key_size, ut32 buf_offset, ut32 buf_size) {
	ut8 previous = key_size & 0xff;
	ut32 i = 0;
	ut32 out_offset = 0;
	ut32 displace = buf_offset - key_offset;
	if (!out_buffer) {
		out_buffer = buffer;
	}

	if (displace) {
		previous = gg_sample_buffer (rg, buffer, i++, displace - 1);
		displace --;
		if (out_buffer != buffer) {
			out_offset = 1;
		}
	}

	for (; i < buf_size; i++) {
		ut8 x = gg_sample_buffer (rg, buffer, i, displace);
		out_buffer[i-out_offset] = x ^ previous;
		previous = x;
	}
}

static void gg_obfuscate(RIOGGPack *rg, ut8 * out_buffer, ut8 *buffer,
			   ut32 key_offset, ut32 key_size, ut32 buf_offset, ut32 buf_size) {
	ut8 previous = key_size & 0xff;
	ut32 i = 0;
	ut32 out_offset = 0;
	ut32 displace = buf_offset - key_offset;
	if (!out_buffer) {
		out_buffer = buffer;
	}

	if (displace) {
		previous = gg_sample_buffer (rg, buffer, i++, displace - 1);
		displace --;
		if (out_buffer != buffer) {
			out_offset = 1;
		}
	}

	for (; i < buf_size; i++) {
		ut8 x = buffer[i] ^ previous;
		out_buffer[i-out_offset] = x ^ magic_bytes[rg->version][(i + displace) & 0xf] ^ ((i + displace) * 0x6dL);
		previous = x;
	}
}

static ut8 gg_sample_buffer(RIOGGPack *rg, ut8 *buffer, ut32 index, ut32 displace) {
	return buffer[index] ^ magic_bytes[rg->version][(index + displace) & 0xf] ^ ((index + displace) * 0x6dL);
}

static char * r_ggpack_read_str(ut8 * index_buffer, ut32 offset) {
	ut32 ptr = r_read_le32 (index_buffer + offset);
	if (ptr == 0xffffffff) {
		return NULL;
	}
	return (char *) &index_buffer[ptr];
}

static ut32 fread_le32(FILE *f) {
	void *buf[4];
	fread (buf, 1, 4, f);
	return r_read_le32 (buf);
}

RIOPlugin r_io_plugin_ggpack = {
	.name = "ggpack",
	.desc = "ggpack:// io plugin",
	.license = "MIT",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.lseek = __lseek,
	.write = __write,
	.resize = __resize,
	.system = __system,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_ggpack,
	.version = R2_VERSION
};
#endif
