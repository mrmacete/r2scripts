/* MIT - Copyright 2017 - mrmacete */

#include <r_core.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "r_ggpack.h"
#include "gglib.h"

#define ENABLE_DEBUG 1

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
#define CURRENT_SIZE(rg) (\
		rg->index->entries[rg->index->length-1]->offset +\
		rg->index->entries[rg->index->length-1]->size\
		)

static int r_io_ggpack_read_entry(RIOGGPack *rg, ut32 read_start, ut8 *buf, int count, RGGPackIndexEntry * entry);
static int r_io_ggpack_write_entry(RIOGGPack *rg, ut32 write_start, const ut8 *buf, int count, RGGPackIndexEntry * entry);
static bool r_io_ggpack_resize_entry(RIOGGPack *rg, RIO *io, RIODesc * fd, st64 delta, int i);
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

static int __read_internal(RIOGGPack * rg, ut32 read_start, ut8 * buf, int count);
static int __write_internal(RIOGGPack * rg, ut32 write_start, const ut8 *buf, int count);

static bool r_io_ggpack_rebuild_index_directory(RIOGGPack *rg, ut8 ** new_index_buf, ut32 * size, ut8 * old_index_buf);
static int sort_index_string_cb(const void *a, const void *b);
static void r_io_ggpack_dump_index(RIO * io, RIOGGPack * rg);


static void r_dump_gghash_json(RIO * io, GGHashValue * hash);
static void r_dump_ggarray_json(RIO * io, GGArrayValue * array);

static GGHashValue *r_ggpack_index_to_hash(RGGPackIndex * index);

static int entries_sort_func(const void *a, const void *b);

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
	rg->file = fopen (rg->file_name, (mode & R_IO_RW) ? "rb+" : "rb");
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

	ut32 read_start = io->off;
	return __read_internal (rg, read_start, buf, count);
}

static int __read_internal(RIOGGPack * rg, ut32 read_start, ut8 * buf, int count) {
	int i = R_MAX (0, r_ggpack_index_search(rg->index, read_start));

	RGGPackIndexEntry * entry;
	do {
		entry = rg->index->entries[i];
		r_io_ggpack_read_entry (rg, read_start, buf, count, entry);
		i++;
	} while ((i < rg->index->length) && (entry->offset + entry->size) < (read_start + count));

	return count;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	RIOGGPack *rg;
	if (!fd || !fd->data) {
		return -1;
	}
	rg = fd->data;

	ut32 write_start = io->off;
	return __write_internal (rg, write_start, buf, count);
}

static int __write_internal(RIOGGPack * rg, ut32 write_start, const ut8 *buf, int count) {
	int i = R_MAX (0, r_ggpack_index_search(rg->index, write_start));

	RGGPackIndexEntry * entry;
	do {
		entry = rg->index->entries[i];
		r_io_ggpack_write_entry (rg, write_start, buf, count, entry);
		i++;
	} while ((i < rg->index->length) && (entry->offset + entry->size) < (write_start + count));

	return count;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	RIOGGPack *rg = NULL;
	ut64 r_offset = offset;

	if (!fd || !fd->data) {
		return r_offset;
	}

	rg = fd->data;
	ut32 current_size = CURRENT_SIZE (rg);

	switch (whence) {
	case SEEK_SET:
		r_offset = offset;
		break;
	case SEEK_CUR:
		r_offset = rg->offset + (ut32) offset;
		break;
	case SEEK_END:
		r_offset = current_size + offset;
		break;
	}

	if (r_offset > current_size) {
		r_offset = current_size;
	}

	io->off = rg->offset = r_offset;

	return r_offset;
}

static bool __resize(RIO *io, RIODesc *fd, ut64 count) {
	RIOGGPack *rg;
	if (!fd || !fd->data) {
		return false;
	}
	rg = fd->data;

	if (count > 0xffffffff) {
		dbg_log ("can't resize that much\n");
		return false;
	}

	int i = r_ggpack_index_search(rg->index, rg->offset);
	if (i < 1) {
		dbg_log ("can't resize here\n");
		return false;
	}


	ut32 old_size = CURRENT_SIZE (rg);
	st64 delta = count - old_size;

	return r_io_ggpack_resize_entry (rg, io, fd, delta, i);
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
		               "ri                         rebuild index\n"
		               );
		return true;
	}

	rg = fd->data;

	if (!strcmp (command, "ri")) {
		GGHashValue * index_dir = r_ggpack_index_to_hash (rg->index);
		ut8 * new_index_buf;
		ut32 new_index_size;
		gg_hash_serialize (index_dir, &new_index_buf, &new_index_size);

		ut8 int_buf[4];
		r_write_le32 (&int_buf[0], new_index_size);
		__write_internal (rg, 4, &int_buf[0], 4);

		rg->index->entries[rg->index->length-1]->size = new_index_size;
		rg->index_size = new_index_size;
		__write_internal (rg, rg->index_offset, new_index_buf, rg->index_size);

		/*FILE * f = fopen ("temp_rebuilt_index", "wb");
		   fwrite (new_index_buf, 1, new_index_size, f);
		   fclose (f);
		   eprintf ("written\n");*/

		gg_hash_free (index_dir);
	}

	if (!strcmp (command, "00ri")) {
		ut32 old_size = rg->index_size;
		ut8 * old_index_buf = malloc (old_size);
		__read_internal (rg, rg->index_offset, old_index_buf, rg->index_size);

		ut32 new_size = 0;
		ut8 * new_index_buf = NULL;
		if (!r_io_ggpack_rebuild_index_directory (rg, &new_index_buf, &new_size, old_index_buf)) {
			if (new_index_buf) {
				R_FREE (new_index_buf);
			}
			R_FREE (old_index_buf);
			eprintf ("FAIL\n");
			return -1;
		}

		ut8 int_buf[4];
		r_write_le32 (&int_buf[0], new_size);
		__write_internal (rg, 4, &int_buf[0], 4);


		rg->index->entries[rg->index->length-1]->size = new_size;
		rg->index_size = new_size;
		//__write_internal (rg, rg->index_offset, new_index_buf, rg->index_size);
		/*FILE * f = fopen ("temp_rebuilt_index", "wb");
		   fwrite (new_index_buf, 1, new_size, f);
		   fclose (f);
		   eprintf ("written\n");*/

		ut8 * test_buf = malloc (new_size);
		//memcpy (test_buf, new_index_buf, new_size);

		gg_obfuscate (rg, test_buf, new_index_buf, rg->index_offset, rg->index_size, rg->index_offset, rg->index_size);
		fseek (rg->file, rg->index_offset, SEEK_SET);
		fwrite (test_buf, 1, rg->index_size, rg->file);
		gg_deobfuscate (rg, NULL, test_buf, rg->index_offset, rg->index_size, rg->index_offset, rg->index_size);

		eprintf ("CORRECT: %d\n", memcmp (test_buf, new_index_buf, new_size) == 0);

		R_FREE (test_buf);

		R_FREE (new_index_buf);
		R_FREE (old_index_buf);
		return 0;
	}

	if (!strcmp (command, "test")) {
		char * test_string = "this is a fairly long text useful to test obfuscation correctness, i.e. is this text being obfuscated then deobfuscated to itself? only the test can tell it, so let's see how it goes.";
		ut32 the_size = strlen (test_string);
		ut8 * buf = malloc (the_size);
		strcpy ((char *) buf, test_string);
		gg_obfuscate (rg, NULL, buf, 0, the_size, 0, the_size);
		gg_deobfuscate (rg, NULL, buf, 0, the_size, 0, the_size);
		eprintf ("%s\n", buf);
		eprintf ("success? %d\n", strcmp ((char *) buf, test_string) == 0);
		R_FREE (buf);
		return 0;
	}

	if (!strcmp (command, "di")) {
		r_io_ggpack_dump_index (io, rg);
		return 0;
	}

	return 0;
}

static GGHashValue *r_ggpack_index_to_hash(RGGPackIndex * index) {
	int i;
	GGHashValue * index_dir = gg_hash_new (1);
	GGArrayValue * files = gg_array_new (index->length - 2);
	index_dir->pairs[0] = gg_pair_new ("files", (GGValue *) files);

	for (i = 1; i < index->length - 1; i++) {
		GGHashValue * file = gg_hash_new (3);
		RGGPackIndexEntry * entry = index->entries[i];

		GGStringValue * filename = gg_string_new (entry->file_name);
		file->pairs[0] = gg_pair_new ("filename", (GGValue *) filename);

		GGIntValue * offset = gg_int_new (entry->offset);
		file->pairs[1] = gg_pair_new ("offset", (GGValue *) offset);

		GGIntValue * size = gg_int_new (entry->size);
		file->pairs[2] = gg_pair_new ("size", (GGValue *) size);

		files->entries[i-1] = (GGValue *) file;
	}

	return index_dir;
}

static int r_io_ggpack_read_entry(RIOGGPack *rg, ut32 read_start, ut8 *buf, int count, RGGPackIndexEntry * entry) {
	ut32 entry_start = entry->offset;
	ut32 entry_end = entry->offset + entry->size;
	ut32 read_end = read_start + count;

	// TODO remove this "inside" shit
	bool inside = entry_start <= read_end && entry_end >= read_start;
	if (!inside) {
		return 0;
	}

	ut32 start_gap = (entry_start > read_start) ? entry_start - read_start : 0;
	ut32 real_count = R_MIN (entry_end, read_end) - R_MAX (entry_start, read_start);

	if (entry->is_obfuscated) {
		if (read_start > entry_start) {
			ut8 * dbuf = malloc (real_count+1);
			fseek (rg->file, read_start-1 + start_gap, SEEK_SET);
			fread (dbuf, 1, real_count+1, rg->file);
			gg_deobfuscate (rg, buf + start_gap, dbuf, entry_start, entry->size, read_start + start_gap, real_count+1);
			R_FREE (dbuf);
		} else {
			fseek (rg->file, read_start + start_gap, SEEK_SET);
			fread (buf + start_gap, 1, real_count, rg->file);
			gg_deobfuscate (rg, NULL, buf+start_gap, entry_start, entry->size, read_start + start_gap, real_count);
		}
	} else {
		fseek (rg->file, read_start + start_gap, SEEK_SET);
		fread (buf + start_gap, 1, real_count, rg->file);
	}

	return real_count;
}

static int r_io_ggpack_write_entry(RIOGGPack *rg, ut32 write_start, const ut8 *buf, int count, RGGPackIndexEntry * entry) {
	ut32 entry_start = entry->offset;
	ut32 entry_end = entry->offset + entry->size;
	ut32 write_end = write_start + count;
	ut32 rest_size = entry_end - write_end;

	// TODO remove this "inside" shit
	bool inside = entry_start <= write_end && entry_end >= write_start;
	if (!inside) {
		return 0;
	}

	ut32 start_gap = (entry_start > write_start) ? entry_start - write_start : 0;
	ut32 real_count = R_MIN (entry_end, write_end) - R_MAX (entry_start, write_start);
	if (real_count == 0) {
		return 0;
	}

	eprintf ("WRITING entry %s (at 0x%x - size 0x%x)\n", entry->file_name, entry->offset, entry->size);
	eprintf ("\tstart_gap %u\n", start_gap);
	eprintf ("\treal_count %u\n", real_count);
	eprintf ("\trest_size %u\n", rest_size);

	ut8 *dbuf = NULL, *wbuf;;
	if (entry->is_obfuscated) {
		eprintf ("\tis obfuscated\n");
		if (write_start > entry_start) {
			eprintf ("\tin the middle of entry\n");
			dbuf = malloc(real_count + 1 + rest_size);
			wbuf = dbuf + 1;
			fseek (rg->file, write_start + start_gap - 1, SEEK_SET);
			fread (dbuf, 1, 1, rg->file);
			memcpy (wbuf, buf + start_gap, real_count);

			if (rest_size > 0) {
				__read_internal (rg, write_end, wbuf + real_count, rest_size);
			}

			gg_obfuscate (rg, NULL, dbuf, entry_start, entry->size, write_start + start_gap, real_count + 1 + rest_size);
		} else {
			eprintf ("\tfrom start of entry\n");
			wbuf = dbuf = malloc(real_count + rest_size);
			memcpy (dbuf, buf + start_gap, real_count);

			if (rest_size > 0) {
				__read_internal (rg, write_end, wbuf + real_count, rest_size);
			}

			eprintf ("\tOBF 0x%x %u - 0x%x %u\n", entry_start, entry->size, write_start + start_gap, real_count + rest_size);
			gg_obfuscate (rg, NULL, dbuf, entry_start, entry->size, write_start + start_gap, real_count + rest_size);
		}
	} else {
		eprintf ("\tis NOT obfuscated\n");
		wbuf = (ut8 *) buf + start_gap;
	}

	fseek (rg->file, write_start + start_gap, SEEK_SET);
	fwrite (wbuf, 1, real_count + rest_size, rg->file);

	if (dbuf) {
		R_FREE (dbuf);
	}

	return real_count;
}

static bool r_io_ggpack_resize_entry(RIOGGPack *rg, RIO *io, RIODesc * fd, st64 delta, int i) {
	RGGPackIndexEntry * entry = rg->index->entries[i];

	st64 new_size = entry->size + delta;
	if (new_size < 0) {
		return false;
	}

	// r_ggpack_index_resize_entry_at (rg->index, i, new_size);

	return true;
}

static bool r_io_ggpack_create_index(RIOGGPack *rg) {
	ut8 *index_buffer = NULL;
	RList * entries = NULL;
	GGHashValue * index_dir = NULL;

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

	index_dir = gg_hash_unserialize (index_buffer, rg->index_size);
	if (!index_dir) {
		goto nice_error;
	}

	GGArrayValue * files = (GGArrayValue *) gg_hash_value_for_key (index_dir, "files");
	if (!files) {
		dbg_log ("missing \"files\" key\n");
		goto nice_error;
	}

	entries = r_list_new ();
	int i = 0;
	bool is_sorted = true;
	ut32 previous_offset = 0;
	for (; i < files->length; i++) {
		char * name;
		ut32 offset = 0, size = 0;
		int j = 0;
		GGHashValue * a_file = (GGHashValue *) files->entries[i];

		for (; j < a_file->n_pairs; j++) {
			GGHashPair * pair = a_file->pairs[j];
			if (!strcmp (pair->key, "filename")) {
				if (pair->value->type == GG_TYPE_STRING) {
					GGStringValue * sv = (GGStringValue *) pair->value;
					if (sv->value) {
						name = strdup (sv->value);
					}
				}
			} else if (!strcmp (pair->key, "offset")) {
				if (pair->value->type == GG_TYPE_INT) {
					offset = ((GGIntValue *) pair->value)->value;
				}
			} else if (!strcmp (pair->key, "size")) {
				if (pair->value->type == GG_TYPE_INT) {
					size = ((GGIntValue *) pair->value)->value;
				}
			}
		}

		if (name == NULL || offset == 0 || size == 0) {
			dbg_log ("incomplete entry %s 0x%x %u\n", name, offset, size);
			goto nice_error;
		}

		if (offset > previous_offset) {
			is_sorted = false;
		}

		RGGPackIndexEntry * entry = r_ggpack_entry_new (name, offset, size);
		r_list_append (entries, entry);
	}

	if (!is_sorted) {
		dbg_log ("sorting index\n");
		r_list_sort (entries, entries_sort_func);
	}

	RGGPackIndexEntry * index_entry = r_ggpack_entry_new ("index directory", rg->index_offset, rg->index_size);
	r_list_append (entries, index_entry);

	RGGPackIndexEntry * header_entry = r_ggpack_entry_new ("header", 0, 8);
	header_entry->is_obfuscated = false;
	r_list_prepend (entries, header_entry);

	rg->index = r_ggpack_index_new (entries);
	r_list_free (entries);
	R_FREE (index_buffer);
	gg_hash_free (index_dir);

	if (!rg->index) {
		eprintf ("no index, oh snap\n");
		return false;
	}
	return true;

nice_error:
	if (entries) {
		RListIter * iter;
		RGGPackIndexEntry * entry;
		r_list_foreach (entries, iter, entry) {
			r_ggpack_entry_free (entry);
		}
		r_list_free (entries);
		entries = NULL;
	}
	if (index_dir) {
		gg_hash_free (index_dir);
		index_dir = NULL;
	}
	if (rg->version < BRUTE_VERSIONS - 1) {
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

static int entries_sort_func(const void *a, const void *b) {
	RGGPackIndexEntry *A = (RGGPackIndexEntry *)a;
	RGGPackIndexEntry *B = (RGGPackIndexEntry *)b;
	return A->offset - B->offset;
}

static void r_dump_ggarray_json(RIO * io, GGArrayValue * array) {
	RListIter * iter;
	GGHashPair * pair;
	int i = 0;

	io->cb_printf ("[");
	for (i = 0; i < array->length; i++) {
		GGValue * value = array->entries[i];
		switch (value->type) {
		case GG_TYPE_STRING:
			io->cb_printf ("\"%s\"", ((GGStringValue *) value)->value);
			break;
		case GG_TYPE_INT:
			io->cb_printf ("%u", ((GGIntValue *) value)->value);
			break;
		case GG_TYPE_HASH:
			r_dump_gghash_json (io, (GGHashValue *) value);
			break;
		case GG_TYPE_ARRAY:
			r_dump_ggarray_json (io, (GGArrayValue *) value);
			break;
		default:
			io->cb_printf ("\"UNSUPPORTED TYPE %d\"", pair->value->type);
		}

		if (i < array->length - 1) {
			io->cb_printf(", ");
		}
	}
	io->cb_printf ("]");
}

static void r_dump_gghash_json(RIO * io, GGHashValue * hash) {
	RListIter * iter;
	GGHashPair * pair;
	int i = 0;

	io->cb_printf ("{");
	for (i = 0; i < hash->n_pairs; i++) {
		GGHashPair * pair = hash->pairs[i];
		io->cb_printf ("\"%s\": ", pair->key);
		switch (pair->value->type) {
		case GG_TYPE_STRING:
			io->cb_printf ("\"%s\"", ((GGStringValue *) pair->value)->value);
			break;
		case GG_TYPE_INT:
			io->cb_printf ("%u", ((GGIntValue *) pair->value)->value);
			break;
		case GG_TYPE_HASH:
			r_dump_gghash_json (io, (GGHashValue *) pair->value);
			break;
		case GG_TYPE_ARRAY:
			r_dump_ggarray_json (io, (GGArrayValue *) pair->value);
			break;
		default:
			io->cb_printf ("\"UNSUPPORTED TYPE %d\"", pair->value->type);
		}

		if (i < hash->n_pairs) {
			io->cb_printf(", ");
		}
	}
	io->cb_printf ("}");
}

static void r_io_ggpack_dump_index(RIO * io, RIOGGPack * rg) {
	ut8 * index_buf = malloc (rg->index_size);
	__read_internal (rg, rg->index_offset, index_buf, rg->index_size);
	GGHashValue * index_dir = gg_hash_unserialize (index_buf, rg->index_size);
	if (!index_dir) {
		eprintf ("TOTAL FAILURE");
		return;
	}

	r_dump_gghash_json (io, index_dir);

	free (index_buf);
}

static bool r_io_ggpack_rebuild_index_directory(RIOGGPack *rg, ut8 ** new_index_buf, ut32 * size, ut8 * old_index_buf) {
	bool success = false;

	ut8 * string_table_buf = NULL;
	ut32 string_table_offset = 0;
	ut8 * plo_buf = NULL;
	RListIter *iter;
	RGGPackIndexString *table_entry;
	RList * string_table = r_list_newf (free);
	if (!string_table) {
		return false;
	}

	int i;
	char str[16];
	ut32 string_table_size = 0;
	for (i = 1; i < rg->index->length-1; i++) {
		RGGPackIndexEntry * entry = rg->index->entries[i];
		entry->tmp_raw = R_NEW0 (RGGPackRawEntry);

		RGGPackIndexString * str_name = R_NEW0 (RGGPackIndexString);
		str_name->string = strdup (entry->file_name);
		str_name->raw_entry = entry->tmp_raw;
		str_name->entry_offset = offsetof (RGGPackRawEntry, name_off);
		str_name->size = strlen (str_name->string) + 1;
		r_list_append (string_table, str_name);
		string_table_size += str_name->size;

		snprintf (str, 16, "%u", entry->offset);
		RGGPackIndexString * str_offset = R_NEW0 (RGGPackIndexString);
		str_offset->string = strdup (str);
		str_offset->raw_entry = entry->tmp_raw;
		str_offset->entry_offset = offsetof (RGGPackRawEntry, offset_off);
		str_offset->size = strlen (str_offset->string) + 1;
		r_list_append (string_table, str_offset);
		string_table_size += str_offset->size;

		snprintf (str, 16, "%u", entry->size);
		RGGPackIndexString * str_size = R_NEW0 (RGGPackIndexString);
		str_size->string = strdup (str);
		str_size->raw_entry = entry->tmp_raw;
		str_size->entry_offset = offsetof (RGGPackRawEntry, size_off);
		str_size->size = strlen (str_size->string) + 1;
		r_list_append (string_table, str_size);
		string_table_size += str_size->size;

		if (!strcmp(entry->file_name, "AbandonedCircusDollRope1.wav")) {
			eprintf ("\tstr_name = %s\n", str_name->string);
			eprintf ("\tstr_offset = %s\n", str_offset->string);
			eprintf ("\tstr_size = %s\n", str_size->string);
		}
	}

	if (string_table_size == 0) {
		success = false;
		goto cleanup;
	}

	ut32 s_files, s_filename, s_offset, s_size;
	RGGPackIndexString * constants;
	constants = R_NEW0 (RGGPackIndexString);
	constants->string = strdup ("files");
	constants->size = 6;
	constants->raw_entry = (RGGPackRawEntry *) &s_files;
	constants->entry_offset = 0;
	r_list_append (string_table, constants);
	string_table_size += constants->size;

	constants = R_NEW0 (RGGPackIndexString);
	constants->string = strdup ("filename");
	constants->size = 9;
	constants->raw_entry = (RGGPackRawEntry *) &s_filename;
	constants->entry_offset = 0;
	r_list_append (string_table, constants);
	string_table_size += constants->size;

	constants = R_NEW0 (RGGPackIndexString);
	constants->string = strdup ("offset");
	constants->size = 7;
	constants->raw_entry = (RGGPackRawEntry *) &s_offset;
	constants->entry_offset = 0;
	r_list_append (string_table, constants);
	string_table_size += constants->size;

	constants = R_NEW0 (RGGPackIndexString);
	constants->string = strdup ("size");
	constants->size = 5;
	constants->raw_entry = (RGGPackRawEntry *) &s_size;
	constants->entry_offset = 0;
	r_list_append (string_table, constants);
	string_table_size += constants->size;

	r_list_sort (string_table, sort_index_string_cb);

	ut32 plo_size = (rg->index->length - 1) * 3 * 4 + 1 + 4 * 4;
	ut32 old_plo = r_read_le32 (old_index_buf + 8);
	*size = old_plo + plo_size + 1 + string_table_size;
	ut8 * nbuf = *new_index_buf = malloc (*size);
	memcpy (nbuf, old_index_buf, old_plo);

	ut8 * list_index = nbuf + 12;

	memcpy (list_index, "\x02\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00", 14);
	r_write_le32 (list_index + 10, rg->index->length -2);
	list_index += 14;

	ut32 list_index_iterator = 2;
	i = 0;
	while (i < rg->index->length-2) {
		bool is_first = list_index_iterator == 2;
		memcpy (list_index, "\x02\x03\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x00\x03\x00\x00\x00\x05\x00\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00\x00\x02", 33);
		r_write_le32 (list_index + 10, list_index_iterator);
		list_index_iterator++;
		if (is_first) {
			list_index_iterator++;
		}

		r_write_le32 (list_index + 19, list_index_iterator);
		list_index_iterator++;
		if (is_first) {
			list_index_iterator++;
		}

		r_write_le32 (list_index + 28, list_index_iterator);
		list_index_iterator++;
		list_index += 33;
		i++;
	}

	string_table_buf = nbuf + old_plo + plo_size;
	ut8 * string_table_cursor = string_table_buf;
	*(string_table_cursor++) = 0x08;

	r_list_foreach (string_table, iter, table_entry) {
		memcpy (string_table_cursor, table_entry->string, table_entry->size);
		RGGPackRawEntry * tmp_raw = table_entry->raw_entry;
		*((ut32*)((ut8*)tmp_raw + table_entry->entry_offset)) = (ut32) (string_table_cursor - string_table_buf);
		string_table_cursor += table_entry->size;
	}

	plo_buf = nbuf + old_plo;
	ut8 * plo_cursor = plo_buf;
	*(plo_cursor++) = 0x07;

	string_table_offset += old_plo;
	string_table_offset += plo_size;

	bool header = true;

	for (i = 1; i < rg->index->length-1; i++) {
		RGGPackIndexEntry * entry = rg->index->entries[i];

		if (header) {
			r_write_le32 (plo_cursor, s_files + string_table_offset);
			plo_cursor += 4;
			r_write_le32 (plo_cursor, s_filename + string_table_offset);
			plo_cursor += 4;
		}
		r_write_le32 (plo_cursor, entry->tmp_raw->name_off + string_table_offset);
		plo_cursor += 4;

		if (header) {
			r_write_le32 (plo_cursor, s_offset + string_table_offset);
			plo_cursor += 4;
		}
		r_write_le32 (plo_cursor, entry->tmp_raw->offset_off + string_table_offset);
		plo_cursor += 4;

		if (header) {
			r_write_le32 (plo_cursor, s_size + string_table_offset);
			plo_cursor += 4;
		}
		r_write_le32 (plo_cursor, entry->tmp_raw->size_off + string_table_offset);
		plo_cursor += 4;

		header = false;
	}
	r_write_le32 (plo_cursor, 0xffffffff);

	success = true;

cleanup:
	for (i = 0; i < rg->index->length; i++) {
		RGGPackIndexEntry * entry = rg->index->entries[i];
		if (entry->tmp_raw) {
			R_FREE(entry->tmp_raw);
			entry->tmp_raw = NULL;
		}
	}

	if (string_table) {
		r_list_foreach (string_table, iter, table_entry) {
			if (table_entry->string) {
				R_FREE (table_entry->string);
			}
		}
		r_list_free (string_table);
	}

	return success;
}

static int sort_index_string_cb(const void *a, const void *b) {
	RGGPackIndexString *A = (RGGPackIndexString *)a;
	RGGPackIndexString *B = (RGGPackIndexString *)b;
	return strcmp (A->string, B->string);
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
		displace--;
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
		displace--;
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
