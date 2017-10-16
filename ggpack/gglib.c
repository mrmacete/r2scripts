/* MIT - Copyright 2017 - mrmacete */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <r_lib.h>
#include "gglib.h"

typedef struct {
	ut32 * plo;
	ut32 plo_length;

	const ut8 *buf;
	ut32 buf_size;
	ut32 buf_cursor;
} GGParseContext;

typedef struct {
	RList * chunks;
	ut32 chunks_size;
	RList * string_table;
	char ** string_table_array;
	ut32 * string_table_offsets;
	ut32 string_table_length;
	ut32 string_table_size;
	RList * tmp_strings;
	RList * plo;
} GGSerializationContext;

typedef struct {
	ut8 * data;
	ut32 size;
} GGChunk;

static GGHashValue *gg_hash_carve(GGParseContext *ctx);
static GGValue *gg_value_carve(GGParseContext *ctx);

static void gg_hash_create_string_table(GGSerializationContext * ctx, GGHashValue * hash);
static void gg_array_create_string_table(GGSerializationContext * ctx, GGArrayValue * array);
static void gg_value_create_string_table(GGSerializationContext * ctx, GGValue * value);

static bool gg_hash_create_chunks(GGSerializationContext * ctx, GGHashValue * hash);
static bool gg_array_create_chunks(GGSerializationContext * ctx, GGArrayValue * array);
static bool gg_value_create_chunks(GGSerializationContext * ctx, GGValue * value);
static bool gg_string_create_chunks(GGSerializationContext * ctx, GGStringValue * value);
static bool gg_int_create_chunks(GGSerializationContext * ctx, GGIntValue * value);

static char * gg_get_tmp_string(GGSerializationContext * ctx, ut32 value);
static bool gg_string_table_uniq(GGSerializationContext * ctx);
static int gg_search_string_table(GGSerializationContext * ctx, const char * string);

static void gg_serialization_context_free(GGSerializationContext * ctx);
static void gg_serlization_context_render(GGSerializationContext * ctx, ut8 * buffer);

static const char * gg_get_plo_string(GGParseContext * ctx, ut32 plo_idx);
static st64 gg_plo_add_string(GGSerializationContext * ctx, const char * string);
static void gg_plo_add_offset(GGSerializationContext * ctx, ut32 offset);

static GGChunk *gg_chunk_new(ut32 len);
static void gg_chunk_free(GGChunk * chunk);
static void gg_chunks_add_chunk(GGSerializationContext * ctx, GGChunk *chunk);

#define CTX_CUR_BYTE(ctx) (ctx->buf[ctx->buf_cursor])
#define CTX_CUR_UT32(ctx) (r_read_le32 (ctx->buf + ctx->buf_cursor))
#define CTX_CUR_VALID(ctx) (ctx->buf_cursor < ctx->buf_size)
#define CTX_CUR_ADVANCE(ctx, advance, fname)\
	ctx->buf_cursor += (advance);\
	if (!CTX_CUR_VALID (ctx)) {\
		dbg_log ("%s: parse out of range\n", fname);\
		goto error;\
	}\

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
	#define dbg_log(...) eprintf(__VA_ARGS__)
#else
	#define dbg_log(...)
#endif

GGHashValue *gg_hash_unserialize(const ut8* in_buf, ut32 buf_size) {
	GGHashValue * result = NULL;

	ut32 signature = r_read_le32 (in_buf);
	if (signature != 0x04030201) {
		dbg_log ("gg_hash_unserialize: wrong signature 0x%x\n", signature);
		return NULL;
	}

	ut32 plo_offset = r_read_le32 (in_buf + 8);
	if (plo_offset < 12 || plo_offset >= buf_size - 4) {
		dbg_log ("gg_hash_unserialize: plo out of range\n");
		return NULL;
	}

	if (in_buf[plo_offset] != 7) {
		dbg_log ("gg_hash_unserialize: can't find plo\n");
		return NULL;
	}

	plo_offset++;
	ut32 plo_length = 0;
	while (r_read_le32 (in_buf + plo_offset + plo_length * 4) != 0xffffffff &&
	       (plo_offset + plo_length * 4) < buf_size) {
		plo_length++;
	}

	if ((plo_offset + (plo_length-1) * 4) >= buf_size) {
		dbg_log ("gg_hash_unserialize: corrupted plo\n");
		return NULL;
	}

	ut32 * plo = malloc (plo_length * 4);
	int i;
	for (i = 0; i < plo_length; i++) {
		ut32 plo_element = r_read_le32 (in_buf + plo_offset + i*4);
		plo[i] = plo_element;
	}

	GGParseContext context = { plo, plo_length, in_buf, buf_size, 12 };

	result = gg_hash_carve (&context);

cleanup:
	if (plo) {
		R_FREE (plo);
	}

	return result;
}

bool gg_hash_serialize(GGHashValue * hash, ut8 ** out_buf, ut32 * out_buf_size) {
	if (!hash) {
		*out_buf = NULL;
		*out_buf_size = 0;
		return false;
	}

	GGSerializationContext ctx;
	ctx.chunks = r_list_new ();
	ctx.chunks_size = 0;
	ctx.plo = r_list_new ();
	ctx.string_table = r_list_new ();
	ctx.string_table_array = NULL;
	ctx.string_table_length = 0;
	ctx.tmp_strings = r_list_new ();

	gg_hash_create_string_table (&ctx, hash);

	if (!gg_string_table_uniq (&ctx)) {
		dbg_log ("cannot uniq string table\n");
		goto error;
	}

	if (!gg_hash_create_chunks (&ctx, hash)) {
		dbg_log ("cannot create chunks\n");
		goto error;
	}

	ut32 string_table_offset = 12 + ctx.chunks_size +
	                           1 + (r_list_length (ctx.plo) + 1) * 4 + 1;

	gg_plo_add_offset (&ctx, string_table_offset);

	ut32 buf_size = string_table_offset +
	                ctx.string_table_size;

	ut8 * buffer = calloc (1, buf_size);
	gg_serlization_context_render (&ctx, buffer);

	*out_buf = buffer;
	*out_buf_size = buf_size;

	gg_serialization_context_free (&ctx);

	return true;

error:
	*out_buf = NULL;
	*out_buf_size = 0;
	gg_serialization_context_free (&ctx);

	return false;
}

static void gg_serlization_context_render(GGSerializationContext * ctx, ut8 * buffer) {
	RListIter * iter;
	GGChunk * chunk;
	void * plo_entry;
	int i;

	ut32 cursor = 0;
	r_write_be32 (buffer + cursor, 0x01020304);
	cursor += 4;

	r_write_le32 (buffer + cursor, 0x01);
	cursor += 4;

	ut32 plo_offset = 12 + ctx->chunks_size;
	r_write_le32 (buffer + cursor, plo_offset);
	cursor += 4;

	r_list_foreach (ctx->chunks, iter, chunk) {
		memcpy (buffer + cursor, chunk->data, chunk->size);
		cursor += chunk->size;
	}

	buffer[cursor++] = 0x07;

	r_list_foreach (ctx->plo, iter, plo_entry) {
		r_write_le32 (buffer + cursor, (ut32) plo_entry);
		cursor += 4;
	}

	r_write_le32 (buffer + cursor, 0xffffffff);
	cursor += 4;

	buffer[cursor++] = 0x08;

	for (i = 0; i < ctx->string_table_length; i++) {
		char * str = ctx->string_table_array[i];
		ut32 off = ctx->string_table_offsets[i];
		strcpy ((char *) buffer + cursor + off, str);
	}
}

static void gg_serialization_context_free(GGSerializationContext * ctx) {
	RListIter * iter;
	if (ctx->chunks) {
		GGChunk * chunk;
		r_list_foreach (ctx->chunks, iter, chunk) {
			gg_chunk_free (chunk);
		}
		r_list_free (ctx->chunks);
		ctx->chunks = NULL;
	}
	if (ctx->string_table) {
		r_list_free (ctx->string_table);
		ctx->string_table = NULL;
	}
	if (ctx->plo) {
		r_list_free (ctx->plo);
		ctx->plo = NULL;
	}
	if (ctx->string_table_array) {
		R_FREE (ctx->string_table_array);
		ctx->string_table_array = NULL;
	}
	if (ctx->string_table_offsets) {
		R_FREE (ctx->string_table_offsets);
		ctx->string_table_offsets = NULL;
	}
	if (ctx->tmp_strings) {
		char * string;
		r_list_foreach (ctx->tmp_strings, iter, string) {
			R_FREE (string);
		}
		r_list_free (ctx->tmp_strings);
		ctx->tmp_strings = NULL;
	}
}

static bool gg_string_table_uniq(GGSerializationContext * ctx) {
	RListIter *iter, *tmp;
	char *string;

	int length_before = r_list_length (ctx->string_table);

	r_list_sort (ctx->string_table, (RListComparator) strcmp);
	r_list_foreach_safe (ctx->string_table, iter, tmp, string) {
		if (iter->p && !strcmp ((char *) iter->p->data, string)) {
			r_list_delete (ctx->string_table, iter);
		}
	}

	int length = r_list_length (ctx->string_table);
	if (!length) {
		return false;
	}

	ctx->string_table_array = malloc (length * sizeof(void *));
	ctx->string_table_offsets = malloc (length * sizeof(ut32));
	ctx->string_table_length = length;

	int i = 0;
	ctx->string_table_size = 0;
	r_list_foreach (ctx->string_table, iter, string) {
		ut32 len = strlen (string);
		ctx->string_table_offsets[i] = ctx->string_table_size;
		ctx->string_table_array[i++] = string;
		ctx->string_table_size += len + 1;
	}

	r_list_free (ctx->string_table);
	ctx->string_table = NULL;

	return true;
}

static void gg_hash_create_string_table(GGSerializationContext * ctx, GGHashValue * hash) {
	int i;
	for (i = 0; i < hash->n_pairs; i++) {
		GGHashPair * pair = hash->pairs[i];
		r_list_append (ctx->string_table, (void *) pair->key);
		gg_value_create_string_table (ctx, pair->value);
	}
}

static void gg_array_create_string_table(GGSerializationContext * ctx, GGArrayValue * array) {
	int i;
	for (i = 0; i < array->length; i++) {
		GGValue * value = array->entries[i];
		if (!value) {
			dbg_log ("array entry %d is NULL\n", i);
			continue;
		}
		gg_value_create_string_table (ctx, value);
	}
}

static void gg_value_create_string_table(GGSerializationContext * ctx, GGValue * value) {
	switch (value->type) {
	case GG_TYPE_HASH:
		gg_hash_create_string_table (ctx, (GGHashValue *) value);
		break;
	case GG_TYPE_ARRAY:
		gg_array_create_string_table (ctx, (GGArrayValue *) value);
		break;
	case GG_TYPE_STRING:
		r_list_append (ctx->string_table, (void *) ((GGStringValue *) value)->value);
		break;
	case GG_TYPE_INT:
	{
		char * tmp_str = gg_get_tmp_string (ctx, ((GGIntValue *) value)->value);
		r_list_append (ctx->string_table, tmp_str);
		break;
	}
	default:
		break;
	}
}

static bool gg_hash_create_chunks(GGSerializationContext * ctx, GGHashValue * hash) {
	int i;

	GGChunk * hash_chunk = gg_chunk_new (5);
	hash_chunk->data[0] = GG_TYPE_HASH;
	r_write_le32 (hash_chunk->data + 1, hash->n_pairs);
	gg_chunks_add_chunk (ctx, hash_chunk);

	for (i = 0; i < hash->n_pairs; i++) {
		GGHashPair * pair = hash->pairs[i];
		st64 plo_idx = gg_plo_add_string (ctx, pair->key);
		if (plo_idx < 0) {
			return false;
		}
		GGChunk * key_chunk = gg_chunk_new (4);
		r_write_le32 (key_chunk->data, (ut32) plo_idx);
		gg_chunks_add_chunk (ctx, key_chunk);

		if (!gg_value_create_chunks (ctx, pair->value)) {
			return false;
		}
	}

	GGChunk * pad_chunk = gg_chunk_new (1);
	pad_chunk->data[0] = GG_TYPE_HASH;
	gg_chunks_add_chunk (ctx, pad_chunk);

	return true;
}

static bool gg_array_create_chunks(GGSerializationContext * ctx, GGArrayValue * array) {
	int i;

	GGChunk * array_chunk = gg_chunk_new (5);
	array_chunk->data[0] = GG_TYPE_ARRAY;
	r_write_le32 (array_chunk->data + 1, array->length);
	gg_chunks_add_chunk (ctx, array_chunk);

	for (i = 0; i < array->length; i++) {
		if (!gg_value_create_chunks (ctx, array->entries[i])) {
			return false;
		}
	}

	GGChunk * pad_chunk = gg_chunk_new (1);
	pad_chunk->data[0] = GG_TYPE_ARRAY;
	gg_chunks_add_chunk (ctx, pad_chunk);

	return true;
}

static bool gg_value_create_chunks(GGSerializationContext * ctx, GGValue * value) {
	switch (value->type) {
	case GG_TYPE_HASH:
		return gg_hash_create_chunks (ctx, (GGHashValue *) value);
	case GG_TYPE_ARRAY:
		return gg_array_create_chunks (ctx, (GGArrayValue *) value);
	case GG_TYPE_STRING:
		return gg_string_create_chunks (ctx, (GGStringValue *) value);
	case GG_TYPE_INT:
		return gg_int_create_chunks (ctx, (GGIntValue *) value);
	default:
		break;
	}
	return false;
}

static bool gg_string_create_chunks(GGSerializationContext * ctx, GGStringValue * value) {
	GGChunk * str_chunk = gg_chunk_new (5);
	str_chunk->data[0] = GG_TYPE_STRING;
	gg_chunks_add_chunk (ctx, str_chunk);

	st64 plo_idx = gg_plo_add_string (ctx, value->value);
	if (plo_idx < 0) {
		return false;
	}

	r_write_le32 (str_chunk->data + 1, (ut32) plo_idx);
	return true;
}

static bool gg_int_create_chunks(GGSerializationContext * ctx, GGIntValue * value) {
	GGChunk * int_chunk = gg_chunk_new (5);
	int_chunk->data[0] = GG_TYPE_INT;
	gg_chunks_add_chunk (ctx, int_chunk);

	char temp[32];
	snprintf (temp, 31, "%u", value->value);
	st64 plo_idx = gg_plo_add_string (ctx, temp);
	if (plo_idx < 0) {
		return false;
	}

	r_write_le32 (int_chunk->data + 1, (ut32) plo_idx);
	return true;
}

static GGChunk *gg_chunk_new(ut32 size) {
	GGChunk * result = R_NEW0 (GGChunk);

	result->data = calloc (1, R_MAX(size, 16));
	result->size = size;

	return result;
}

static void gg_chunk_free(GGChunk * chunk) {
	if (chunk == NULL) {
		return;
	}

	if (chunk->data) {
		R_FREE (chunk->data);
		chunk->data = NULL;
	}

	R_FREE (chunk);
}

static void gg_chunks_add_chunk(GGSerializationContext * ctx, GGChunk *chunk) {
	r_list_append (ctx->chunks, chunk);
	ctx->chunks_size += chunk->size;
}

static st64 gg_plo_add_string(GGSerializationContext * ctx, const char * string) {
	st64 in_table = gg_search_string_table (ctx, string);
	if (in_table < 0) {
		return -1;
	}

	ut64 st_offset = ctx->string_table_offsets[in_table];

	RListIter * iter;
	void * plo_entry;
	st64 in_plo = -1;
	st64 i = 0;
	r_list_foreach (ctx->plo, iter, plo_entry) {
		if ((ut32) plo_entry == (ut32) st_offset) {
			in_plo = i;
			break;
		}
		i++;
	}

	if (in_plo == -1) {
		r_list_append (ctx->plo, (void *) st_offset);
		in_plo = r_list_length (ctx->plo) - 1;
	}

	return in_plo;
}

static void gg_plo_add_offset(GGSerializationContext * ctx, ut32 offset) {
	RListIter * iter;
	void * plo_entry;
	r_list_foreach (ctx->plo, iter, plo_entry) {
		iter->data += offset;
	}
}

static int gg_search_string_table(GGSerializationContext * ctx, const char * string) {
	int imid;
	int imin = 0;
	int imax = ctx->string_table_length - 1;

	while (imin < imax) {
		imid = (imin + imax) / 2;
		const char * x_string = ctx->string_table_array[imid];
		if (strcmp (x_string, string) < 0) {
			imin = imid + 1;
		} else {
			imax = imid;
		}
	}

	const char * min_string = ctx->string_table_array[imin];
	if ((imax == imin) && strcmp (min_string, string) == 0) {
		return imin;
	}
	return -1;
}

static char * gg_get_tmp_string(GGSerializationContext * ctx, ut32 value) {
	char * result = calloc (1, 32);

	snprintf (result, 31, "%u", value);
	r_list_append (ctx->tmp_strings, result);

	return result;
}

GGHashValue *gg_hash_new(ut32 n_pairs) {
	GGHashValue * result = R_NEW0 (GGHashValue);
	result->type = GG_TYPE_HASH;
	result->pairs = calloc (n_pairs, sizeof (void *));
	result->n_pairs = n_pairs;
	if (!result->pairs) {
		R_FREE (result);
		result = NULL;
	}
	return result;
}

void gg_hash_free(GGHashValue * hash) {
	if (hash == NULL) {
		return;
	}

	if (hash->pairs) {
		int i;
		for (i = 0; i < hash->n_pairs; i++) {
			GGHashPair * pair = hash->pairs[i];
			if (!pair || !pair->value) {
				continue;
			}
			switch (pair->value->type) {
			case GG_TYPE_HASH:
				gg_hash_free ((GGHashValue *) pair->value);
				break;
			case GG_TYPE_ARRAY:
				gg_array_free ((GGArrayValue *) pair->value);
				break;
			default:
				R_FREE (pair->value);
			}
			R_FREE (pair);
		}

		hash->n_pairs = 0;
		R_FREE (hash->pairs);
		hash->pairs = NULL;
	}
	R_FREE (hash);
}

GGValue *gg_hash_value_for_key(GGHashValue * hash, const char * key) {
	if (!hash || !key) {
		return NULL;
	}

	int i;
	for (i = 0; i < hash->n_pairs; i++) {
		if (!strcmp (hash->pairs[i]->key, key)) {
			return hash->pairs[i]->value;
		}
	}

	return NULL;
}

GGArrayValue *gg_array_new(ut32 length) {
	if (length == 0) {
		return NULL;
	}

	GGArrayValue * result = R_NEW0 (GGArrayValue);
	result->type = GG_TYPE_ARRAY;
	result->length = length;
	result->entries = calloc (1, length * sizeof(void *));
	if (!result->entries) {
		R_FREE (result);
		result = NULL;
	}

	return result;
}

void gg_array_free(GGArrayValue * array) {
	if (array == NULL) {
		return;
	}

	int i;
	for (i = 0; i < array->length; i++) {
		GGValue * entry = array->entries[i];
		if (!entry) {
			continue;
		}
		switch (entry->type) {
		case GG_TYPE_HASH:
			gg_hash_free ((GGHashValue *) entry);
			break;
		case GG_TYPE_ARRAY:
			gg_array_free ((GGArrayValue *) entry);
			break;
		default:
			R_FREE (entry);
		}
	}

	array->length = 0;
	R_FREE (array);
}

GGIntValue *gg_int_new (ut32 value) {
	GGIntValue * result = R_NEW0 (GGIntValue);
	result->type = GG_TYPE_INT;
	result->value = value;

	return result;
}

GGStringValue *gg_string_new (const char * value) {
	GGStringValue * result = R_NEW0 (GGStringValue);
	result->type = GG_TYPE_STRING;
	result->value = value;

	return result;
}

GGHashPair *gg_pair_new (const char * key, GGValue * value) {
	GGHashPair * result = R_NEW0 (GGHashPair);
	result->key = key;
	result->value = value;

	return result;
}

static const char * gg_get_plo_string(GGParseContext * ctx, ut32 plo_idx) {
	if (plo_idx >= ctx->plo_length) {
		dbg_log ("plo index out of range\n");
		return NULL;
	}

	ut32 str_offset = ctx->plo[plo_idx];
	if (str_offset < 12 || str_offset >= ctx->buf_size) {
		dbg_log ("string offset (%u) out of range\n", str_offset);
		return NULL;
	}

	return (const char *) &ctx->buf[str_offset];
}

static GGValue *gg_value_carve(GGParseContext *ctx) {
	GGValue * result = NULL;

	if (!CTX_CUR_VALID (ctx)) {
		dbg_log ("gg_value_carve: parse out of range\n");
		return NULL;
	}

	ut32 type = CTX_CUR_BYTE (ctx);

	switch (type) {
	case GG_TYPE_HASH:
		result = (GGValue *) gg_hash_carve (ctx);
		break;
	case GG_TYPE_INT:
	{
		CTX_CUR_ADVANCE (ctx, 1, "gg_value_carve");
		ut32 plo_idx_int = CTX_CUR_UT32 (ctx);
		CTX_CUR_ADVANCE (ctx, 4, "gg_value_carve");

		const char * int_str = gg_get_plo_string (ctx, plo_idx_int);
		if (!int_str) {
			dbg_log ("gg_value_carve: could not carve int string value\n");
			return NULL;
		}

		GGIntValue * result_int = R_NEW0 (GGIntValue);
		result_int->type = GG_TYPE_INT;
		result_int->value = strtoul (int_str, NULL, 10);
		result = (GGValue*) result_int;

		break;
	}
	case GG_TYPE_STRING:
	{
		CTX_CUR_ADVANCE (ctx, 1, "gg_value_carve");
		ut32 plo_idx_str = CTX_CUR_UT32 (ctx);
		CTX_CUR_ADVANCE (ctx, 4, "gg_value_carve");

		const char * str = gg_get_plo_string (ctx, plo_idx_str);
		if (!str) {
			dbg_log ("gg_value_carve: could not carve string value\n");
			return NULL;
		}

		GGStringValue * result_str = R_NEW0 (GGStringValue);
		result_str->type = GG_TYPE_STRING;
		result_str->value = str;
		result = (GGValue*) result_str;

		break;
	}
	case GG_TYPE_ARRAY:
	{
		CTX_CUR_ADVANCE (ctx, 1, "gg_value_carve");
		ut32 length = CTX_CUR_UT32 (ctx);
		CTX_CUR_ADVANCE (ctx, 4, "gg_value_carve");

		if (length == 0) {
			dbg_log ("gg_value_carve: zero-length array\n");
			return NULL;
		}

		GGArrayValue * result_arr = gg_array_new (length);
		int i;
		for (i = 0; i < length; i++) {
			GGValue * entry = gg_value_carve (ctx);
			if (!entry) {
				dbg_log ("gg_value_carve: error on array item %d\n", i);
				goto cleanup_array;
			}
			result_arr->entries[i] = entry;
		}

		if (CTX_CUR_BYTE (ctx) != 3) {
			dbg_log ("gg_value_carve: unterminated array\n");
			return NULL;
		}

		CTX_CUR_ADVANCE (ctx, 1, "gg_value_carve");

		result = (GGValue*) result_arr;

		break;

cleanup_array:
		gg_array_free (result_arr);
		break;
	}
	default:
		dbg_log ("gg_value_carve: unsupported type %u\n", type);
	}

error:
	return result;
}

static GGHashValue *gg_hash_carve(GGParseContext *ctx) {
	GGHashValue * result = NULL;

	if (!CTX_CUR_VALID (ctx)) {
		dbg_log ("gg_hash_carve: parse out of range\n");
		return NULL;
	}

	if (CTX_CUR_BYTE (ctx) != 2) {
		dbg_log ("gg_hash_carve: trying to parse a non-hash\n");
		return NULL;
	}

	CTX_CUR_ADVANCE (ctx, 1, "gg_hash_carve");

	ut32 n_pairs = CTX_CUR_UT32 (ctx);
	if (n_pairs == 0) {
		dbg_log ("gg_hash_carve: empty hash\n");
		goto error;
	}

	result = gg_hash_new (n_pairs);
	CTX_CUR_ADVANCE (ctx, 4, "gg_hash_carve");

	int i;
	for (i = 0; i < n_pairs; i++) {
		ut32 key_plo_idx = CTX_CUR_UT32 (ctx);
		CTX_CUR_ADVANCE (ctx, 4, "gg_hash_carve");

		const char * key = gg_get_plo_string (ctx, key_plo_idx);
		if (!key) {
			dbg_log ("gg_hash_carve: could not carve key\n");
			return NULL;
		}

		GGHashPair * pair = R_NEW0 (GGHashPair);
		pair->key = key;

		GGValue * value = gg_value_carve(ctx);
		if (!value) {
			dbg_log ("gg_hash_carve: could not carve value\n");
			R_FREE (pair);
			goto error;
		}
		pair->value = value;
		result->pairs[i] = pair;
	}

	if (CTX_CUR_BYTE (ctx) != 2) {
		dbg_log ("gg_hash_carve: unterminated hash\n");
		return NULL;
	}

	CTX_CUR_ADVANCE (ctx, 1, "gg_hash_carve");

	return result;

error:
	if (result) {
		gg_hash_free (result);
		result = NULL;
	}

	return NULL;
}
