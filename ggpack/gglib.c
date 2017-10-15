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

static GGHashValue *gg_hash_carve(GGParseContext *ctx);
static GGValue *gg_value_carve(GGParseContext *ctx);

static const char * gg_get_plo_string(GGParseContext * ctx, ut32 plo_idx);

#define CTX_CUR_BYTE(ctx) (ctx->buf[ctx->buf_cursor])
#define CTX_CUR_UT32(ctx) (r_read_le32 (ctx->buf + ctx->buf_cursor))
#define CTX_CUR_VALID(ctx) (ctx->buf_cursor < ctx->buf_size)
#define CTX_CUR_ADVANCE(ctx, advance, fname) \
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
		dbg_log ("gg_hash_unserialize: wrong signature\n");
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

	plo_offset ++;
	ut32 plo_length = 0;
	while (r_read_le32 (in_buf + plo_offset + plo_length * 4) != 0xffffffff &&
			(plo_offset + plo_length * 4) < buf_size) {
		plo_length ++;
	}

	if ((plo_offset + plo_length * 4) >= buf_size) {
		dbg_log ("gg_hash_unserialize: corrupted plo");
		return NULL;
	}

	ut32 * plo = malloc (plo_length * 4);
	int i;
	for (i = 0; i < plo_length; i ++) {
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

ut8 *gg_hash_serialize(GGHashValue * hash) {

}

GGHashValue *gg_hash_new(ut32 n_pairs) {
	GGHashValue * result = R_NEW0 (GGHashValue);
	result->type = GG_TYPE_HASH;
	result->pairs = malloc (n_pairs * sizeof (void *));
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

	return &ctx->buf[str_offset];
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

				CTX_CUR_ADVANCE (ctx, 1, "gg_value_carve");

				result_arr->entries[i] = entry;
				result = (GGValue*) result_arr;
			}

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

	return result;

error:
	if (result) {
		gg_hash_free (result);
		result = NULL;
	}

	return NULL;
}
