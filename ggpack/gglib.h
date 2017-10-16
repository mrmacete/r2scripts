#ifndef R_GGLIB_H
#define R_GGLIB_H

#define GG_TYPE_STRING 4
#define GG_TYPE_INT 5
#define GG_TYPE_HASH 2
#define GG_TYPE_ARRAY 3

typedef struct {
	int type;
} GGValue;

typedef struct {
	const char * key;
	GGValue * value;
} GGHashPair;

typedef struct {
	int type;
	ut32 value;
} GGIntValue;

typedef struct {
	int type;
	const char * value;
} GGStringValue;

typedef struct {
	int type;
	GGHashPair **pairs;
	ut32 n_pairs;
} GGHashValue;

typedef struct {
	int type;
	GGValue **entries;
	ut32 length;
} GGArrayValue;

bool gg_hash_serialize(GGHashValue * hash, ut8 ** out_buf, ut32 * out_buf_size);
GGHashValue *gg_hash_unserialize(const ut8* in_buf, ut32 buf_size);

GGArrayValue *gg_array_new(ut32 length);
void gg_array_free(GGArrayValue * array);

GGHashValue *gg_hash_new(ut32 n_pairs);
void gg_hash_free(GGHashValue * hash);
GGValue *gg_hash_value_for_key(GGHashValue * hash, const char * key);

GGIntValue *gg_int_new (ut32 value);
GGStringValue *gg_string_new (const char * value);
GGHashPair *gg_pair_new (const char * key, GGValue * value);

#endif
