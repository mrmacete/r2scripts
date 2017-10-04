#ifndef R_GGPACK
#define R_GGPACK

typedef struct {
	char *file_name;
	ut32 offset;
	ut32 size;
	bool is_obfuscated;
} RGGPackIndexEntry;

typedef struct {
	RGGPackIndexEntry ** entries;
	ut32 length;
} RGGPackIndex;

typedef struct {
	RGGPackIndex * index;
	char *file_name;
	FILE *file;
	ut32 version;
	ut32 index_offset;
	ut32 index_size;
} RIOGGPack;

#endif
