#ifndef R_GGPACK
#define R_GGPACK

typedef struct {
    ut32 name_off;
    ut32 offset_off;
    ut32 size_off;
} RGGPackRawEntry;

typedef struct {
    char * string;
    RGGPackRawEntry * raw_entry;
    int entry_offset;
    ut32 size;
} RGGPackIndexString;

typedef struct {
	char *file_name;
	ut32 offset;
	ut32 size;
	bool is_obfuscated;
    RGGPackRawEntry * tmp_raw;
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
    ut32 offset;
    bool wait_for_shift_and_rebuild_index;
    bool shifting_index;
} RIOGGPack;

#endif
