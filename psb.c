#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include <zlib.h>
#include <openssl/md5.h>

#include "mt19937.c"

int debug = 0; // use for debug outputs
int debug_filewrites = 0; // use for debug file writes

struct _type_value {
    uint8_t type;
    uint16_t value_length; // if value is an array, save its length here
    union value {
        struct _type_value *type_value_object;
        struct _type_value **type_value_array;
        struct _name_object **name_object_array;
        uint32_t integer;
        uint32_t *integer_array;
        uint64_t long_integer;
        float float_value;
        double double_value;
    } value;
};

struct _name_object {
    uint32_t name_index;
    struct _type_value *object;
    char *name_string;
};

struct _file_info {
    uint32_t name_index;
    uint64_t *offset; // pointer to the offset value in the psb_data struct
    uint64_t *length; // pointer to the length value in the psb_data struct
};

struct _psb_header {
	Byte signature[4];
	uint32_t type;
	uint32_t unknown1;
	uint32_t offset_names;
	uint32_t offset_strings;
	uint32_t offset_strings_data;
	uint32_t offset_chunk_offsets;
	uint32_t offset_chunk_lengths;
	uint32_t offset_chunk_data;
	uint32_t offset_entries;
};

// for easy re-packing
struct _original_psb_data {
    Byte *raw_names;
    uint32_t raw_names_size;
    Byte *raw_strings;
    uint32_t raw_strings_size;
};

struct _psb_data {
    struct _psb_header *header;
    char **names;
    uint32_t names_amount;
    char **strings;
    uint32_t strings_amount;
    Byte **chunkdata;
    uint32_t chunkdata_size;
    struct _type_value *entries; // type 33
    struct _file_info **file_info;
    uint32_t file_info_amount;
    Byte **subfile_data;
    struct _original_psb_data *raw_psb_data;
};

typedef struct _file_info file_info;
typedef struct _type_value type_value;
typedef struct _name_object name_object;
typedef struct _psb_header psb_header;
typedef struct _psb_data psb_data;
typedef struct _original_psb_data original_psb_data;


void free_psb_data(psb_data *my_psb_data)
{
    free(my_psb_data->header);

    for (int i = 0; i < my_psb_data->names_amount; i++) {
        free(my_psb_data->names[i]);
    }
    free(my_psb_data->names);

    for (int i = 0; i < my_psb_data->strings_amount; i++) {
        free(my_psb_data->strings[i]);
    }
    free(my_psb_data->strings);

    for (int i = 0; i < my_psb_data->chunkdata_size; i++) {
        free(my_psb_data->chunkdata[i]);
    }
    free(my_psb_data->chunkdata);

    for (int i = 0; i < my_psb_data->entries->value_length; i++) {
        if (my_psb_data->entries->value.name_object_array[i]) {
            name_object *current_typevalue = my_psb_data->entries->value.name_object_array[i];
            if (current_typevalue->object->type == 32) {
                free(current_typevalue->object->value.type_value_object);
            } else if (current_typevalue->object->type == 33) { // file_info object
                for (int j = 0; j < my_psb_data->file_info_amount; j++) {
                    free(current_typevalue->object->value.name_object_array[j]->object->value.type_value_array[0]); // relies on the knowledge that these arrays will contain exactly 2 elements
                    free(current_typevalue->object->value.name_object_array[j]->object->value.type_value_array[1]);
                    free(current_typevalue->object->value.name_object_array[j]->object->value.type_value_array);
                    free(current_typevalue->object->value.name_object_array[j]->object);
                    free(current_typevalue->object->value.name_object_array[j]);
                }
                free(current_typevalue->object->value.name_object_array);
            }
            free(current_typevalue->object);
            free(current_typevalue);
        }
    }
    free(my_psb_data->entries->value.name_object_array);
    free(my_psb_data->entries);

    for (int i = 0; i < my_psb_data->file_info_amount; i++) {
        free(my_psb_data->file_info[i]);
    }
    free(my_psb_data->file_info);

    for (int i = 0; i < my_psb_data->file_info_amount; i++) {
        free(my_psb_data->subfile_data[i]);
    }
    free(my_psb_data->subfile_data);

    free(my_psb_data->raw_psb_data->raw_names);
    free(my_psb_data->raw_psb_data->raw_strings);
    free(my_psb_data->raw_psb_data);

    free(my_psb_data);
}

// Modifies the provided data using an xor method that uses the basename of the provided filename
void xor_data(Byte *data, const char *file_name, int data_length)
{
    Byte xor_key[80];
    if (strcmp(&file_name[strlen(file_name) - 13], "alldata.psb.m") == 0) { // ez way out
        memcpy(xor_key, "\x3e\xa2\xcb\x35\xb4\x83\x46\xe9\x9a\xaf\xd1\xcc\xb4\x5e\x51\xd5\xe4\xa2\x64\x96\xb8\x23\x63\x1b\xfc\x49\xb6\x34\x93\xef\x93\x1b\x2b\x8f\x74\xf1\x1e\x10\x24\x80\x11\x8f\xda\xaf\xaf\xe6\x69\xc0\x8b\x18\xd5\xbd\x89\x8a\x0b\xf0\xa8\x5b\x8a\x8e\x58\x21\x8b\x17\x60\x9c\xd2\xe3\xc7\x5a\x22\xdd\xde\x7b\x23\xf2\x74\x3e\x47\x59", 80);
    } else {
        // we need to calculate the xor_key based on the file_name

        int i;
        for (i = strlen(file_name); i > 0; i--) { // figure out the basename
            if (file_name[i-1] == '/' || file_name[i-1] == '\\') {
                break;
            }
        }
        int basename_length = strlen(file_name) - i;
        char basename[basename_length];

        for (int j = 0; j < basename_length; j++) { // lower the basename
            basename[j] = tolower(file_name[i+j]);
        }

        Byte hash_seed[basename_length + 13];
        memcpy(hash_seed, "MX8wgGEJ2+M47", 13); // fixed seed part from m2engage.elf
        memcpy(&hash_seed[13], basename, basename_length);

        if (debug) {
            printf("Using hash seed: ");
            for (int i = 0; i < basename_length + 13; i++) {
                printf("%c", hash_seed[i]);
            }
            printf("\n");
        }

        Byte hash_bytes[16];
        MD5(hash_seed, basename_length + 13, hash_bytes); // generate the 16-byte MD5 of our hash_seed

        if (debug) {
            printf("md5 of hash seed: ");
            for (int i = 0; i < 16; i++) {
                printf(hash_bytes[i] < 127 && hash_bytes[i] > 31 ? "%c" : "\\x%02x", hash_bytes[i]);
            }
            printf("\n");
        }

        uint32_t hash_ints[4]; // convert it to 4 uint32_t values
        for (int i = 0; i < 4; i++) {
            memcpy(&hash_ints[i], &hash_bytes[4*i], 4);
        }

        init_by_array(hash_ints, 4); // initialize the mersenne twister

        for (int i = 0; i < 80; i += 4) {
            uint32_t returned_int = genrand_int32();
            memcpy(&xor_key[i], &returned_int, 4);
        }

        if (debug) {
            printf("Using xor key: ");
            for (int i = 0; i < 80; i++) {
                printf("%x", xor_key[i]);
            }
            printf("\n");
        }
    }

    for (int i = 0; i < data_length; i++) {
        data[i] ^= xor_key[i % 80];
    }
}


int get_unsigned_byte_size(uint64_t value)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if ((value >> i*8) != 0) {
            i--;
            break;
        }
    }
    return i + 2;
}


int get_signed_byte_size(uint64_t value)
{
    int i;
    for (i = 7; i >= 0; i--) {
        if ((value >> i*8) != 0) {
            if (!(value >> i*8 & 0x80)) {
                i--;
            }
            break;
        }
    }
    return i + 2;
}


// packs data from the type_value object to_pack and returns it, setting current_size to the amount of bytes packed
Byte *pack_data(psb_data *my_psb_data, type_value *to_pack, int *current_size)
{
    Byte *return_data;
    assert(current_size);
    uint8_t type = to_pack->type;

    if (debug) {
        printf("Now starting to pack type_value object with type %d.\n", type);
    }

    if (type == 0 || type > 33) {
        fprintf(stderr, "Error when packing: type_value has unknown type %d.\n", type);
        fprintf(stderr, "Will abort now.\n");
        exit(EXIT_FAILURE);
    }

    if (type <= 3) {
        // length = 0, purpose unknown

        return_data = malloc(1);
        *current_size = 1;
        return_data[0] = type;

    } else if (type <= 12) {
        // int, 0 - 8 bytes
        // it works, I hope; even if it looks weird

        int size = get_signed_byte_size(to_pack->value.long_integer);
        if (type == 4 && to_pack->value.long_integer == 0) { // I'm going to catch this manually, because if this value is 0, we probably have a 0 byte value (aka none)
            size = 0; // size would otherwise be 1 instead
        }

        return_data = malloc(size + 1);
        return_data[0] = size + 4;
        Byte *byte_pointer = (Byte *) &to_pack->value.long_integer;
        memcpy(&return_data[1], byte_pointer, size);

        *current_size = size + 1;

    } else if (type <= 20) {
        // array of ints, in the form "size of count, count, size of entries, entries[]"

        int size_count = get_unsigned_byte_size((uint64_t) to_pack->value_length);

        int largest_value = 0;
        for (int i = 0; i < to_pack->value_length; i++) {
            if (to_pack->value.integer_array[i] > largest_value) {
                largest_value = to_pack->value.integer_array[i];
            }
        }
        int size_entries = get_unsigned_byte_size((uint64_t) largest_value);

        return_data = malloc(1 + size_count + 1 + (size_entries * to_pack->value_length));
        return_data[0] = size_count + 12;
        memcpy(&return_data[1], &to_pack->value_length, size_count);
        return_data[1 + size_count] = size_entries + 12;

        *current_size = 1 + 1 + size_count;
        for (int i = 0; i < to_pack->value_length; i++) {
            memcpy(&return_data[*current_size], &to_pack->value.integer_array[i], size_entries);
            *current_size += size_entries;
        }

    } else if (type <= 24) {
        // index into strings array, 1-4 bytes

        int size = get_unsigned_byte_size((uint64_t) to_pack->value.integer);

        return_data = malloc(size + 1);
        return_data[0] = size + 20;
        Byte *byte_pointer = (Byte *) &to_pack->value.integer;
        memcpy(&return_data[1], byte_pointer, size);

        *current_size = size + 1;

    } else if (type <= 28) {
        // index into chunks array, 1-4 bytes

        int size = get_unsigned_byte_size((uint64_t) to_pack->value.integer);

        return_data = malloc(size + 1);
        return_data[0] = size + 20;
        Byte *byte_pointer = (Byte *) &to_pack->value.integer;
        memcpy(&return_data[1], byte_pointer, size);

        *current_size = size + 1;

    } else if (type == 29) {
        // 0 byte float

        return_data = malloc(1);
        *current_size = 1;
        return_data[0] = type;

    } else if (type == 30) {
        // 4 byte float

        return_data = malloc(5);
        *current_size = 5;
        return_data[0] = type;
        memcpy(&return_data[1], &to_pack->value.float_value, 4);

    } else if (type == 31) {
        // 8 byte double

        return_data = malloc(9);
        *current_size = 9;
        return_data[0] = type;
        memcpy(&return_data[1], &to_pack->value.double_value, 8);

    } else if (type == 32) {
        // array of type_values
        // array of offsets of objects, followed by the objects

        return_data = malloc(1);
        memcpy(return_data, &type, 1);
        *current_size = 1;

        int next_offset = 0;
        uint32_t *temp_offsets = malloc(to_pack->value_length * sizeof(uint32_t));
        Byte *temp_data = malloc(0);

        for (int i = 0; i < to_pack->value_length; i++) {
            int returned_size;
            Byte *returned_data = pack_data(my_psb_data, to_pack->value.type_value_array[i], &returned_size);

            if (debug) {
                for (int i = 0; i < returned_size; i++) {
                    printf("%02x ", returned_data[i]);
                }
                printf("\n");
            }

            temp_offsets[i] = next_offset;

            temp_data = realloc(temp_data, next_offset + returned_size);
            memcpy(&temp_data[next_offset], returned_data, returned_size);
            free(returned_data);
            next_offset += returned_size;
        }

        type_value *temp_offsets_typevalue = malloc(sizeof(type_value));
        temp_offsets_typevalue->type = 13;
        temp_offsets_typevalue->value_length = to_pack->value_length;
        temp_offsets_typevalue->value.integer_array = temp_offsets;

        int returned_count;
        Byte *wtf_offsets_temp = pack_data(my_psb_data, temp_offsets_typevalue, &returned_count);
        free(temp_offsets);
        free(temp_offsets_typevalue);
        return_data = realloc(return_data, *current_size + returned_count);
        memcpy(&return_data[*current_size], wtf_offsets_temp, returned_count);
        free(wtf_offsets_temp);
        *current_size += returned_count;

        return_data = realloc(return_data, *current_size + next_offset);
        memcpy(&return_data[*current_size], temp_data, next_offset);
        free(temp_data);
        *current_size += next_offset;
        if (debug) {
            for (int i = 0; i < *current_size; i++) {
                printf("%02x ", return_data[i]);
            }
            printf("\n");
        }

    } else if (type == 33) {
        // array of name_objects
        // array of int name indexes, array of int offsets, followed by objects

        return_data = malloc(1);
        memcpy(return_data, &type, 1);
        *current_size = 1;

        int next_offset = 0;
        uint32_t *temp_names = malloc(to_pack->value_length * sizeof(uint32_t));
        uint32_t *temp_offsets = malloc(to_pack->value_length * sizeof(uint32_t));
        Byte *temp_data = malloc(0);

        for (int i = 0; i < to_pack->value_length; i++) {
            if (debug) {
                printf("next offset: %d\n", next_offset);
            }
            int returned_size;
            Byte *returned_data = pack_data(my_psb_data, to_pack->value.name_object_array[i]->object, &returned_size);

            temp_names[i] = to_pack->value.name_object_array[i]->name_index;
            temp_offsets[i] = next_offset;

            temp_data = realloc(temp_data, next_offset + returned_size);
            memcpy(&temp_data[next_offset], returned_data, returned_size);
            free(returned_data);
            next_offset += returned_size;
        }

        type_value *temp_names_typevalue = malloc(sizeof(type_value));
        temp_names_typevalue->type = 13;
        temp_names_typevalue->value_length = to_pack->value_length;
        temp_names_typevalue->value.integer_array = temp_names;

        int returned_count;
        Byte *wtf_names_temp = pack_data(my_psb_data, temp_names_typevalue, &returned_count);
        free(temp_names);
        free(temp_names_typevalue);
        return_data = realloc(return_data, *current_size + returned_count);
        memcpy(&return_data[*current_size], wtf_names_temp, returned_count);
        free(wtf_names_temp);
        *current_size += returned_count;


        type_value *temp_offsets_typevalue = malloc(sizeof(type_value));
        temp_offsets_typevalue->type = 13;
        temp_offsets_typevalue->value_length = to_pack->value_length;
        temp_offsets_typevalue->value.integer_array = temp_offsets;

        Byte *wtf_offsets_temp = pack_data(my_psb_data, temp_offsets_typevalue, &returned_count);
        free(temp_offsets);
        free(temp_offsets_typevalue);
        return_data = realloc(return_data, *current_size + returned_count);
        memcpy(&return_data[*current_size], wtf_offsets_temp, returned_count);
        free(wtf_offsets_temp);
        *current_size += returned_count;

        return_data = realloc(return_data, *current_size + next_offset);
        memcpy(&return_data[*current_size], temp_data, next_offset);
        free(temp_data);
        *current_size += next_offset;
    }

    return return_data;
}


// Returns a malloc'd type_value object, based on the given pointer.
// my_psb_data and return_count are used internally idk what the fuck to put here
type_value *extract_data(psb_data *my_psb_data, Byte **pointer, uint32_t *return_count)
{
    uint8_t type;
    memcpy(&type, *pointer, 1);
    (*pointer)++;

    if (debug) {
        printf("Current offset value: %d\n", type);
    }

    if (type == 0 || type > 33) {
        fprintf(stderr, "Error when extracting: Unknown type %d.\n", type);
        fprintf(stderr, "will exit now just in case.");
        exit(EXIT_FAILURE);
    }

    type_value *return_type_value = malloc(sizeof(type_value));
    return_type_value->type = type;

    if (type <= 3) {
        // length = 0, purpose unknown

        return_type_value->value.long_integer = 0L;

    } else if (type <= 12) {
        // long, 0-8 bytes

        return_type_value->value.long_integer = 0L;
        memcpy(&return_type_value->value.long_integer, *pointer, type - 4);

    } else if (type <= 20) {
        // array of ints, in the form "size of count, count, size of entries, entries[]"

        int count_size = type - 12;
        uint32_t count = 0;
        memcpy(&count, *pointer, count_size);
        *pointer += count_size;

        int size_entries = 0;
        memcpy(&size_entries, *pointer, 1);
        size_entries -= 12;
        (*pointer)++;
        if (debug) {
            printf("count: %d, size entries: %d\n", count, size_entries);
        }

        return_type_value->value_length = count;
        return_type_value->value.integer_array = calloc(1, sizeof(uint32_t) * count);
        for (int i = 0; i < count; i++) {
            memcpy(&return_type_value->value.integer_array[i], *pointer, size_entries);
            *pointer += size_entries;
        }

        if (debug) {
            printf("Debug array output:\n");
            if (count) { // make sure we actually have at least one element
                printf("%d", return_type_value->value.integer_array[0]);
            }
            for (int i = 1; i < count; i++) {
                printf(", %d", return_type_value->value.integer_array[i]);
            }
            printf("\n");
        }

    } else if (type <= 24) {
        // index into strings array, 1-4 bytes

        return_type_value->value.integer = 0;  // initialization
        memcpy(&return_type_value->value.integer, *pointer, type - 20);

    } else if (type <= 28) {
        // index into chunk array, 1-4 bytes
        // warning: so far untested

        return_type_value->value.integer = 0;  // initialization
        memcpy(&return_type_value->value.integer, *pointer, type - 24);

    } else if (type == 29) {
        // float, 0 bytes?

        return_type_value->value.float_value = 0.0f; // just set it to 0 w/e

    } else if (type == 30) {
        // float, 4 bytes

        memcpy(&return_type_value->value.float_value, *pointer, 4);
        (*pointer) += 4; // The pointer probably isn't used by the calling function, but we'll set it for consistency

    } else if (type == 31) {
        // double, 8 bytes

        memcpy(&return_type_value->value.double_value, *pointer, 8);
        (*pointer) += 8; // The pointer probably isn't used by the calling function, but we'll set it for consistency

    } else if (type == 32) {
        // array of objects
        // array of offsets of objects, followed by the objects

        type_value *offsets = extract_data(NULL, pointer, NULL);

        return_type_value->value_length = offsets->value_length;
        return_type_value->value.type_value_array = malloc(offsets->value_length * sizeof(type_value *));
        Byte *new_pointer;
        for (int i = 0; i < offsets->value_length; i++) {
            int o = offsets->value.integer_array[i];

            new_pointer = (*pointer) + o;
            type_value *v1 = extract_data(NULL, &new_pointer, NULL);
            return_type_value->value.type_value_array[i] = v1;
        }
        free(offsets->value.integer_array);
        free(offsets);

    } else if (type == 33) {
        // array of name-objects
        // array of int name indexes, array of int offsets, followed by objects

        assert(my_psb_data);

        type_value *names = extract_data(NULL, pointer, NULL);
        type_value *offsets = extract_data(NULL, pointer, NULL);

        if (debug) {
            for (int i = 0; i < names->value_length; i++) {
                printf("name string[%d]: %s\n", i, my_psb_data->names[names->value.integer_array[i]]);
            }
            for (int i = 0; i < offsets->value_length; i++) {
                printf("offsets[%d]: %d\n", i, offsets->value.integer_array[i]);
            }
        }

        assert(names->value_length == offsets->value_length);

        _Bool is_file_info = 0;
        if (return_count && *return_count == 1) {
            is_file_info = 1;
            printf("FILE INFO DETECTED!\n");
            my_psb_data->file_info = malloc(names->value_length * sizeof(file_info));
            my_psb_data->file_info_amount = names->value_length;
        }

        return_type_value->value_length = names->value_length;
        return_type_value->value.name_object_array = malloc(names->value_length * sizeof(name_object *));

        uint32_t pass_value = 0;
        Byte *new_pointer;
        for (int i = 0; i < names->value_length; i++) {
            if (strcmp(my_psb_data->names[names->value.integer_array[i]], "file_info") == 0) {
                pass_value = 1;
            }
            name_object *this_name_object = malloc(sizeof(name_object));
            this_name_object->name_index = names->value.integer_array[i];
            if (debug) {
                printf("Currently unpacking information for entry \"%s\".\n", my_psb_data->names[this_name_object->name_index]);
            }

            new_pointer = (*pointer) + offsets->value.integer_array[i];

            this_name_object->object = extract_data(my_psb_data, &new_pointer, &pass_value);
            this_name_object->name_string = my_psb_data->names[this_name_object->name_index];

            return_type_value->value.name_object_array[i] = this_name_object;

            if (is_file_info) {
                // sanity check the file_info object
                assert(this_name_object->object->type == 32);
                assert(this_name_object->object->value_length == 2);
                assert(this_name_object->object->value.type_value_array[0]->type >= 4);
                assert(this_name_object->object->value.type_value_array[0]->type <= 12);
                assert(this_name_object->object->value.type_value_array[1]->type >= 4);
                assert(this_name_object->object->value.type_value_array[1]->type <= 12);

                file_info *new_file_info = malloc(sizeof(file_info));

                new_file_info->name_index = names->value.integer_array[i];
                new_file_info->offset = &this_name_object->object->value.type_value_array[0]->value.long_integer;
                new_file_info->length = &this_name_object->object->value.type_value_array[1]->value.long_integer;

                my_psb_data->file_info[i] = new_file_info;
            }
        }
        free(names->value.integer_array);
        free(names);
        free(offsets->value.integer_array);
        free(offsets);
    }

    return return_type_value;
}


void pack_bin(psb_data *my_psb_data, const char *out_file)
{
    char out_bin_name[strlen(out_file) - 1];
    strncpy(out_bin_name, out_file, strlen(out_file) - 5);
    memcpy(&out_bin_name[strlen(out_file) - 5], "bin", 4);

    FILE *out_bin_file = fopen(out_bin_name, "wb");
    if (out_bin_file == NULL) {
        fprintf(stderr, "Error: Couldn't open output bin file (%s). Will now terminate.\n", out_bin_name);
        exit(EXIT_FAILURE);
    }
    printf("Writing out bin file \"%s\".\n", out_bin_name);

    Byte *null_data = calloc(1, 2048);
    for (int i = 0; i < my_psb_data->file_info_amount; i++) {
        fwrite(my_psb_data->subfile_data[i], *my_psb_data->file_info[i]->length, 1, out_bin_file);
        if (*my_psb_data->file_info[i]->length % 2048 != 0) {
            fwrite(null_data, 2048 - (*my_psb_data->file_info[i]->length % 2048), 1, out_bin_file);
        }
    }
    free(null_data);

    fclose(out_bin_file);
}


void pack_psb(psb_data *my_psb_data, const char *out_name)
{
    Byte *injected_psb_data = malloc(40);
    uint32_t injected_psb_data_size = 40;
    printf("Writing out psb.m file \"%s\".\n", out_name);

    // We will pack in a relatively lazy way, by re-using raw data saved earlier
    // everything should still work perfectly fine though

    // I will pack the header later, as to avoid duplicate packing because of a potential offset difference due to a difference in file size

    // pack_names function
    // instead of packing manually, we just use our raw_names
    injected_psb_data = realloc(injected_psb_data, injected_psb_data_size + my_psb_data->raw_psb_data->raw_names_size);
    memcpy(&injected_psb_data[injected_psb_data_size], my_psb_data->raw_psb_data->raw_names, my_psb_data->raw_psb_data->raw_names_size);
    injected_psb_data_size += my_psb_data->raw_psb_data->raw_names_size;

    // pack_entries function
    int size_entry_data = 0;
    Byte *entry_data = pack_data(my_psb_data, my_psb_data->entries, &size_entry_data);
    injected_psb_data = realloc(injected_psb_data, injected_psb_data_size + size_entry_data);
    memcpy(&injected_psb_data[injected_psb_data_size], entry_data, size_entry_data);
    free(entry_data);
    injected_psb_data_size += size_entry_data;

    uint8_t offset_difference = abs(injected_psb_data_size - my_psb_data->header->offset_strings);
    if (offset_difference > 0) {
        printf("updating offsets; filesize differs by %d.\n", offset_difference);
        if (offset_difference > 1) {
            fprintf(stderr, "The filesize difference was larger than 1. I believe that this should not happen. If issues occur, it's likely due to this.\n");
        }
        my_psb_data->header->offset_strings += offset_difference;
        my_psb_data->header->offset_strings_data += offset_difference;
        my_psb_data->header->offset_chunk_offsets += offset_difference;
        my_psb_data->header->offset_chunk_lengths += offset_difference;
        my_psb_data->header->offset_chunk_data += offset_difference;
    }

    // pack_strings function
    // we'll use our raw strings again
    injected_psb_data = realloc(injected_psb_data, injected_psb_data_size + my_psb_data->raw_psb_data->raw_strings_size);
    memcpy(&injected_psb_data[injected_psb_data_size], my_psb_data->raw_psb_data->raw_strings, my_psb_data->raw_psb_data->raw_strings_size);
    injected_psb_data_size += my_psb_data->raw_psb_data->raw_strings_size;

    // pack_chunks function
    // because I believe alldata.psbs ALWAYS have absolutely no chunk data, we will append the according "empty" bytes
    injected_psb_data = realloc(injected_psb_data, injected_psb_data_size + 6);
    memcpy(&injected_psb_data[injected_psb_data_size], "\x0d\x00\x0d\x0d\x00\x0d", 6);
    injected_psb_data_size += 6;
    printf("injected (uncompressed) psb size: %d\n", injected_psb_data_size);

    // we will pack the header now
    memcpy(injected_psb_data, my_psb_data->header->signature, 4);
    memcpy(&injected_psb_data[4], &my_psb_data->header->type, 4);
    memcpy(&injected_psb_data[8], &my_psb_data->header->unknown1, 4);
    memcpy(&injected_psb_data[12], &my_psb_data->header->offset_names, 4);
    memcpy(&injected_psb_data[16], &my_psb_data->header->offset_strings, 4);
    memcpy(&injected_psb_data[20], &my_psb_data->header->offset_strings_data, 4);
    memcpy(&injected_psb_data[24], &my_psb_data->header->offset_chunk_offsets, 4);
    memcpy(&injected_psb_data[28], &my_psb_data->header->offset_chunk_lengths, 4);
    memcpy(&injected_psb_data[32], &my_psb_data->header->offset_chunk_data, 4);
    memcpy(&injected_psb_data[36], &my_psb_data->header->offset_entries, 4);

    if (debug_filewrites) {
        FILE *debug_file = fopen("__injected_uncompressed_psb_data.psb", "wb");
        if (debug_file == NULL) {
            fprintf(stderr, "Error when opening injected psb output file.\n");
            exit(EXIT_FAILURE);
        }
        fwrite(injected_psb_data, injected_psb_data_size, 1, debug_file);
        fclose(debug_file);
    }

    uLongf compressed_size = compressBound(injected_psb_data_size);
    Byte *compressed_injected_psb_data = malloc(8 + compressed_size);
    memcpy(compressed_injected_psb_data, "mdf\x00", 4);
    memcpy(&compressed_injected_psb_data[4], &injected_psb_data_size, 4);
    int return_value = compress2(&compressed_injected_psb_data[8], &compressed_size, injected_psb_data, injected_psb_data_size, 9);
    if (return_value != Z_OK) {
        fprintf(stderr, "Error when compressing final psb.m file. The return code was %d. Will now exit.\n", return_value);
        exit(EXIT_FAILURE);
    }
    free(injected_psb_data);

    printf("injected compressed psb size: %lu (+8 for the header)\n", compressed_size);
    compressed_injected_psb_data = realloc(compressed_injected_psb_data, compressed_size + 8);
    xor_data(&compressed_injected_psb_data[8], "alldata.psb.m", compressed_size);

    FILE *out_psb_file = fopen(out_name, "wb");
    if (out_psb_file == NULL) {
        fprintf(stderr, "Couldn't open output file (%s). Will now terminate.", out_name);
        exit(EXIT_FAILURE);
    }

    fwrite(compressed_injected_psb_data, compressed_size + 8, 1, out_psb_file);
    free(compressed_injected_psb_data);
    fclose(out_psb_file);
}


psb_data *load_from_psb(const char *psb_filename)
{
    FILE *in_psb_file = fopen(psb_filename, "rb");
    if (in_psb_file == NULL) {
        fprintf(stderr, "major error i guess\n");
        exit(EXIT_FAILURE);
    }

    // figure out the length of the file, to allocate the exact amount of needed memory
    fseek(in_psb_file, 0, SEEK_END);
    int file_size = ftell(in_psb_file);
    rewind(in_psb_file);

    Byte *file_contents = malloc(file_size);
    assert(fread(file_contents, 1, file_size, in_psb_file) == file_size);
    printf("original (compressed) psb size: %d\n", file_size);
    fclose(in_psb_file); // contents read in, we no longer need the file stream

    if (!(file_size >= 4 && memcmp(file_contents, "mdf\x00", 4) == 0)) {
        fprintf(stderr, "Error: Input file does not have the correct signature.\n");
        exit(EXIT_FAILURE);
    } else {
        printf("Signature correct.\n");
    }

    _Bool is_psb_m = 1; // will be needed much later
    Byte *raw_psb_data;
    if ((strlen(psb_filename) >= 4) && (strcmp(&psb_filename[strlen(psb_filename) - 4], ".psb") == 0)) {
        raw_psb_data = file_contents; // file ends with ".psb", no fancy decrypting needed apparently
        is_psb_m = 0;
    } else {
        // decrypt data
        xor_data(&file_contents[8], psb_filename, file_size - 8);

        // uncompress data
        uLongf uncompressed_size = 0;
        memcpy(&uncompressed_size, &file_contents[4], 4);

        raw_psb_data = malloc(uncompressed_size);
        int return_value = uncompress(raw_psb_data, &uncompressed_size, &file_contents[8], file_size - 8);
        if (return_value != Z_OK) {
            fprintf(stderr, "MAJOR error was occuring here; the entire uncompressing failed.\n");
            fprintf(stderr, "return_value: %d\n", return_value);
            exit(EXIT_FAILURE);
        }
        printf("original uncompressed psb size: %ld\n", uncompressed_size);
        free(file_contents);

        if (debug_filewrites) {
            FILE *out_file = fopen("__original_uncompressed_psb_data.psb", "wb");
            if (out_file == NULL) {
                fprintf(stderr, "Error when opening uncompressed psb output file. Will now terminate.\n");
                exit(EXIT_FAILURE);
            }
            fwrite(raw_psb_data, uncompressed_size, 1, out_file);
            fclose(out_file);
        }
    }


    // read in the psb header into our psb_header struct
    psb_header *my_psb_header = malloc(sizeof(psb_header));
    memcpy(&my_psb_header->signature, raw_psb_data, 4);
    memcpy(&my_psb_header->type, &raw_psb_data[4], 4);
    memcpy(&my_psb_header->unknown1, &raw_psb_data[8], 4);
    memcpy(&my_psb_header->offset_names, &raw_psb_data[12], 4);
    memcpy(&my_psb_header->offset_strings, &raw_psb_data[16], 4);
    memcpy(&my_psb_header->offset_strings_data, &raw_psb_data[20], 4);
    memcpy(&my_psb_header->offset_chunk_offsets, &raw_psb_data[24], 4);
    memcpy(&my_psb_header->offset_chunk_lengths, &raw_psb_data[28], 4);
    memcpy(&my_psb_header->offset_chunk_data, &raw_psb_data[32], 4);
    memcpy(&my_psb_header->offset_entries, &raw_psb_data[36], 4);

    // read in all psb data into our psb_data struct
    psb_data *my_psb_data = malloc(sizeof(psb_data));
    my_psb_data->header = my_psb_header;
    original_psb_data *my_original_psb_data = malloc(sizeof(original_psb_data));
    Byte *current_position = &raw_psb_data[my_psb_header->offset_names];
    type_value *temp; // temporary buffer to avoid memory leaks


    // unpack_names function
    temp = extract_data(NULL, &current_position, NULL);
    uint32_t *offsets = temp->value.integer_array;
    free(temp);
    temp = extract_data(NULL, &current_position, NULL);
    uint32_t *jumps = temp->value.integer_array;
    free(temp);
    type_value *starts = extract_data(NULL, &current_position, NULL);

    my_psb_data->names = malloc(starts->value_length * sizeof(char *));
    char temp_string[255];
    my_psb_data->names_amount = starts->value_length;

    // not my algorithm, still have to understand what it does
    if (debug) {
        printf("Started deciphering the file names...\n");
    }
    for (int i = 0; i < starts->value_length; i++) {
        uint32_t a = starts->value.integer_array[i];

        int j;
        for (j = 0; a != 0; j++) {
            uint32_t b = jumps[a];
            uint32_t c = offsets[b];

            int d = a - c;
            if (d < 0) {
                fprintf(stderr, "Error: this shouldn't happen.\n");
                exit(EXIT_FAILURE);
            }
            temp_string[j] = d;

            a = b;
        }

        my_psb_data->names[i] = malloc(j);
        j--;
        for (int k = j; j >= 0; j--) { // reverse the string and save it in the struct
            my_psb_data->names[i][j] = temp_string[k-j];
        }
        if (debug) {
            printf("%03d: %s\n", i, my_psb_data->names[i]);
        }
    }
    // save the raw byte-data as raw_names for easier access when packing later
    my_original_psb_data->raw_names_size = (uint64_t) current_position - (uint64_t) &raw_psb_data[my_psb_data->header->offset_names];
    my_original_psb_data->raw_names = malloc(my_original_psb_data->raw_names_size);
    memcpy(my_original_psb_data->raw_names, &raw_psb_data[my_psb_data->header->offset_names], my_original_psb_data->raw_names_size);
    free(offsets);
    free(jumps);
    free(starts->value.integer_array);
    free(starts);


    // unpack_strings function
    if (debug) {
        printf("Started unpacking strings...\n");
    }
    current_position = &raw_psb_data[my_psb_data->header->offset_strings];
    type_value *string_offsets = extract_data(NULL, &current_position, NULL);

    current_position = &raw_psb_data[my_psb_data->header->offset_strings_data];
    my_psb_data->strings = malloc(string_offsets->value_length * sizeof(char *));
    my_psb_data->strings_amount = string_offsets->value_length;

    for (int i = 0; i < string_offsets->value_length; i++) {
        current_position = &raw_psb_data[my_psb_data->header->offset_strings_data] + string_offsets->value.integer_array[i];
        my_psb_data->strings[i] = malloc(strlen((char *) current_position) + 1);
        strcpy(my_psb_data->strings[i], (char *) current_position);
        if (debug) {
            printf("string at offset %d: \"%s\"\n", i,  my_psb_data->strings[i]);
        }
    }
    // save the raw byte-data as raw_strings for easier access when packing later
    my_original_psb_data->raw_strings_size = (uint64_t) current_position - (uint64_t) &raw_psb_data[my_psb_data->header->offset_strings] + strlen((char *) current_position) + 1;
    my_original_psb_data->raw_strings = malloc(my_original_psb_data->raw_strings_size);
    memcpy(my_original_psb_data->raw_strings, &raw_psb_data[my_psb_data->header->offset_strings], my_original_psb_data->raw_strings_size);
    free(string_offsets->value.integer_array);
    free(string_offsets);


    // unpack_chunks function
    current_position = &raw_psb_data[my_psb_header->offset_chunk_offsets];
    type_value *chunk_offsets = extract_data(NULL, &current_position, NULL);
    my_psb_data->chunkdata_size = chunk_offsets->value_length;

    current_position = &raw_psb_data[my_psb_header->offset_chunk_lengths];
    type_value *chunk_lengths = extract_data(NULL, &current_position, NULL);

    current_position = &raw_psb_data[my_psb_header->offset_chunk_data];
    if (chunk_offsets->value_length == 0) {
        my_psb_data->chunkdata = NULL;
    }
    for (int i = 0; i < chunk_offsets->value_length; i++) {
        my_psb_data->chunkdata = malloc(chunk_lengths->value_length * sizeof(Byte *));
        my_psb_data->chunkdata[i] = malloc(chunk_lengths->value.integer_array[i]);
        memcpy(&my_psb_data->chunkdata[i], current_position, chunk_offsets->value.integer_array[i]);
    }
    free(chunk_lengths->value.integer_array);
    free(chunk_lengths);
    free(chunk_offsets->value.integer_array);
    free(chunk_offsets);


    // unpack_entries function
    // takes around 0.1 seconds
    current_position = &raw_psb_data[my_psb_header->offset_entries];
    my_psb_data->entries = extract_data(my_psb_data, &current_position, NULL);

    // Debug file_info output
    if (debug) {
        printf("file info before rom injection:\n");
        for (int i = 0; i < my_psb_data->file_info_amount; i++) {
            printf("file_info[%03d]: (name_index = %3u, offset = %8lu, length = %7lu); string = \"%s\"\n", i, my_psb_data->file_info[i]->name_index, *my_psb_data->file_info[i]->offset, *my_psb_data->file_info[i]->length, my_psb_data->names[my_psb_data->file_info[i]->name_index]);
        }
    }

    free(raw_psb_data);


    // start reading in the bin file
    int bin_basename_length;
    if (is_psb_m) {
        bin_basename_length = strlen(psb_filename) - 6; // ends with ".psb.m"
    } else {
        bin_basename_length = strlen(psb_filename) - 4; // ends with ".psb"
    }

    char bin_name[bin_basename_length + 5]; // additional space for ".bin" and '\0'
    memcpy(bin_name, psb_filename, bin_basename_length);
    strcpy(&bin_name[bin_basename_length], ".bin");
    printf("Reading in bin file \"%s\".\n", bin_name);

    FILE *bin_file = fopen(bin_name, "rb");
    if (bin_file == NULL) {
        fprintf(stderr, "corresponding \".bin\" file doesn't exist. Imma just kill the program now.\n");
        exit(EXIT_FAILURE);
    }

    // read the bin data into the psb_data->subfile_data
    my_psb_data->subfile_data = malloc(my_psb_data->file_info_amount * sizeof(Byte *));
    for (int i = 0; i < my_psb_data->file_info_amount; i++) {
        Byte *this_subfile_data = malloc(*my_psb_data->file_info[i]->length);
        fseek(bin_file, *my_psb_data->file_info[i]->offset, SEEK_SET);
        assert(fread(this_subfile_data, 1, *my_psb_data->file_info[i]->length, bin_file) == *my_psb_data->file_info[i]->length);
        my_psb_data->subfile_data[i] = this_subfile_data;
    }
    fclose(bin_file);

    my_psb_data->raw_psb_data = my_original_psb_data;
    return my_psb_data;
}


void read_rom(psb_data *my_psb_data, const char *rom_name)
{
    printf("Reading in rom file \"%s\".\n", rom_name);

    for (int i = 0; i < my_psb_data->file_info_amount; i++) {
        char *current_name = my_psb_data->names[my_psb_data->file_info[i]->name_index];
        if (strncmp(current_name, "system/roms/", 12) == 0) {
            // replace that (rom) subfile with the rom to inject

            FILE *in_rom_file = fopen(rom_name, "rb");
            if (in_rom_file == NULL) {
                fprintf(stderr, "um idk what the fuck but that rom file can not be loaded in.\n");
                exit(EXIT_FAILURE);
            }

            // figure out the length of the file, to allocate the exact amount of needed memory
            fseek(in_rom_file, 0, SEEK_END);
            int file_size = ftell(in_rom_file);
            rewind(in_rom_file);
            printf("file size of rom: %d\n", file_size);

            uLongf final_size = compressBound(file_size);
            if (final_size + 8 > *my_psb_data->file_info[i]->length) { // need to realloc to make absolutely sure we compress only to initialized memory
                my_psb_data->subfile_data[i] = realloc(my_psb_data->subfile_data[i], final_size + 8);
            }
            assert(fread(&my_psb_data->subfile_data[i][8], 1, file_size, in_rom_file) == file_size);
            fclose(in_rom_file); // contents read in, we no longer need the file stream

            printf("Started compressing rom file...\n");
            int return_value = compress2(&my_psb_data->subfile_data[i][8], &final_size, my_psb_data->subfile_data[i], file_size, 9);
            if (return_value != Z_OK) {
                fprintf(stderr, "Error when compressing rom file. The return code was %d. Will now exit.\n", return_value);
                exit(EXIT_FAILURE);
            }
            printf("Rom compression finished.\n");
            printf("compressed rom size: %lu\n", final_size);
            my_psb_data->subfile_data[i] = realloc(my_psb_data->subfile_data[i], final_size + 8); // will probably be much lower, so we save space
            memcpy(my_psb_data->subfile_data[i], "mdf\x00", 4);
            memcpy(&my_psb_data->subfile_data[i][4], &file_size, 4);

            xor_data(&my_psb_data->subfile_data[i][8], current_name, final_size);
            *my_psb_data->file_info[i]->length = final_size + 8; // all offsets are potentially broken rn, so we need to fix them up below

            break;
        }
    }

    for (int i = 0; i < my_psb_data->file_info_amount - 1; i++) {
        uint64_t next_offset = *my_psb_data->file_info[i+1]->offset;

        // our current offset is already correct because of the last pass (or it's 0, which is always correct)
        uint64_t potential_next_offset = *my_psb_data->file_info[i]->offset + *my_psb_data->file_info[i]->length;
        if (next_offset < potential_next_offset || potential_next_offset + 2048 <= next_offset) {
            // 1. the next offset will have to be bumped, the current length is too high to fit ||
            // 2. the next offset will have to be lowered, it's too high for our smaller length

            if (potential_next_offset % 2048 == 0) {
                *my_psb_data->file_info[i+1]->offset = potential_next_offset;
            } else {
                *my_psb_data->file_info[i+1]->offset = ((potential_next_offset / 2048) + 1) * 2048;
            }
        }
    }

    // Debug file_info output
    if (debug) {
        printf("file info after rom injection:\n");
        for (int i = 0; i < my_psb_data->file_info_amount; i++) {
            printf("file_info[%03d]: (name_index = %3u, offset = %8lu, length = %7lu); string = \"%s\"\n", i, my_psb_data->file_info[i]->name_index, *my_psb_data->file_info[i]->offset, *my_psb_data->file_info[i]->length, my_psb_data->names[my_psb_data->file_info[i]->name_index]);
        }
    }
}


int main(int argc, char **argv)
{
    if (argc != 4) {
        printf("Syntax: ./psb.exe <psb.m to inject into> <rom to inject> <output psb.m>\n");
        exit(0);
    }
    if (strcmp(&argv[3][strlen(argv[3]) - 6], ".psb.m") != 0) {
        printf("please just use a file with a \".psb.m\" ending for now.\n");
        exit(0);
    }

    // checks for sanity
    // printf("sizeof(type_value): %lu (%d expected)\n", sizeof(type_value), 16);
    // printf("sizeof(name_object): %lu (%d expected)\n", sizeof(name_object), 24);
    // printf("sizeof(file_info): %lu (%d expected)\n", sizeof(file_info), 24);
    // printf("sizeof(psb_header): %lu (%d expected)\n", sizeof(psb_header), 40);
    // printf("sizeof(psb_data): %lu (%d expected)\n", sizeof(psb_data), 104);
    // printf("sizeof(int): %lu (%d expected)\n", sizeof(int), 4);
    // printf("sizeof(long): %lu (%d expected)\n", sizeof(long), 8);
    // printf("sizeof(float): %lu (%d expected)\n", sizeof(float), 4);
    // printf("sizeof(double): %lu (%d expected)\n", sizeof(double), 8);
    // exit(0);

    psb_data *mypsb = load_from_psb(argv[1]);

    read_rom(mypsb, argv[2]);

    pack_psb(mypsb, argv[3]);
    pack_bin(mypsb, argv[3]);

    printf("Injection finished.\n");
    free_psb_data(mypsb);
}
