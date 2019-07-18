/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _LARGEFILE64_SOURCE
#include <libgen.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ext2fs/ext2fs.h>
#include <et/com_err.h>

// --------------------------------------------------------------------------------------------

#include <sys/types.h>
#include <linux/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Used to retry syscalls that can return EINTR. */
#define TEMP_FAILURE_RETRY(exp) ({         \
    __typeof__(exp) _rc;                   \
    do {                                   \
        _rc = (exp);                       \
    } while (_rc == -1 && errno == EINTR); \
    _rc; })

typedef struct sparse_header {
    __le32 magic;            /* 0xed26ff3a */
    __le16 major_version;    /* (0x1) - reject images with higher major versions */
    __le16 minor_version;    /* (0x0) - allow images with higer minor versions */
    __le16 file_hdr_sz;      /* 28 bytes for first revision of the file format */
    __le16 chunk_hdr_sz;     /* 12 bytes for first revision of the file format */
    __le32 blk_sz;           /* block size in bytes, must be a multiple of 4 (4096) */
    __le32 total_blks;       /* total blocks in the non-sparse output image */
    __le32 total_chunks;     /* total chunks in the sparse input image */
    __le32 image_checksum;   /* CRC32 checksum of the original data, counting "don't care" */
    /* as 0. Standard 802.3 polynomial, use a Public Domain */
    /* table implementation */
} sparse_header_t;

#define SPARSE_HEADER_MAGIC    0xed26ff3a

#define CHUNK_TYPE_RAW         0xCAC1
#define CHUNK_TYPE_FILL        0xCAC2
#define CHUNK_TYPE_DONT_CARE   0xCAC3
#define CHUNK_TYPE_CRC32       0xCAC4

typedef struct chunk_header {
    __le16 chunk_type;  /* 0xCAC1 -> raw; 0xCAC2 -> fill; 0xCAC3 -> don't care */
    __le16 reserved1;
    __le32 chunk_sz;    /* in blocks in output image */
    __le32 total_sz;    /* in bytes of chunk input file including chunk header and data */
} chunk_header_t;

/* Following a Raw or Fill or CRC32 chunk is data.
 *  For a Raw chunk, it's the data in chunk_sz * blk_sz.
 *  For a Fill chunk, it's 4 bytes of the fill data.
 *  For a CRC32 chunk, it's 4 bytes of CRC32
 */

static int sparse_write_header(int fd, __le32 total_blks, __le32 total_chunks) {
    // static_assert(sizeof(sparse_header_t) == 28, "BOOM");
    // static_assert(sizeof(chunk_header_t) == 12, "BOOM");
    if (lseek64(fd, 0, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking output file %s\n", strerror(errno));
        return 0;
    }
    sparse_header_t header = { SPARSE_HEADER_MAGIC, 1, 0, sizeof(sparse_header_t),
                              sizeof(chunk_header_t), 4096, total_blks, total_chunks, 0 };
    return TEMP_FAILURE_RETRY(write(fd, &header, sizeof(sparse_header_t))) == sizeof(sparse_header_t);
}

static int sparse_write_dont_care_chunk(int fd, __le32 blocks) {
    chunk_header_t chunk = { CHUNK_TYPE_DONT_CARE, 0, blocks, sizeof(chunk_header_t) };
    return TEMP_FAILURE_RETRY(write(fd, &chunk, sizeof(chunk_header_t))) == sizeof(chunk_header_t);
}

static int sparse_write_raw_chunk(int fd, int in, int64_t offset, size_t len) {
    if ((len % 4096) != 0) {
        fprintf(stderr, "Not a multiple of the block size 4096 vs %zu\n", len);
        return 0;
    }

    if (lseek64(in, offset, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking input file %s\n", strerror(errno));
        return 0;
    }

    __le32 blocks = (__le32)(len / 4096);

    chunk_header_t chunk = { CHUNK_TYPE_RAW, 0, blocks, sizeof(chunk_header_t) + len };
    if (TEMP_FAILURE_RETRY(write(fd, &chunk, sizeof(chunk_header_t))) != sizeof(chunk_header_t)) {
        fprintf(stderr, "Error writing raw chunk %s\n", strerror(errno));
        return 0;
    }

    static char buffer[1024 * 4096];
    size_t max_read = len >= sizeof(buffer) ? sizeof(buffer) : len;
    ssize_t r;
    while ((r = TEMP_FAILURE_RETRY(read(in, buffer, max_read))) > 0) {
        if (TEMP_FAILURE_RETRY(write(fd, buffer, (size_t)r)) != r) {
            fprintf(stderr, "Error writing raw chunk %s", strerror(errno));
            return -1;
        }
        len -= r;
        if (len <= 0) {
            break;
        }
        max_read = len >= sizeof(buffer) ? sizeof(buffer) : len;
    }

    return 1;
}

// --------------------------------------------------------------------------------------------

struct {
    int   verbose;
    char *in_file;
    char *out_file;
} params = {
    .verbose = 0,
};

#define ext2fs_fatal(Retval, Format, ...) \
	do { \
		com_err("error", Retval, Format, __VA_ARGS__); \
		exit(EXIT_FAILURE); \
	} while(0)

#define sparse_fatal(Format) \
	do { \
		fprintf(stderr, "sparse: "Format); \
		exit(EXIT_FAILURE); \
	} while(0)

static void usage(char *path) {
    char *progname = basename(path);

    fprintf(stderr, "%s [ options ] <image or block device> <output image>\n", progname);
}

static void ext_to_sparse(const char *in_file, int in_fd, int out_fd) {
	if (sparse_write_header(out_fd, 0, 0) == 0) {
		ext2fs_fatal(errno, "sparse_write_header %d", errno);
	}

	errcode_t retval;
	ext2_filsys fs;
	blk_t first_blk, last_blk, nb_blk, cur_blk;

	retval = ext2fs_open(in_file, 0, 0, 0, unix_io_manager, &fs);
	if (retval)
		ext2fs_fatal(retval, "while reading %s", in_file);

	retval = ext2fs_read_block_bitmap(fs);
	if (retval)
		ext2fs_fatal(retval, "while reading block bitmap of %s", in_file);

	first_blk = ext2fs_get_block_bitmap_start2(fs->block_map);
	last_blk = ext2fs_get_block_bitmap_end2(fs->block_map);
	nb_blk = last_blk - first_blk + 1;

	if (fs->blocksize != 4096) {
		ext2fs_fatal(errno, "fs->blocksize != 4096 vs %d", fs->blocksize);
	}

	/*
	 * The sparse format encodes the size of a chunk (and its header) in a
	 * 32-bit unsigned integer (UINT32_MAX)
	 * When writing the chunk, the library uses a single call to write().
	 * Linux's implementation of the 'write' syscall does not allow transfers
	 * larger than INT32_MAX (32-bit _and_ 64-bit systems).
	 * Make sure we do not create chunks larger than this limit.
	 */
	int64_t max_blk_per_chunk = (INT32_MAX / 2 - 12) / fs->blocksize;

	/* Iter on the blocks to merge contiguous chunk */
	int kp = 0;
	__le32 total_chunks = 0;
	blk_t last_found_blk = first_blk;
	for (cur_blk = first_blk; cur_blk <= last_blk; ++cur_blk) {
		// TODO: Don't care more zero blocks N (dumpe2fs)
		// Block bitmap at N (+N)
		// Inode bitmap at N (+N)
		// Reserved GDT blocks at N-N
		int64_t blk_chunk = cur_blk - last_found_blk;
		if (ext2fs_test_block_bitmap2(fs->block_map, cur_blk)) {
			if (kp != 1) {
				kp = 1;
			un_used:
				if (cur_blk > last_found_blk) {
					if (params.verbose) {
						fprintf(stderr, "unused block range: %d-%d %ld\n", last_found_blk, cur_blk, blk_chunk);
					}
					sparse_write_dont_care_chunk(out_fd, blk_chunk);
					++total_chunks;
					last_found_blk = cur_blk;
				}
			} else if (blk_chunk >= max_blk_per_chunk) {
				goto in_used;
			}
		} else {
			if (kp != 2) {
				kp = 2;
			in_used:
				if (cur_blk > last_found_blk) {
					if (params.verbose) {
						fprintf(stderr, "inused block range: %d-%d %ld\n", last_found_blk, cur_blk, blk_chunk);
					}

					size_t len = blk_chunk * fs->blocksize;
					int64_t offset = (int64_t)last_found_blk * (int64_t)fs->blocksize;

					sparse_write_raw_chunk(out_fd, in_fd, offset, len);
					++total_chunks;
					last_found_blk = cur_blk;
				}
			} else if (blk_chunk >= max_blk_per_chunk) {
				goto un_used;
			}
		}
	}
	if (last_found_blk >= last_blk) {
		ext2fs_fatal(errno, "last_found_blk >= last_blk %d >= %d", last_found_blk, last_blk);
	}

	if (kp == 1) {
		if (params.verbose) {
			fprintf(stderr, "inused last block range: %d-%d\n", last_found_blk, last_blk + 1);
		}

		int64_t blk_chunk = last_blk + 1 - last_found_blk;
		size_t len = blk_chunk * fs->blocksize;
		int64_t offset = (int64_t)last_found_blk * (int64_t)fs->blocksize;

		sparse_write_raw_chunk(out_fd, in_fd, offset, len);
		++total_chunks;
		last_found_blk = cur_blk;
	} else if (kp == 2) {
		if (params.verbose) {
			fprintf(stderr, "unused last block range: %d-%d\n", last_found_blk, last_blk + 1);
		}
		sparse_write_dont_care_chunk(out_fd, last_blk + 1 - last_found_blk);
		++total_chunks;
		last_found_blk = cur_blk;
	} else {
		ext2fs_fatal(errno, "invalid kp %d", kp);
	}

	ext2fs_free(fs);

	if (sparse_write_header(out_fd, nb_blk, total_chunks) == 0) {
		ext2fs_fatal(errno, "sparse_write_header %d", errno);
	}
}

int main(int argc, char *argv[]) {
    int opt;
    int in_fd;
    int out_fd;

    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                params.verbose = 1;
                break;
            default:
                usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    if (optind + 1 >= argc) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    params.in_file = strdup(argv[optind++]);
    params.out_file = strdup(argv[optind]);

    in_fd = open(params.in_file, O_RDONLY, 0);
    if (in_fd == -1) {
        ext2fs_fatal(errno, "opening %s\n", params.in_file);
    }

    out_fd = open(params.out_file, O_WRONLY | O_CREAT | O_TRUNC, 0664);
    if (out_fd == -1) {
        ext2fs_fatal(errno, "opening %s\n", params.out_file);
    }

    ext_to_sparse(params.in_file, in_fd, out_fd);

    free(params.in_file);
    free(params.out_file);
    close(in_fd);
    close(out_fd);

    return 0;
}
