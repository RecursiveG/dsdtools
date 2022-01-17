// Copyright 2022, Recursive G
// SPDX-License-Identifier: GPL-3.0-or-later

#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <cinttypes>
#include <cstdlib>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/cleanup/cleanup.h"
#include "absl/time/time.h"

using std::string;

ABSL_FLAG(string, dsf, "", "The DSF file.");
ABSL_FLAG(string, out, "", "Raw output file.");

struct ChunkDSD {
  char magic[4];  // "DSD "
  uint64_t chunk_size;  // size of this chunk, always 28
  uint64_t file_size;
  uint64_t metadata_offset;
  void Print() const {
    absl::PrintF("ChunkDSD {\n");
    absl::PrintF("  chunk_size: %d\n", chunk_size);
    absl::PrintF("  file_size: %d\n", file_size);
    absl::PrintF("  metadata_offset: %d\n", metadata_offset);
    absl::PrintF("}\n");
  }
} __attribute__((packed));
static_assert(sizeof(ChunkDSD) == 28);

struct ChunkFormat {
  char magic[4]; // "fmt "
  uint64_t chunk_size;
  uint32_t format_version;
  uint32_t format_id;
  uint32_t channel_type;
  uint32_t channel_num;
  uint32_t sample_frequency;
  uint32_t bits_per_sample;
  uint64_t sample_count;
  uint32_t block_size_per_channel;
  // Skip according to chunk_size;
  void Print() const {
    absl::PrintF("ChunkFormat {\n");
    absl::PrintF("  chunk_size: %d\n", chunk_size);
    absl::PrintF("  format_version: %d\n", format_version);
    absl::PrintF("  format_id: %d\n", format_id);
    absl::PrintF("  channel_type: %d\n", channel_type);
    absl::PrintF("  channel_num: %d\n", channel_num);
    absl::PrintF("  sample_frequency: %d\n", sample_frequency);
    absl::PrintF("  bits_per_sample: %d\n", bits_per_sample);
    absl::PrintF("  sample_count: %d\n", sample_count);
    absl::PrintF("  block_size_per_channel: %d\n", block_size_per_channel);
    absl::PrintF("}\n");
  }
} __attribute__((packed));
static_assert(sizeof(ChunkFormat) == 48);

struct ChunkDataHeader {
  char magic[4]; // "data"
  uint64_t chunk_size;
  // Followed by (chunk_size - 12) bytes of data
} __attribute__((packed));
static_assert(sizeof(ChunkDataHeader) == 12);

int main(int argc, char *argv[]) {
  // reverse_byte
  uint8_t reverse_bits[256];
  for (int i=0; i <= 255; i++) {
    int r = 0;
    if (i & 1) r += 128;
    if (i & 2) r += 64;
    if (i & 4) r += 32;
    if (i & 8) r += 16;
    if (i & 16) r += 8;
    if (i & 32) r += 4;
    if (i & 64) r += 2;
    if (i & 128) r += 1;
    reverse_bits[i] = r;
  }

  absl::SetProgramUsageMessage("Extract RAW DSD stream from DSF file, so it can be played using aplay.");
  absl::ParseCommandLine(argc, argv);
  if (absl::GetFlag(FLAGS_dsf) == "") {
    absl::PrintF("no input file\n");
    return 1;
  }
  absl::PrintF("DSF file: %s\n", absl::GetFlag(FLAGS_dsf));

  // FD
  int dsf_fd = open(absl::GetFlag(FLAGS_dsf).c_str(), O_RDONLY);
  if (dsf_fd < 0) {
    absl::PrintF("open() failed\n");
    return 1;
  }
  auto dsf_fd_cleanup = absl::MakeCleanup([=](){close(dsf_fd);});

  // size
  off_t dsf_size = lseek(dsf_fd, 0, SEEK_END);
  if (dsf_size < 0) {
    absl::PrintF("lseek() failed\n");
    return 1;
  }
  absl::PrintF("File size: %d\n", dsf_size);

  // mmap
  void* dsf_addr = mmap(nullptr, dsf_size, PROT_READ, MAP_SHARED, dsf_fd, 0);
  if (dsf_addr == MAP_FAILED) {
    absl::PrintF("mmap() failed\n");
    return 1;
  }
  auto mmap_cleanup = absl::MakeCleanup([=](){munmap(dsf_addr, dsf_size);});

  // memory reader
  const char* pointer = static_cast<const char*>(dsf_addr);
  uint64_t remained_bytes = dsf_size;
  auto next = [&]<typename T>(uint64_t offset, uint64_t request_bytes = sizeof(T)) -> const T* {
    if (remained_bytes < offset + request_bytes) return nullptr;
    pointer += offset;
    return reinterpret_cast<const T*>(pointer);
  };

  // File header
  const ChunkDSD* chunk_dsd = next.operator()<ChunkDSD>(0);
  if (chunk_dsd == nullptr) {
    absl::PrintF("Unexpected file end\n");
    return 1;
  }
  if (absl::string_view(chunk_dsd->magic, 4) != "DSD ") {
    absl::PrintF("Incorrect DSD magic\n");
    return 1;
  }
  chunk_dsd->Print();

  // Fmt chunk
  const ChunkFormat* chunk_fmt = next.operator()<ChunkFormat>(chunk_dsd->chunk_size);
  if (chunk_fmt == nullptr) {
    absl::PrintF("Unexpected file end\n");
    return 1;
  }
  if (absl::string_view(chunk_fmt->magic, 4) != "fmt ") {
    absl::PrintF("Incorrect fmt magic\n");
    return 1;
  }
  chunk_fmt->Print();

  // Data chunk
  const ChunkDataHeader* chunk_data = next.operator()<ChunkDataHeader>(chunk_fmt->chunk_size);
  if (chunk_data == nullptr) {
    absl::PrintF("Unexpected file end\n");
    return 1;
  }
  if (absl::string_view(chunk_data->magic, 4) != "data") {
    absl::PrintF("Incorrect data magic\n");
    return 1;
  }
  if (remained_bytes < chunk_data->chunk_size) {
    absl::PrintF("Data chunk too small\n");
    return 1;
  }

  // Validate a few parameters
  if ((chunk_data->chunk_size - 12) % chunk_fmt->block_size_per_channel != 0) {
    absl::PrintF("data is not a multiple of blocks");
    return 1;
  }
  uint64_t in_blocks = (chunk_data->chunk_size - 12) / chunk_fmt->block_size_per_channel;
  if (in_blocks % chunk_fmt->channel_num != 0) {
    absl::PrintF("block is not a multiple of channels");
    return 1;
  }
  uint64_t in_frames = in_blocks / chunk_fmt->channel_num;
  uint64_t valid_bits = chunk_fmt->sample_count * chunk_fmt->bits_per_sample * chunk_fmt->channel_num;
  uint64_t bits_per_frame = 8 * chunk_fmt->block_size_per_channel * chunk_fmt->channel_num;
  if ((valid_bits-1)/bits_per_frame+1 != in_frames) {
    absl::PrintF("metadata value not match size");
    return 1;
  }
  absl::Duration audio_length = absl::Seconds(static_cast<double>(chunk_fmt->sample_count / chunk_fmt->sample_frequency));
  absl::PrintF("Frames: %d\n", in_frames);
  absl::PrintF("Duration: %s\n", absl::FormatDuration(audio_length));

  // convert to raw file
  // DSF frames:        lo [4096B FL][4096B FR]... hi
  // DSF bytes:         lo [B0 B1 ... B4095]       hi
  // DSF bits:          lo [b0 b1 ... b7]          hi
  // DSD_U32_BE frames: lo [4B FL][4B FR]...       hi
  // DSD_U32_BE bytes:  lo [B0 B1 B2 B3]           hi
  // DSD_U32_BE bits:   lo [b7 b6 ... b0]          hi

  if (absl::GetFlag(FLAGS_out) == "") {
    absl::PrintF("No output file specified\n");
    return 0;
  }

  // open output file
  int out_fd = open(absl::GetFlag(FLAGS_out).c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (out_fd < 0) {
    absl::PrintF("open() out_fd failed\n");
    return 1;
  }
  auto out_fd_cleanup = absl::MakeCleanup([=](){close(out_fd);});
  auto write_all = [](int fd, const void* buf, size_t count) {
    int offset = 0;
    while (count > 0) {
      int written = write(fd, static_cast<const char*>(buf) + offset, count);
      if (written < 0) {
        absl::PrintF("bad write");
        exit(1);
      }
      offset += written;
      count -= written;
    }
  };

  uint64_t frame_ratio = 4096 / 4;
  for (uint64_t frame = 0; frame < in_frames; frame++) {
    // Assuming 2CH, 4096 block size
    auto output = std::make_unique<uint8_t[]>(8192);
    const auto* input = reinterpret_cast<const uint8_t*>(pointer + 12 + 8192 * frame);
    for (uint64_t out_frame = 0; out_frame < frame_ratio; out_frame++) {
      for (uint64_t chn = 0; chn < 2; chn++) {
        output[out_frame * (4*2) + chn*4 + 0] = input[chn*4096 + out_frame*4 + 0];
        output[out_frame * (4*2) + chn*4 + 1] = input[chn*4096 + out_frame*4 + 1];
        output[out_frame * (4*2) + chn*4 + 2] = input[chn*4096 + out_frame*4 + 2];
        output[out_frame * (4*2) + chn*4 + 3] = input[chn*4096 + out_frame*4 + 3];
      }
    }
    for (uint64_t i = 0; i < 8192; i++) output[i] = reverse_bits[output[i]];
    write_all(out_fd, output.get(), 8192);
  }
  // TODO: deal with trailing zeros.

  absl::PrintF("aplay -D hw:2,0 -f DSD_U32_BE -c 2 -r %d \"%s\"\n", chunk_fmt->sample_frequency / 8 / 4, absl::GetFlag(FLAGS_out));
  absl::PrintF("Done\n");

  return 0;
}
