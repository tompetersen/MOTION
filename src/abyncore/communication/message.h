#pragma once

#include "fbs_headers/message_generated.h"
#include "utility/typedefs.h"

namespace ABYN::Communication {
static flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                                   const std::vector<uint8_t> *payload) {
  auto allocation_size = payload ? payload->size() + 20 : 1024;
  flatbuffers::FlatBufferBuilder builder(allocation_size);
  auto root = CreateMessageDirect(builder, message_type, payload);
  FinishMessageBuffer(builder, root);
  return std::move(builder);
}

static flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type, const uint8_t *payload,
                                                   std::size_t size) {
  std::vector<std::uint8_t> buffer(payload, payload + size);
  return std::move(BuildMessage(message_type, &buffer));
}
}  // namespace ABYN::Communication
