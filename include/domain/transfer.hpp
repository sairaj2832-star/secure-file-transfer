// include/domain/transfer.hpp
#pragma once
#include "domain/ids.hpp"
struct Transfer {
  enum class Status { CREATED, UPLOADED, DOWNLOADED, FAILED };
  TransferId id; FileId file; UserId sender, recipient; Status status = Status::CREATED;
  void markDownloaded() { status = Status::DOWNLOADED; }
};