/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_COMMON_IPC_MESSAGE_H__
#define CHROME_COMMON_IPC_MESSAGE_H__

#include <string>

#include "base/basictypes.h"
#include "base/pickle.h"
#include "mojo/core/ports/user_message.h"
#include "mojo/core/ports/port_ref.h"
#include "mozilla/RefPtr.h"
#include "mozilla/TimeStamp.h"
#include "mozilla/UniquePtrExtensions.h"
#include "mozilla/ipc/ScopedPort.h"
#include "nsTArray.h"

#ifdef FUZZING
#  include "mozilla/ipc/Faulty.h"
#endif

namespace mozilla {
namespace ipc {
class MiniTransceiver;
}
}  // namespace mozilla

namespace IPC {

//------------------------------------------------------------------------------

// Generated by IPDL compiler
const char* StringFromIPCMessageType(uint32_t aMessageType);

class Channel;
class Message;
#ifdef FUZZING
class Faulty;
#endif
struct LogData;

class Message : public mojo::core::ports::UserMessage, public Pickle {
 public:
  static const TypeInfo kUserMessageTypeInfo;

  typedef uint32_t msgid_t;

  enum NestedLevel {
    NOT_NESTED = 1,
    NESTED_INSIDE_SYNC = 2,
    NESTED_INSIDE_CPOW = 3
  };

  enum PriorityValue {
    NORMAL_PRIORITY = 0,
    INPUT_PRIORITY = 1,
    VSYNC_PRIORITY = 2,
    MEDIUMHIGH_PRIORITY = 3,
    CONTROL_PRIORITY = 4,
  };

  enum MessageCompression {
    COMPRESSION_NONE,
    COMPRESSION_ENABLED,
    COMPRESSION_ALL
  };

  enum Sync {
    SYNC = 0,
    ASYNC = 1,
  };

  enum Interrupt {
    NOT_INTERRUPT = 0,
    INTERRUPT = 1,
  };

  enum Constructor {
    NOT_CONSTRUCTOR = 0,
    CONSTRUCTOR = 1,
  };

  enum Reply {
    NOT_REPLY = 0,
    REPLY = 1,
  };

  // Mac and Linux both limit the number of file descriptors per message to
  // slightly more than 250.
  enum { MAX_DESCRIPTORS_PER_MESSAGE = 200 };

  class HeaderFlags {
    friend class Message;

    enum {
      NESTED_MASK = 0x0003,
      PRIO_MASK = 0x001C,
      SYNC_BIT = 0x0020,
      REPLY_BIT = 0x0040,
      REPLY_ERROR_BIT = 0x0080,
      INTERRUPT_BIT = 0x0100,
      COMPRESS_BIT = 0x0200,
      COMPRESSALL_BIT = 0x0400,
      CONSTRUCTOR_BIT = 0x0800,
      RELAY_BIT = 0x1000,
    };

   public:
    constexpr HeaderFlags() : mFlags(NOT_NESTED) {}

    explicit constexpr HeaderFlags(NestedLevel level) : mFlags(level) {}

    constexpr HeaderFlags(NestedLevel level, PriorityValue priority,
                          MessageCompression compression,
                          Constructor constructor, Sync sync,
                          Interrupt interrupt, Reply reply)
        : mFlags(level | (priority << 2) |
                 (compression == COMPRESSION_ENABLED ? COMPRESS_BIT
                  : compression == COMPRESSION_ALL   ? COMPRESSALL_BIT
                                                     : 0) |
                 (constructor == CONSTRUCTOR ? CONSTRUCTOR_BIT : 0) |
                 (sync == SYNC ? SYNC_BIT : 0) |
                 (interrupt == INTERRUPT ? INTERRUPT_BIT : 0) |
                 (reply == REPLY ? REPLY_BIT : 0)) {}

    NestedLevel Level() const {
      return static_cast<NestedLevel>(mFlags & NESTED_MASK);
    }

    PriorityValue Priority() const {
      return static_cast<PriorityValue>((mFlags & PRIO_MASK) >> 2);
    }

    MessageCompression Compression() const {
      return ((mFlags & COMPRESS_BIT)      ? COMPRESSION_ENABLED
              : (mFlags & COMPRESSALL_BIT) ? COMPRESSION_ALL
                                           : COMPRESSION_NONE);
    }

    bool IsConstructor() const { return (mFlags & CONSTRUCTOR_BIT) != 0; }
    bool IsSync() const { return (mFlags & SYNC_BIT) != 0; }
    bool IsInterrupt() const { return (mFlags & INTERRUPT_BIT) != 0; }
    bool IsReply() const { return (mFlags & REPLY_BIT) != 0; }

    bool IsReplyError() const { return (mFlags & REPLY_ERROR_BIT) != 0; }
    bool IsRelay() const { return (mFlags & RELAY_BIT) != 0; }

   private:
    void SetSync() { mFlags |= SYNC_BIT; }
    void SetInterrupt() { mFlags |= INTERRUPT_BIT; }
    void SetReply() { mFlags |= REPLY_BIT; }
    void SetReplyError() { mFlags |= REPLY_ERROR_BIT; }
    void SetRelay(bool relay) {
      if (relay) {
        mFlags |= RELAY_BIT;
      } else {
        mFlags &= ~RELAY_BIT;
      }
    }

    uint32_t mFlags;
  };

  virtual ~Message();

  Message();

  // Initialize a message with a user-defined type, priority value, and
  // destination WebView ID.
  //
  // NOTE: `recordWriteLatency` is only passed by IPDL generated message code,
  // and is used to trigger the IPC_WRITE_LATENCY_MS telemetry.
  Message(int32_t routing_id, msgid_t type,
          uint32_t segmentCapacity = 0,  // 0 for the default capacity.
          HeaderFlags flags = HeaderFlags(), bool recordWriteLatency = false);

  Message(const char* data, int data_len);

  Message(const Message& other) = delete;
  Message(Message&& other);
  Message& operator=(const Message& other) = delete;
  Message& operator=(Message&& other);

  // Helper method for the common case (default segmentCapacity, recording
  // the write latency of messages) of IPDL message creation.  This helps
  // move the malloc and some of the parameter setting out of autogenerated
  // code.
  static Message* IPDLMessage(int32_t routing_id, msgid_t type,
                              HeaderFlags flags);

  // One-off constructors for special error-handling messages.
  static Message* ForSyncDispatchError(NestedLevel level);
  static Message* ForInterruptDispatchError();

  NestedLevel nested_level() const { return header()->flags.Level(); }

  PriorityValue priority() const { return header()->flags.Priority(); }

  bool is_constructor() const { return header()->flags.IsConstructor(); }

  // True if this is a synchronous message.
  bool is_sync() const { return header()->flags.IsSync(); }

  // True if this is a synchronous message.
  bool is_interrupt() const { return header()->flags.IsInterrupt(); }

  MessageCompression compress_type() const {
    return header()->flags.Compression();
  }

  bool is_reply() const { return header()->flags.IsReply(); }

  bool is_reply_error() const { return header()->flags.IsReplyError(); }

  bool is_valid() const { return !!header(); }

  msgid_t type() const { return header()->type; }

  int32_t routing_id() const { return header()->routing; }

  void set_routing_id(int32_t new_id) { header()->routing = new_id; }

  int32_t transaction_id() const { return header()->txid; }

  void set_transaction_id(int32_t txid) { header()->txid = txid; }

  uint32_t interrupt_remote_stack_depth_guess() const {
    return header()->interrupt_remote_stack_depth_guess;
  }

  void set_interrupt_remote_stack_depth_guess(uint32_t depth) {
    DCHECK(is_interrupt());
    header()->interrupt_remote_stack_depth_guess = depth;
  }

  uint32_t interrupt_local_stack_depth() const {
    return header()->interrupt_local_stack_depth;
  }

  void set_interrupt_local_stack_depth(uint32_t depth) {
    DCHECK(is_interrupt());
    header()->interrupt_local_stack_depth = depth;
  }

  int32_t seqno() const { return header()->seqno; }

  void set_seqno(int32_t aSeqno) { header()->seqno = aSeqno; }

  const char* name() const { return StringFromIPCMessageType(type()); }

  const mozilla::TimeStamp& create_time() const { return create_time_; }

  uint32_t num_handles() const;

  bool is_relay() const { return header()->flags.IsRelay(); }
  void set_relay(bool new_relay) { header()->flags.SetRelay(new_relay); }

  template <class T>
  static bool Dispatch(const Message* msg, T* obj, void (T::*func)()) {
    (obj->*func)();
    return true;
  }

  template <class T>
  static bool Dispatch(const Message* msg, T* obj, void (T::*func)() const) {
    (obj->*func)();
    return true;
  }

  template <class T>
  static bool Dispatch(const Message* msg, T* obj,
                       void (T::*func)(const Message&)) {
    (obj->*func)(*msg);
    return true;
  }

  template <class T>
  static bool Dispatch(const Message* msg, T* obj,
                       void (T::*func)(const Message&) const) {
    (obj->*func)(*msg);
    return true;
  }

  // We should not be sending messages that are smaller than our header size.
  void AssertAsLargeAsHeader() const;

  // UserMessage implementation
  size_t GetSizeIfSerialized() const override { return size(); }
  bool WillBeRoutedExternally(mojo::core::ports::UserMessageEvent&) override;

  // Write the given footer bytes to the end of the current message. The
  // footer's `data_len` will be padded to a multiple of 4 bytes.
  void WriteFooter(const void* data, uint32_t data_len);
  // Read a footer written with `WriteFooter` from the end of the message, given
  // a buffer and the length of the footer. If `truncate` is true, the message
  // will be truncated, removing the footer.
  [[nodiscard]] bool ReadFooter(void* buffer, uint32_t buffer_len,
                                bool truncate);

  uint32_t event_footer_size() const { return header()->event_footer_size; }

  void set_event_footer_size(uint32_t size) {
    header()->event_footer_size = size;
  }

  // Used for async messages with no parameters.
  static void Log(const Message* msg, std::wstring* l) {}

  static int HeaderSize() { return sizeof(Header); }

  // Figure out how big the message starting at range_start is. Returns 0 if
  // there's no enough data to determine (i.e., if [range_start, range_end) does
  // not contain enough of the message header to know the size).
  static uint32_t MessageSize(const char* range_start, const char* range_end) {
    return Pickle::MessageSize(HeaderSize(), range_start, range_end);
  }

  bool WriteFileHandle(mozilla::UniqueFileHandle handle);

  // WARNING: This method is marked as `const` so it can be called when
  // deserializing the message, but will mutate it, consuming the handle.
  bool ConsumeFileHandle(PickleIterator* iter,
                         mozilla::UniqueFileHandle* handle) const;

  // Called when receiving an IPC message to attach file handles which were
  // received from IPC. Must only be called when there are no handles on this
  // IPC::Message.
  void SetAttachedFileHandles(nsTArray<mozilla::UniqueFileHandle> handles);

#if defined(OS_MACOSX)
  void set_fd_cookie(uint32_t cookie) { header()->cookie = cookie; }
  uint32_t fd_cookie() const { return header()->cookie; }
#endif

  void WritePort(mozilla::ipc::ScopedPort port);

  // This method consumes the port from the message, preventing the message's
  // destructor from destroying the port and meaning that future attempts to
  // read this port will instead produce an invalid port.
  //
  // WARNING: This method is marked as `const` so it can be called when
  // deserializing the message, but will mutate the message.
  bool ConsumePort(PickleIterator* iter, mozilla::ipc::ScopedPort* port) const;

  // Called when loading an IPC message to attach ports which were recieved form
  // IPC. Must only be called when there are no ports on this IPC::Message.
  void SetAttachedPorts(nsTArray<mozilla::ipc::ScopedPort> ports);

#if defined(OS_MACOSX)
  bool WriteMachSendRight(mozilla::UniqueMachSendRight port);

  // WARNING: This method is marked as `const` so it can be called when
  // deserializing the message, but will mutate it, consuming the send rights.
  bool ConsumeMachSendRight(PickleIterator* iter,
                            mozilla::UniqueMachSendRight* port) const;

  uint32_t num_send_rights() const;
#endif

  uint32_t num_relayed_attachments() const {
#if defined(OS_WIN)
    return num_handles();
#elif defined(OS_MACOSX)
    return num_send_rights();
#else
    return 0;
#endif
  }

  friend class Channel;
  friend class MessageReplyDeserializer;
  friend class SyncMessage;
#ifdef FUZZING
  friend class mozilla::ipc::Faulty;
#endif
  friend class mozilla::ipc::MiniTransceiver;

#if !defined(OS_MACOSX)
 protected:
#endif

  struct Header : Pickle::Header {
    int32_t routing;       // ID of the view that this message is destined for
    msgid_t type;          // specifies the user-defined message type
    HeaderFlags flags;     // specifies control flags for the message
    uint32_t num_handles;  // the number of handles included with this message
#if defined(OS_MACOSX)
    uint32_t cookie;  // cookie to ACK that the descriptors have been read.
    uint32_t num_send_rights;  // the number of mach send rights included with
                               // this message
#endif
    union {
      // For Interrupt messages, a guess at what the *other* side's stack depth
      // is.
      uint32_t interrupt_remote_stack_depth_guess;

      // For RPC and Urgent messages, a transaction ID for message ordering.
      int32_t txid;
    };
    // The actual local stack depth.
    uint32_t interrupt_local_stack_depth;
    // Sequence number
    int32_t seqno;
    // Size of the message's event footer
    uint32_t event_footer_size;
  };

  Header* header() { return headerT<Header>(); }
  const Header* header() const { return headerT<Header>(); }

  // The set of file handles which are attached to this message.
  //
  // Mutable, as this array can be mutated during `ReadHandle` when
  // deserializing a message.
  mutable nsTArray<mozilla::UniqueFileHandle> attached_handles_;

  // The set of mojo ports which are attached to this message.
  //
  // Mutable, as this array can be mutated during `ConsumePort` when
  // deserializing a message.
  mutable nsTArray<mozilla::ipc::ScopedPort> attached_ports_;

#if defined(OS_MACOSX)
  // The set of mach send rights which are attached to this message.
  //
  // Mutable, as this array can be mutated during `ConsumeMachSendRight` when
  // deserializing a message.
  mutable nsTArray<mozilla::UniqueMachSendRight> attached_send_rights_;
#endif

  mozilla::TimeStamp create_time_;
};

class MessageInfo {
 public:
  typedef uint32_t msgid_t;

  explicit MessageInfo(const Message& aMsg)
      : mSeqno(aMsg.seqno()), mType(aMsg.type()) {}

  int32_t seqno() const { return mSeqno; }
  msgid_t type() const { return mType; }

 private:
  int32_t mSeqno;
  msgid_t mType;
};

//------------------------------------------------------------------------------

}  // namespace IPC

enum SpecialRoutingIDs {
  // indicates that we don't have a routing ID yet.
  MSG_ROUTING_NONE = kint32min,

  // indicates a general message not sent to a particular tab.
  MSG_ROUTING_CONTROL = kint32max
};

#define IPC_REPLY_ID 0xFFF0    // Special message id for replies
#define IPC_LOGGING_ID 0xFFF1  // Special message id for logging

#endif  // CHROME_COMMON_IPC_MESSAGE_H__
