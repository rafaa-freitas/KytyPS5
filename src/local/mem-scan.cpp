#include "local/mem-scan.h"

#include "common/guardedCopy.h"
#include "kernel/memory.h"
#include "local/local-platform.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace LocalMemScan {

namespace {

namespace Memory = Libs::LibKernel::Memory;

enum class Type { U8, U16, U32, F32 };

struct State {
	std::mutex            mutex;
	Type                  type = Type::U32;
	std::vector<uint64_t> candidates;
};
State& Get() {
	static State state;
	return state;
}

constexpr size_t MaxCandidates = 20'000'000;

uint32_t Size(Type type) {
	switch (type) {
		case Type::U8: return 1;
		case Type::U16: return 2;
		default: return 4;
	}
}

bool ParseType(const std::string& text, Type* type) {
	if (text == "u8") *type = Type::U8;
	else if (text == "u16") *type = Type::U16;
	else if (text == "u32") *type = Type::U32;
	else if (text == "f32") *type = Type::F32;
	else return false;
	return true;
}

// The value's bytes (little endian, Size(type) of them).
uint32_t Encode(Type type, const std::string& text) {
	if (type == Type::F32) {
		const float value = std::strtof(text.c_str(), nullptr);
		uint32_t    bits  = 0;
		std::memcpy(&bits, &value, 4);
		return bits;
	}
	return static_cast<uint32_t>(std::strtoull(text.c_str(), nullptr, 10));
}

bool Matches(const uint8_t* at, Type type, uint32_t bits) {
	switch (type) {
		case Type::U8: return at[0] == static_cast<uint8_t>(bits);
		case Type::U16: {
			uint16_t value = 0;
			std::memcpy(&value, at, 2);
			return value == static_cast<uint16_t>(bits);
		}
		default: {
			uint32_t value = 0;
			std::memcpy(&value, at, 4);
			return value == bits;
		}
	}
}

// The guest's committed ranges the CPU writes, but the pages the GPU wrote (read faults): the game's data. (start,
// size), in order.
std::vector<std::pair<uint64_t, uint64_t>> DataRanges() {
	std::vector<std::pair<uint64_t, uint64_t>> ranges;
	uint64_t                                   version = 0;
	std::vector<uint32_t>                      granules;
	if (!Memory::CommittedGranules(&version, &granules)) return ranges;
	constexpr uint64_t                         Granule = uint64_t {1} << Memory::CommittedGranuleBits;
	constexpr uint64_t                         Page    = 0x4000;
	std::vector<std::pair<uint64_t, uint64_t>> parts;
	for (const auto granule: granules) {
		Memory::MappedParts(uint64_t {granule} << Memory::CommittedGranuleBits, Granule, &parts);
		for (const auto& [start, size]: parts) {
			// Page by page: one granule can hold mappings of different protections.
			for (uint64_t at = start; at < start + size; at += Page) {
				const uint64_t bytes = std::min(Page, start + size - at);
				bool           gpu = false, cpu_write = false;
				// (The game's heap is GPU-visible memory too: only pages a read must not touch, those the GPU wrote, are left
				// out; GuardedCopy stops at a page without access.)
				if (!Memory::GuestRangeAccess(at, bytes, &gpu, &cpu_write) || !cpu_write || Memory::ReadFaults(at, bytes))
					continue;
				if (!ranges.empty() && ranges.back().first + ranges.back().second == at) {
					ranges.back().second += bytes;
				} else {
					ranges.emplace_back(at, bytes);
				}
			}
		}
	}
	return ranges;
}

bool ReadValue(uint64_t address, uint32_t size, uint8_t* out) {
	return Common::GuardedCopy(out, reinterpret_cast<const void*>(address), size) == 0;
}

void PrintValue(uint64_t id, uint64_t address, Type type) {
	uint8_t bytes[4] {};
	if (!ReadValue(address, Size(type), bytes)) {
		std::printf("LIVE_SCAN_ITEM id=%" PRIu64 " address=0x%" PRIx64 " unreadable\n", id, address);
		return;
	}
	if (type == Type::F32) {
		float value = 0;
		std::memcpy(&value, bytes, 4);
		std::printf("LIVE_SCAN_ITEM id=%" PRIu64 " address=0x%" PRIx64 " value=%g\n", id, address, static_cast<double>(value));
	} else {
		uint32_t value = 0;
		std::memcpy(&value, bytes, Size(type));
		std::printf("LIVE_SCAN_ITEM id=%" PRIu64 " address=0x%" PRIx64 " value=%u\n", id, address, value);
	}
}

#if defined(_WIN32)
struct Hit {
	std::atomic<uint64_t> rip {0};
	std::atomic<uint64_t> count {0};
};
constexpr size_t      MaxHits = 64;
Hit                   g_hits[MaxHits];
std::atomic<uint64_t> g_watch_address {0};
std::atomic<uint64_t> g_lost_hits {0};
PVOID                 g_handler = nullptr;

LONG CALLBACK WatchHandler(PEXCEPTION_POINTERS info) {
	if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP || (info->ContextRecord->Dr6 & 1u) == 0 ||
	    g_watch_address.load(std::memory_order_relaxed) == 0)
		return EXCEPTION_CONTINUE_SEARCH;
	const uint64_t rip = info->ContextRecord->Rip;
	bool           kept = false;
	for (auto& hit: g_hits) {
		uint64_t expected = 0;
		if (hit.rip.load(std::memory_order_relaxed) == rip ||
		    hit.rip.compare_exchange_strong(expected, rip, std::memory_order_relaxed) || expected == rip) {
			hit.count.fetch_add(1, std::memory_order_relaxed);
			kept = true;
			break;
		}
	}
	if (!kept) g_lost_hits.fetch_add(1, std::memory_order_relaxed);
	info->ContextRecord->Dr6 = 0;
	return EXCEPTION_CONTINUE_EXECUTION;
}

// Dr0 and Dr7 of every other thread of the process: the write breakpoint on (address != 0) or off.
uint32_t SetBreakpoint(uint64_t address, uint32_t length) {
	const DWORD self = GetCurrentThreadId();
	// Dr7: local enable of Dr0 (bit 0), R/W0 = 01 (writes, bits 16-17), LEN0 (bits 18-19: 00 1 byte, 01 2, 11 4, 10 8).
	const uint64_t len  = length == 1 ? 0u : length == 2 ? 1u : length == 8 ? 2u : 3u;
	const uint64_t dr7  = address != 0 ? (1u | (1u << 16u) | (len << 18u)) : 0u;
	uint32_t       done = 0;
	for (const auto& [tid, name]: LocalPlatform::ProcessThreads()) {
		if (tid == self) continue;
		HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
		if (thread == nullptr) continue;
		if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
			CONTEXT context {};
			context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
			if (GetThreadContext(thread, &context) != 0) {
				context.Dr0 = address;
				context.Dr7 = (context.Dr7 & ~uint64_t {0xf0003}) | dr7;
				context.Dr6 = 0;
				if (SetThreadContext(thread, &context) != 0) done++;
			}
			ResumeThread(thread);
		}
		CloseHandle(thread);
	}
	return done;
}
#endif

} // namespace

void Scan(uint64_t id, const std::string& type_text, const std::string& value) {
	Type type {};
	if (!ParseType(type_text, &type)) {
		std::printf("LIVE_ERROR id=%" PRIu64 " scan: type %s (u8, u16, u32 or f32)\n", id, type_text.c_str());
		return;
	}
	const auto     start  = std::chrono::steady_clock::now();
	const uint32_t bits   = Encode(type, value);
	const uint32_t size   = Size(type);
	const auto     ranges = DataRanges();
	auto&          state  = Get();
	std::lock_guard lock(state.mutex);
	state.type = type;
	state.candidates.clear();
	std::vector<uint8_t> buffer(1u << 20u);
	uint64_t             scanned = 0;
	bool                 full    = false;
	for (const auto& [range_start, range_size]: ranges) {
		for (uint64_t at = range_start; at < range_start + range_size && !full; at += buffer.size()) {
			const uint64_t bytes = std::min<uint64_t>(buffer.size(), range_start + range_size - at);
			if (Common::GuardedCopy(buffer.data(), reinterpret_cast<const void*>(at), bytes) != 0) continue;
			scanned += bytes;
			for (uint64_t offset = 0; offset + size <= bytes; offset += size) {
				if (Matches(buffer.data() + offset, type, bits)) {
					state.candidates.push_back(at + offset);
					if (state.candidates.size() >= MaxCandidates) {
						full = true;
						break;
					}
				}
			}
		}
	}
	const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
	std::printf("LIVE_SCAN id=%" PRIu64 " type=%s value=%s ranges=%zu scanned_mib=%" PRIu64 " candidates=%zu%s ms=%lld\n", id,
	            type_text.c_str(), value.c_str(), ranges.size(), scanned >> 20u, state.candidates.size(),
	            full ? " (full: scan a rarer value)" : "", static_cast<long long>(ms));
}

void Next(uint64_t id, const std::string& value) {
	auto&           state = Get();
	std::lock_guard lock(state.mutex);
	const uint32_t  bits = Encode(state.type, value);
	const uint32_t  size = Size(state.type);
	const size_t    before = state.candidates.size();
	std::erase_if(state.candidates, [&](uint64_t address) {
		uint8_t bytes[4] {};
		return !ReadValue(address, size, bytes) || !Matches(bytes, state.type, bits);
	});
	std::printf("LIVE_NEXT id=%" PRIu64 " value=%s candidates=%zu (of %zu)\n", id, value.c_str(), state.candidates.size(),
	            before);
	if (state.candidates.size() <= 16)
		for (const auto address: state.candidates) PrintValue(id, address, state.type);
}

void List(uint64_t id, uint32_t count) {
	auto&           state = Get();
	std::lock_guard lock(state.mutex);
	const size_t    shown = std::min<size_t>(count == 0 ? 20 : count, state.candidates.size());
	for (size_t i = 0; i < shown; i++) PrintValue(id, state.candidates[i], state.type);
	std::printf("LIVE_LIST id=%" PRIu64 " shown=%zu candidates=%zu\n", id, shown, state.candidates.size());
}

void PokeBytes(uint64_t id, uint64_t address, const std::string& hex) {
	std::vector<uint8_t> bytes;
	for (size_t i = 0; i + 1 < hex.size(); i += 2) bytes.push_back(static_cast<uint8_t>(std::strtoul(hex.substr(i, 2).c_str(), nullptr, 16)));
	bool gpu = false, cpu_write = false;
	if (bytes.empty() || !Memory::GuestRangeAccess(address, bytes.size(), &gpu, &cpu_write) || !cpu_write ||
	    Memory::ReadFaults(address, bytes.size())) {
		std::printf("LIVE_ERROR id=%" PRIu64 " pokeb: 0x%" PRIx64 " is not guest CPU-writable data\n", id, address);
		return;
	}
	std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());
	std::printf("LIVE_POKEB id=%" PRIu64 " address=0x%" PRIx64 " bytes=%zu\n", id, address, bytes.size());
}

void Watch(uint64_t id, uint64_t address, uint32_t length, double seconds) {
#if defined(_WIN32)
	if ((length != 1 && length != 2 && length != 4 && length != 8) || address % length != 0 || seconds <= 0) {
		std::printf("LIVE_ERROR id=%" PRIu64 " watch: length 1, 2, 4 or 8 at an address it divides, seconds > 0\n", id);
		return;
	}
	for (auto& hit: g_hits) {
		hit.rip.store(0);
		hit.count.store(0);
	}
	g_lost_hits.store(0);
	if (g_handler == nullptr) g_handler = AddVectoredExceptionHandler(1, WatchHandler);
	g_watch_address.store(address);
	const uint32_t threads = SetBreakpoint(address, length);
	std::printf("LIVE_WATCH id=%" PRIu64 " address=0x%" PRIx64 " length=%u threads=%u seconds=%g\n", id, address, length,
	            threads, seconds);
	std::fflush(stdout);
	// Until the first write (and half a second more, for the writers of the same moment) or the time is up: a
	// breakpoint left on through a level load slowed the load to a crawl.
	const auto end = std::chrono::steady_clock::now() + std::chrono::duration<double>(seconds);
	while (std::chrono::steady_clock::now() < end) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		if (g_hits[0].rip.load(std::memory_order_relaxed) != 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			break;
		}
	}
	(void)SetBreakpoint(0, length);
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	g_watch_address.store(0);
	uint32_t found = 0;
	for (const auto& hit: g_hits) {
		const uint64_t rip = hit.rip.load();
		if (rip == 0) continue;
		found++;
		std::printf("LIVE_WATCH_HIT id=%" PRIu64 " rip=0x%" PRIx64 " eboot=0x%" PRIx64 " count=%" PRIu64 "\n", id, rip,
		            rip - 0x900000000ull, hit.count.load());
	}
	std::printf("LIVE_WATCH_DONE id=%" PRIu64 " writers=%u lost=%" PRIu64 "\n", id, found, g_lost_hits.load());
#else
	(void)address;
	(void)length;
	(void)seconds;
	std::printf("LIVE_ERROR id=%" PRIu64 " watch: Windows only\n", id);
#endif
}

} // namespace LocalMemScan
