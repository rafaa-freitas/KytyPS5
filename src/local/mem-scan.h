#ifndef EMULATOR_SRC_LOCAL_MEM_SCAN_H_
#define EMULATOR_SRC_LOCAL_MEM_SCAN_H_
// KYTY_LIVE_FILE memory tools for making cheats (live-control.h), in the guest's CPU-writable memory:
//   scan <u8|u16|u32|f32> <value>   every aligned place holding the value: the candidates (replaced)
//   next <value>                    the candidates that hold the value now (a value changed in the game between)
//   list [count]                    the candidates with their values (LIVE_SCAN_ITEM lines)
//   pokeb <address> <hex bytes>     guest data bytes written (a candidate tried out)
//   watch <address> <1|2|4|8> <s>   Windows: a hardware write breakpoint on every thread for <s> seconds: each
//                                   instruction that writes there, with its count (LIVE_WATCH_HIT rip= is the
//                                   instruction after the write; eboot offsets are rip - 0x900000000)
// Values are decimal (f32: a float); addresses hex.

#include <cstdint>
#include <string>

namespace LocalMemScan {

// One live command (the line's words after the command), its LIVE_* lines on stdout.
void Scan(uint64_t id, const std::string& type, const std::string& value);
void Next(uint64_t id, const std::string& value);
void List(uint64_t id, uint32_t count);
void PokeBytes(uint64_t id, uint64_t address, const std::string& hex);
void Watch(uint64_t id, uint64_t address, uint32_t length, double seconds);

} // namespace LocalMemScan

#endif
