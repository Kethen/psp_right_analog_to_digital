/*
  Remastered Controls: analog to digital
  Copyright (C) 2018, TheFloW
  Copyright (C) 2023, Katharine Chui

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <pspsdk.h>
#include <pspkernel.h>
#include <pspctrl.h>
#include <pspiofilemgr.h>
#include <pspthreadman.h>

#include <stdio.h>
#include <string.h>

#include <systemctrl.h>

#define MODULE_NAME "ra2d"

PSP_MODULE_INFO(MODULE_NAME, 0x1007, 1, 0);

int sceKernelQuerySystemCall(void *function);

#define EMULATOR_DEVCTL__IS_EMULATOR     0x00000003

static STMOD_HANDLER previous;

static int is_emulator;

static u32 MakeSyscallStub(void *function) {
  SceUID block_id = sceKernelAllocPartitionMemory(PSP_MEMORY_PARTITION_USER, "", PSP_SMEM_High, 2 * sizeof(u32), NULL);
  u32 stub = (u32)sceKernelGetBlockHeadAddr(block_id);
  _sw(0x03E00008, stub);
  _sw(0x0000000C | (sceKernelQuerySystemCall(function) << 6), stub + 4);
  return stub;
}

// to be set by config
static unsigned int yp_btn = PSP_CTRL_LTRIGGER;
static unsigned int yn_btn = PSP_CTRL_RTRIGGER;
static unsigned int xp_btn = 0;
static unsigned int xn_btn = 0;
static unsigned char outer_deadzone = 20;
static unsigned char inner_deadzone = 10;

// hook sceCtrlSetSamplingCycle or call sceCtrlGetSamplingCycle for this?
static u32 window = 8; // frame

// is there a flush..? or the non async version always syncs?
#define DEBUG 1
#if DEBUG
static int logfd;
#define LOG(...) \
if(logfd > 0){ \
	char logbuf[128]; \
	int loglen = sprintf(logbuf, __VA_ARGS__); \
	if(loglen > 0){ \
		sceIoWrite(logfd, logbuf, loglen); \
	} \
}
#else // DEBUG
#define LOG(...)
#endif // DEBUG
#define VERBOSE 0
#if VERBOSE
#define LOG_VERBOSE(...) LOG(__VA_ARGS__)
#else // VERBOSE
#define LOG_VERBOSE(...)
#endif // VERBOSE


#define MAKE_JUMP(a, f) _sw(0x08000000 | (((u32)(f) & 0x0FFFFFFC) >> 2), a);

#define GET_JUMP_TARGET(x) (0x80000000 | (((x) & 0x03FFFFFF) << 2))

// jacking JR_SYSCALL in ppsspp, so just save the two instructions, instead of seeking the target
// also scan other modules for the same pattern and patch them if ppsspp
// for real hw, go the jump target then attempt the more standard two instructions hijack
// hopefully works with the static args loaded sceCtrl functions, at least referencing uofw and joysens
#define HIJACK_SYSCALL_STUB(a, f, ptr) \
{ \
  LOG("hijacking jmp function at 0x%lx with 0x%lx\n", (u32)a, (u32)f); \
  u32 _func_ = (u32)a; \
  LOG("original instructions: 0x%lx 0x%lx\n", _lw(_func_), _lw(_func_ + 4)); \
  u32 pattern[2]; \
  _sw(_lw(_func_), (u32)pattern); \
  _sw(_lw(_func_ + 4), (u32)pattern + 4); \
  u32 ff = (u32)f; \
  if(!is_emulator){ \
    ff = MakeSyscallStub(f); \
    _func_ = GET_JUMP_TARGET(_lw(a)); \
    LOG("real hardware mode, making syscall stub 0x%lx and retargetting function 0x%lx\n", ff, _func_); \
    LOG("original instructions: 0x%lx 0x%lx\n", _lw(_func_), _lw(_func_ + 4)); \
  } \
  static u32 patch_buffer[3]; \
  if(is_emulator){ \
    _sw(_lw(_func_), (u32)patch_buffer); \
    _sw(_lw(_func_ + 4), (u32)patch_buffer + 4); \
  }else{ \
    _sw(_lw(_func_), (u32)patch_buffer); \
    _sw(_lw(_func_ + 4), (u32)patch_buffer + 8); \
    MAKE_JUMP((u32)patch_buffer + 4, _func_ + 8); \
  } \
  _sw(0x08000000 | (((u32)(ff) >> 2) & 0x03FFFFFF), _func_); \
  _sw(0, _func_ + 4); \
  ptr = (void *)patch_buffer; \
  if(is_emulator){ \
    SceUID modules[32]; \
    SceKernelModuleInfo info; \
    int i, count = 0; \
    if (sceKernelGetModuleIdList(modules, sizeof(modules), &count) >= 0) { \
      for (i = 0; i < count; i++) { \
        info.size = sizeof(SceKernelModuleInfo); \
        if (sceKernelQueryModuleInfo(modules[i], &info) < 0) { \
          continue; \
        } \
        if (strcmp(info.name, MODULE_NAME) == 0) { \
          continue; \
        } \
        LOG("scanning module %s in ppsspp mode\n", info.name); \
        LOG("info.text_addr: 0x%x info.text_size: 0x%x\n", info.text_addr, info.text_size); \
        u32 k; \
        for(k = 0; k < info.text_size; k+=4){ \
          u32 addr = k + info.text_addr; \
          if(/*_lw((u32)pattern) == _lw(addr + 0) &&*/ _lw((u32)pattern + 4) == _lw(addr + 4)){ \
            LOG("found instruction pattern 0x%lx 0x%lx at 0x%lx, patching\n", pattern[0], pattern[1], addr); \
            _sw(0x08000000 | (((u32)(ff) >> 2) & 0x03FFFFFF), addr); \
            _sw(0, addr + 4); \
          } \
        } \
      } \
    } \
  } \
}

static int button_on(int val, u32 timestamp, u32 w){
	int max_val = (127 - outer_deadzone) - (inner_deadzone);
	if(max_val <= 0){
		return 0;
	}
	if(val < inner_deadzone){
		return 0;
	}else{
		val = val - inner_deadzone;
	}
	if(val > max_val){
		val = max_val;
	}
	u32 slice = 1 + (val * (w - 1)) / max_val;
	if(slice <= 0){
		return 0;
	}
	u32 n = timestamp % w + 1;
	LOG_VERBOSE("val is %d, w is %ld, n is %ld, slice is %ld\n", val, w, n, slice);
	return slice >= n;
}

static void apply_analog_to_digital(SceCtrlData *pad_data, int count, int negative){
	if(count < 1){
		LOG("count is %d, processing skipped\n", count);
		return;
	}

	LOG_VERBOSE("processing %d buffers in %s mode\n", count, negative? "negative" : "positive");

	int i;
	for(i = 0;i < count; i++){
		int buttons = negative ? ~pad_data[i].Buttons : pad_data[i].Buttons;
		int rx = pad_data[i].Rsrv[0];
		int ry = pad_data[i].Rsrv[1];
		u32 timestamp = pad_data->TimeStamp;

		if(rx > 128){
			int val = rx - 128;
			if(button_on(val, timestamp, window))
				buttons |= xp_btn;
		}
		if(rx < 128){
			int val = 128 - rx;
			if(val == 128){
				val = 127;
			}
			if(button_on(val, timestamp, window))
				buttons |= xn_btn;
		}
		if(ry > 128){
			int val = ry - 128;
			if(button_on(val, timestamp, window))
				buttons |= yp_btn;
		}
		if(ry < 128){
			int val = 128 - ry;
			if(val == 128){
				val = 127;
			}
			if(button_on(val, timestamp, window))
				buttons |= yn_btn;
		}

		LOG_VERBOSE("timestamp: %d rx: %d ry: %d\n", timestamp, rx, ry);
		pad_data[i].Buttons = negative ? ~buttons : buttons;
	}
}

static int (*sceCtrlReadBufferPositiveOrig)(SceCtrlData *pad_data, int count);
int sceCtrlReadBufferPositivePatched(SceCtrlData *pad_data, int count){
	int k1 = pspSdkSetK1(0);
	int res = sceCtrlReadBufferPositiveOrig(pad_data, count);

	apply_analog_to_digital(pad_data, res, 0);

	pspSdkSetK1(k1);
	return res;
}

static int (*sceCtrlReadBufferNegativeOrig)(SceCtrlData *pad_data, int count);
int sceCtrlReadBufferNegativePatched(SceCtrlData *pad_data, int count){
	int k1 = pspSdkSetK1(0);
	int res = sceCtrlReadBufferNegativeOrig(pad_data, count);

	apply_analog_to_digital(pad_data, res, 1);

	pspSdkSetK1(k1);
	return res;
}

static int (*sceCtrlPeekBufferPositiveOrig)(SceCtrlData *pad_data, int count);
int sceCtrlPeekBufferPositivePatched(SceCtrlData *pad_data, int count){
	int k1 = pspSdkSetK1(0);
	int res = sceCtrlPeekBufferPositiveOrig(pad_data, count);

	apply_analog_to_digital(pad_data, res, 0);

	pspSdkSetK1(k1);
	return res;
}

static int (*sceCtrlPeekBufferNegativeOrig)(SceCtrlData *pad_data, int count);
int sceCtrlPeekBufferNegativePatched(SceCtrlData *pad_data, int count){
	int k1 = pspSdkSetK1(0);
	int res = sceCtrlPeekBufferNegativeOrig(pad_data, count);

	apply_analog_to_digital(pad_data, res, 1);

	pspSdkSetK1(k1);
	return res;
}

static void log_modules(){
	SceUID modules[10];
	SceKernelModuleInfo info;
	int i, count = 0;

	if (sceKernelGetModuleIdList(modules, sizeof(modules), &count) >= 0) {
		for (i = 0; i < count; ++i) {
			info.size = sizeof(SceKernelModuleInfo);
			if (sceKernelQueryModuleInfo(modules[i], &info) < 0) {
				continue;
			}
			LOG("module #%d: %s\n", i+1, info.name);
		}
	}
}

int main_thread(SceSize args, void *argp){
	LOG("main thread begins\n");

	// probably read config here

	sceKernelDelayThread(1000 * 1000 * 5);

	log_modules();

	// hooking this linked addr does not do anything on ppsspp, but joysens' implementation suggests that it works on real hw?
	u32 sceCtrlReadBufferPositive_addr = (u32)sceCtrlReadBufferPositive;
	u32 sceCtrlReadBufferNegative_addr = (u32)sceCtrlReadBufferNegative;
	u32 sceCtrlPeekBufferPositive_addr = (u32)sceCtrlPeekBufferPositive;
	u32 sceCtrlPeekBufferNegative_addr = (u32)sceCtrlPeekBufferNegative;

	if(sceCtrlReadBufferPositive_addr == 0){
		LOG("sceCtrlReadBufferPositive_addr is 0, bailing out\n");
		return 1;
	}

	if(sceCtrlReadBufferNegative_addr == 0){
		LOG("sceCtrlReadBufferNegative_addr is 0, bailing out\n");
		return 1;
	}

	if(sceCtrlPeekBufferPositive_addr == 0){
		LOG("sceCtrlPeekBufferPositive_addr is 0, bailing out\n");
		return 1;
	}

	if(sceCtrlPeekBufferNegative_addr == 0){
		LOG("sceCtrlPeekBufferNegative_addr is 0, bailing out\n");
		return 1;
	}

	// it seems that these location are JR SYSCALL, at least on PPSSPP
	// given joysens hooks by messing with the immediate JAL from the linked function, I'd assume this is a PPSSPP difference
	// (could it also be.. nah it's JR SYSCALL, so it'll run SYSCALL then JR, things after that don't matter)
	// messing with the linked function also does not affect games in PPSSPP so perhaps the stubs are not even shared between modules
	// hmm what to do

	HIJACK_SYSCALL_STUB(sceCtrlReadBufferPositive_addr, sceCtrlReadBufferPositivePatched, sceCtrlReadBufferPositiveOrig);
	HIJACK_SYSCALL_STUB(sceCtrlReadBufferNegative_addr, sceCtrlReadBufferNegativePatched, sceCtrlReadBufferNegativeOrig);
	HIJACK_SYSCALL_STUB(sceCtrlPeekBufferPositive_addr, sceCtrlPeekBufferPositivePatched, sceCtrlPeekBufferPositiveOrig);
	HIJACK_SYSCALL_STUB(sceCtrlPeekBufferNegative_addr, sceCtrlPeekBufferNegativePatched, sceCtrlPeekBufferNegativeOrig);

	sceKernelDcacheWritebackAll();
	sceKernelIcacheClearAll();

	while(0){
		sceKernelDelayThread(1000 * 16);

		SceCtrlData buf[200];
		int cnt = sceCtrlPeekBufferPositiveOrig(buf, 5);
		LOG("sceCtrlPeekBufferPositiveOrig returned %d\n", cnt);
		apply_analog_to_digital(buf, cnt > 5 ? 5 : cnt, 0);
	}
	LOG("main thread finishes\n");
	return 0;
}

void init(){
	#if DEBUG
	logfd = sceIoOpen( "ms0:/ra2d.log", PSP_O_WRONLY|PSP_O_CREAT|PSP_O_TRUNC, 0777);
	#endif

	LOG("module started\n");
	SceUID thid = sceKernelCreateThread("ra2d", main_thread, 0x18, 4*1024, 0, NULL);
	if(thid < 0){
		LOG("failed creating main thread\n")
		return;
	}
	LOG("created thread with thid 0x%x\n", thid);
	sceKernelStartThread(thid, 0, NULL);
	LOG("main thread started\n");
}

int OnModuleStart(SceModule2 *mod) {
    init(0);

	if (!previous)
	return 0;

	return previous(mod);
}

static void CheckModules() {
	init(1);
}

int module_start(SceSize args, void *argp) {
  sceCtrlSetSamplingMode(PSP_CTRL_MODE_ANALOG);
  is_emulator = sceIoDevctl("kemulator:", EMULATOR_DEVCTL__IS_EMULATOR, NULL, 0, NULL, 0) == 0;
  if (is_emulator) {
    // Just scan the modules using normal/official syscalls.
    CheckModules();
  } else {
    previous = sctrlHENSetStartModuleHandler(OnModuleStart);
  }
  return 0;
}
