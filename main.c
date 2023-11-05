/*
  Remastered Controls: Metal Gear Solid
  Copyright (C) 2018, TheFloW

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

PSP_MODULE_INFO("ra2d", 0x1007, 1, 0);

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
// what to do about latch? how to achieve the same?

#define MAKE_JUMP(a, f) _sw(0x08000000 | (((u32)(f) & 0x0FFFFFFC) >> 2), a);

#define HIJACK_FUNCTION(a, f, ptr) \
{ \
  LOG("hijacking function at 0x%lx with 0x%lx\n", (u32)a, (u32)f); \
  u32 _func_ = (u32)a; \
  u32 ff = (u32)f; \
  if(!is_emulator){ \
    ff = MakeSyscallStub(f); \
  } \
  static u32 patch_buffer[3]; \
  _sw(_lw(_func_), (u32)patch_buffer); \
  _sw(_lw(_func_ + 4), (u32)patch_buffer + 8);\
  MAKE_JUMP((u32)patch_buffer + 4, _func_ + 8); \
  _sw(0x08000000 | (((u32)(ff) >> 2) & 0x03FFFFFF), _func_); \
  _sw(0, _func_ + 4); \
  ptr = (void *)patch_buffer; \
}

void apply_analog_to_digital(SceCtrlData *pad_data, int count, int negative){
	if(count < 1){
		LOG("count is %d, processing skipped\n", count);
		return;
	}

	LOG("processing %d buffers in %s mode\n", count, negative? "negative" : "positive")

	int i;
	for(i = 0;i < count; i++){
		int buttons = negative ? ~pad_data[i].Buttons : pad_data[i].Buttons;
		int rx = pad_data[i].Rsrv[0];
		int ry = pad_data[i].Rsrv[1];
		int timestamp = pad_data->TimeStamp;

		LOG("timestamp: %d rx: %d ry: %d\n", timestamp, rx, ry);
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

	sceKernelDelayThread(10000);

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

	HIJACK_FUNCTION(sceCtrlReadBufferPositive_addr, sceCtrlReadBufferPositivePatched, sceCtrlReadBufferPositiveOrig);
	HIJACK_FUNCTION(sceCtrlReadBufferNegative_addr, sceCtrlReadBufferNegativePatched, sceCtrlReadBufferNegativeOrig);
	HIJACK_FUNCTION(sceCtrlPeekBufferPositive_addr, sceCtrlPeekBufferPositivePatched, sceCtrlPeekBufferPositiveOrig);
	HIJACK_FUNCTION(sceCtrlPeekBufferNegative_addr, sceCtrlPeekBufferNegativePatched, sceCtrlPeekBufferNegativeOrig);

	sceKernelDcacheWritebackAll();
	sceKernelIcacheClearAll();

	while(1){
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
	LOG("not on ppsspp, start main thread\n");
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
