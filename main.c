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
static unsigned int yp_btn = PSP_CTRL_SQUARE;
static unsigned int yn_btn = PSP_CTRL_CROSS;
static unsigned int xp_btn = 0;
static unsigned int xn_btn = 0;
static unsigned char outer_deadzone = 20;
static unsigned char inner_deadzone = 10;

static u32 window = 16; // frame

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

#define CONV_LE(addr, dest) { \
	dest = addr[0] | addr[1] << 8 | addr[2] << 16 | addr[3] << 24; \
}

#define CONV_LE16(addr, dest) { \
	dest = addr[0] | addr[1] << 8; \
}

static int get_disc_id(char *out_buf){
	char *sfo_path = "disc0:/PSP_GAME/PARAM.SFO";
	int fd = sceIoOpen(sfo_path, PSP_O_RDONLY,0);
	if(fd <= 0){
		LOG("cannot open %s for reading\n", sfo_path);
		return -1;
	}

	sceIoLseek(fd, 0x08, PSP_SEEK_SET);
	unsigned char buf[4];
	if(sceIoRead(fd, &buf, 4) != 4){
		sceIoClose(fd);
		LOG("failed reading key table start from sfo\n");
		return -1;
	}
	u32 key_table_start = 0;
	CONV_LE(buf, key_table_start);
	LOG_VERBOSE("key_table_start is %ld\n", key_table_start);

	if(sceIoRead(fd, &buf, 4) != 4){
		sceIoClose(fd);
		LOG("failed reading data table start from sfo\n");
		return -1;
	}
	u32 data_table_start = 0;
	CONV_LE(buf, data_table_start);
	LOG_VERBOSE("data_table_start is %ld\n", data_table_start);

	if(sceIoRead(fd, &buf, 4) != 4){
		sceIoClose(fd);
		LOG("failed reading tables entries from sfo\n");
		return -1;
	}
	u32 tables_entries = 0;
	CONV_LE(buf, tables_entries);
	LOG_VERBOSE("tables_entries is %ld\n", tables_entries);

	int i;
	for(i = 0;i < tables_entries;i++){
		sceIoLseek(fd, 0x14 + i * 0x10, PSP_SEEK_SET);
		if(sceIoRead(fd, &buf, 2) != 2){
			sceIoClose(fd);
			LOG("failed reading key offset from sfo\n");
			return -1;
		}
		u32 key_offset = 0;
		CONV_LE16(buf, key_offset);

		if(sceIoRead(fd, &buf, 2) != 2){
			sceIoClose(fd);
			LOG("failed reading data format from sfo\n");
			return -1;
		}
		u32 data_format = 0;
		CONV_LE16(buf, data_format);

		if(sceIoRead(fd, &buf, 4) != 4){
			sceIoClose(fd);
			LOG("failed reading data len from sfo\n");
			return -1;
		}
		u32 data_len = 0;
		CONV_LE(buf, data_len);

		sceIoLseek(fd, 4, PSP_SEEK_CUR);
		if(sceIoRead(fd, &buf, 4) != 4){
			sceIoClose(fd);
			LOG("failed reading data offset from sfo\n");
			return -1;
		}
		u32 data_offset = 0;
		CONV_LE(buf, data_offset);

		sceIoLseek(fd, key_offset + key_table_start, PSP_SEEK_SET);
		char keybuf[50];
		int j;
		for(j = 0;j < 50;j++){
			if(sceIoRead(fd, &keybuf[j], 1) != 1){
				sceIoClose(fd);
				LOG("failed reading key from sfo\n");
			}
			if(keybuf[j] == 0){
				break;
			}
		}
		LOG_VERBOSE("key is %s\n", keybuf);

		sceIoLseek(fd, data_offset + data_table_start, PSP_SEEK_SET);
		char databuf[data_len];
		for(j = 0;j < data_len; j++){
			if(sceIoRead(fd, &databuf[j], 1) != 1){
				sceIoClose(fd);
				LOG("failed reading data from sfo\n");
			}
		}
		if(data_format == 0x0204){
			LOG_VERBOSE("utf8 data: %s\n", databuf);
		}else{
			LOG_VERBOSE("data is not utf8, not printing\n");
		}

		if(strncmp("DISC_ID", keybuf, 50) == 0){
			strcpy(out_buf, databuf);
			break;
		}
	}

	sceIoClose(fd);
	return 0;
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

// up down left right
enum axis_names{
	AXIS_YN = 0,
	AXIS_YP = 1,
	AXIS_XN = 2,
	AXIS_XP = 3,
	AXIS_CNT = 4
};

static void map_button(char *string, int axis){
	char *axis_name;
	switch(axis){
		case AXIS_XP:
			axis_name = "x positive";
			break;
		case AXIS_XN:
			axis_name = "x negative";
			break;
		case AXIS_YP:
			axis_name = "y positive";
			break;
		case AXIS_YN:
			axis_name = "y negative";
			break;
	}

	int button = -1;
	#define STRING_BTN_PAIR(str, btn){ \
		if(strcmp(string, str) == 0){ \
			LOG("mapping %s to %s\n", axis_name, string); \
			button = btn; \
		} \
	}
	STRING_BTN_PAIR("up", PSP_CTRL_UP);
	STRING_BTN_PAIR("right", PSP_CTRL_RIGHT);
	STRING_BTN_PAIR("down", PSP_CTRL_DOWN);
	STRING_BTN_PAIR("left", PSP_CTRL_LEFT);
	STRING_BTN_PAIR("ltrigger", PSP_CTRL_LTRIGGER);
	STRING_BTN_PAIR("rtrigger", PSP_CTRL_RTRIGGER);
	STRING_BTN_PAIR("triangle", PSP_CTRL_TRIANGLE);
	STRING_BTN_PAIR("circle", PSP_CTRL_CIRCLE);
	STRING_BTN_PAIR("cross", PSP_CTRL_CROSS);
	STRING_BTN_PAIR("square", PSP_CTRL_SQUARE);
	STRING_BTN_PAIR("none", 0);

	if(button != -1){
		switch(axis){
			case AXIS_XP:
				xp_btn = button;
				return;
			case AXIS_XN:
				xn_btn = button;
				return;
			case AXIS_YP:
				yp_btn = button;
				return;
			case AXIS_YN:
				yn_btn = button;
				return;
		}
	}
	LOG("unrecognized button %s while trying to map %s\n", string, axis_name);
}

static void read_config(char *disc_id, int disc_id_valid){
	char path[100];
	sprintf(path, "ms0:/PSP/ra2d_conf/%s", disc_id_valid ? disc_id: "homebrew");
	int fd = sceIoOpen(path, PSP_O_RDONLY, 0777);
	if(fd <= 0){
		LOG("cannot load config from %s\n", path);
		return;
	}

	int i;
	for(i = 0;i < AXIS_CNT; i++){
		int j;
		char readbuf[50];
		for(j = 0;j < 50; j++){
			if(sceIoRead(fd, &readbuf[j], 1) != 1){
				LOG("bad config file\n");
				sceIoClose(fd);
				return;
			}
			if(readbuf[j] == ' ' || readbuf[j] == '\r' || readbuf[j] == '\n'){
				readbuf[j] = '\0';
				break;
			}
		}
		if(readbuf[j] != '\0'){
			LOG("bad config file with long button name\n");
			sceIoClose(fd);
			return;
		}
		map_button(readbuf, i);
	}

	sceIoClose(fd);
}

int main_thread(SceSize args, void *argp){
	LOG("main thread begins\n");

	sceKernelDelayThread(1000 * 1000 * 5);
	LOG("changing polling rate and forcing analog mode");
	sceCtrlSetSamplingCycle(5555);
	sceCtrlSetSamplingMode(PSP_CTRL_MODE_ANALOG);

	char disc_id[50];
	int disc_id_valid = get_disc_id(disc_id) == 0;
	if(disc_id_valid){
		LOG("disc id is %s\n", disc_id);
	}else{
		LOG("cannot find disc id from sfo\n");
	}
	read_config(disc_id, disc_id_valid);

	if(is_emulator){
		log_modules();
	}

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
	logfd = sceIoOpen("ms0:/PSP/ra2d.log", PSP_O_WRONLY|PSP_O_CREAT|PSP_O_TRUNC, 0777);
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
  is_emulator = sceIoDevctl("kemulator:", EMULATOR_DEVCTL__IS_EMULATOR, NULL, 0, NULL, 0) == 0;
  if (is_emulator) {
    // Just scan the modules using normal/official syscalls.
    CheckModules();
  } else {
    previous = sctrlHENSetStartModuleHandler(OnModuleStart);
  }
  return 0;
}
