#include <pspsdk.h>
#include <pspkernel.h>
#include <pspdebug.h>
#include <pspctrl.h>
#include <psploadexec_kernel.h>
#include <kubridge.h>
#include <systemctrl.h>
#include <systemctrl_se.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "rdriver.h"

PSP_MODULE_INFO("BootLoad Test", 0x200, 1, 0);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER);

PSP_HEAP_SIZE_MAX();

#define printf    pspDebugScreenPrintf

void ErrorExit(int milisecs, char *fmt, ...)
{
	va_list list;
	char msg[256];	

	va_start(list, fmt);
	vsprintf(msg, fmt, list);
	va_end(list);

	printf(msg);
	
	sceKernelDelayThread(milisecs*1000);
	sceKernelExitGame();

	asm("break\n");
	while (1);
}

int WriteFile(char *file, void *buf, int size)
{
	SceUID fd = sceIoOpen(file, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
	
	if (fd < 0)
	{
		return fd;
	}

	int written = sceIoWrite(fd, buf, size);

	sceIoClose(fd);
	return written;
}

int Dialog(char *msg)
{
	printf("%s", msg);

	while (1)
	{
		SceCtrlData pad;

		sceCtrlReadBufferPositive(&pad, 1);

		if (pad.Buttons & PSP_CTRL_CROSS)
			return 1;

		if (pad.Buttons & PSP_CTRL_RTRIGGER)
			return 0;

		sceKernelDelayThread(50000);
	}

	return -1;
}

int main(int argc, char *argv[])
{
	struct SceKernelLoadExecVSHParam param;
	int apitype = 0;
	char *program = NULL;
	char *mode = NULL;
	
	pspDebugScreenInit();
	
	SceUID mod = sceKernelLoadModule("rdriver.prx", 0, NULL);
	if (mod >= 0)
	{
		mod = sceKernelStartModule(mod, 0, NULL, NULL, NULL);
		if (mod < 0)
			ErrorExit(5000, "Error 0x%08X starting module.\n", mod);
	}
	else
	{
		if (mod == SCE_KERNEL_ERROR_EXCLUSIVE_LOAD)
		{
			// Ignore this error, it means the module loaded on reboot
		}
		else
		{
			ErrorExit(5000, "Error 0x%08X loading module.\n",  mod);
		}
	}

	printf("Press X to run homebrew at ms0:/PSP/GAME/HOMEBREW/EBOOT.PBP\n");
	printf("Press O to run UMD.\n");
	printf("Press triangle to run iso at ms0:/ISO/iso.iso in current M33 config mode.\n");
	printf("Press square to run pops game at ms0:/PSP/GAME/PSX/EBOOT.PBP.\n");
	printf("Press select to run updater at ms0:/PSP/GAME/UPDATE/EBOOT.PBP.\n");
	printf("Press start to exit.\n\n");
	printf("Note: when you exit in one of these programs, you will return here.\n");

	while (1)
	{
		SceCtrlData pad;

		sceCtrlReadBufferPositive(&pad, 1);

		if (pad.Buttons & PSP_CTRL_CROSS)
		{
			apitype = 0x141;
			program = "ms0:/PSP/GAME/HOMEBREW/EBOOT.PBP";
			mode = "game";
			break;
		}
		else if (pad.Buttons & PSP_CTRL_CIRCLE)
		{
			apitype = 0x120;
			program = "disc0:/PSP_GAME/SYSDIR/EBOOT.BIN";
			mode = "game";
			break;
		}
		else if (pad.Buttons & PSP_CTRL_TRIANGLE)
		{
			SEConfig config;
			
			apitype = 0x120;
			program = "disc0:/PSP_GAME/SYSDIR/EBOOT.BIN";
			mode = "game";

			SetUmdFile("ms0:/ISO/iso.iso");
			sctrlSEGetConfigEx(&config, sizeof(config));

			if (config.umdmode == MODE_MARCH33)
			{
				SetConfFile(1);
			}
			else if (config.umdmode == MODE_NP9660)
			{
				SetConfFile(2);
			}
			else
			{
				// Assume this is is normal umd mode, as isofs will be deleted soon
				SetConfFile(0);
			}

			break;
		}
		else if (pad.Buttons & PSP_CTRL_SQUARE)
		{
			apitype = 0x143;
			program = "ms0:/PSP/GAME/PSX/EBOOT.PBP";
			mode = "pops";
			break;
		}

		else if (pad.Buttons & PSP_CTRL_SELECT)
		{
			apitype = 0x140;
			program = "ms0:/PSP/GAME/UPDATE/EBOOT.PBP";
			mode = "updater";
			break;
		}
		else if (pad.Buttons & PSP_CTRL_START)
		{
			RestoreExitGame();
			sceKernelExitGame();
		}

		sceKernelDelayThread(50000);
	}

	sceDisplaySetHoldMode(1);
	pspDebugScreenSetTextColor(0x0000FF00);
	printf("\n\nLoading selection...\n");

	memset(&param, 0, sizeof(param));
	param.size = sizeof(param);
	param.args = strlen(program)+1;
	param.argp = program;
	param.key = mode;

	sctrlKernelLoadExecVSHWithApitype(apitype, program, &param);

    return 0;
}

