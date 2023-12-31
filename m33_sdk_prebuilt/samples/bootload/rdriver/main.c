#include <pspsdk.h>
#include <pspkernel.h>
#include <pspsysmem_kernel.h>
#include <psploadexec_kernel.h>
#include <pspreg.h>
#include <pspctrl.h>
#include <psprtc.h>
#include <pspusb.h>
#include <pspusbstor.h>
#include <psppower.h>
#include <systemctrl.h>
#include <systemctrl_se.h>
#include <stdio.h>
#include <string.h>

PSP_MODULE_INFO("rdriver", 0x1007, 1, 0);

u32 orig_funcs[2];

int ExitPatched()
{
	int k1 = pspSdkSetK1(0);
	
	// Using fixed path. See remarks in module_start of what you could do to avoid this
	char *program = "ms0:/PSP/GAME4XX/bootload/EBOOT.PBP";
	struct SceKernelLoadExecVSHParam param;

	memset(&param, 0, sizeof(param));
	param.size = sizeof(param);
	param.args = strlen(program)+1;
	param.argp = program;
	param.key = "game";

	int res = sctrlKernelLoadExecVSHMs2(program, &param);
	pspSdkSetK1(k1);
	return res;
}

int ExitPatched2()
{
	return ExitPatched();
}

int RestoreExitGame()
{
	int k1 = pspSdkSetK1(0);
	
	sctrlHENPatchSyscall((u32)ExitPatched, (void *)orig_funcs[0]); 
	sctrlHENPatchSyscall((u32)ExitPatched2, (void *)orig_funcs[1]); 

	pspSdkSetK1(k1);
	return 0;
}

void SetConfFile(int n)
{
	int k1 = pspSdkSetK1(0);
	sctrlSESetBootConfFileIndex(n);
	pspSdkSetK1(k1);
}

void SetUmdFile(char *umdfile)
{
	int k1 = pspSdkSetK1(0);
	sctrlSESetUmdFile(umdfile);
	pspSdkSetK1(k1);
}



int module_start(SceSize args, void *argp)
{
	// As in reboot we are executed with no params and we don't know our path,
	// we need to use a fixed path.
	// This could be solved if the program stores in a known location (for example seplugins)
	// the path of the program first time is run in the vsh
	
	SceUID fd = sceIoOpen("ms0:/PSP/GAME4XX/bootload/rdriver.prx", PSP_O_RDONLY, 0);
	if (fd < 0)
	{
		return 0;
	}

	int size = sceIoLseek(fd, 0, PSP_SEEK_END);
	sceIoLseek(fd, 0, PSP_SEEK_SET);

	SceUID pid = sceKernelAllocPartitionMemory(PSP_MEMORY_PARTITION_KERNEL, "", PSP_SMEM_Low, size, NULL);
	if (pid < 0)
		return 0;

	sceIoRead(fd, sceKernelGetBlockHeadAddr(pid), size);
	
	sctrlHENLoadModuleOnReboot("/kd/usersystemlib.prx", sceKernelGetBlockHeadAddr(pid), size, BOOTLOAD_GAME | BOOTLOAD_POPS | BOOTLOAD_UMDEMU);
	
	orig_funcs[0] = sctrlHENFindFunction("sceLoadExec", "LoadExecForUser", 0x05572A5F);
	orig_funcs[1] = sctrlHENFindFunction("sceLoadExec", "LoadExecForUser", 0x2AC9954B);
	sctrlHENPatchSyscall(orig_funcs[0], ExitPatched); // sceKernelExitGame
	sctrlHENPatchSyscall(orig_funcs[1], ExitPatched2); // sceKernelExitGameWithStatus

	// Alternativelly you would patch kernel functions here too
	// to avoid errors returning to xmb, or to avoid kernel homebrew exiting to xmb

	sceKernelDcacheWritebackAll();
	sceKernelIcacheClearAll();
	
	return 0;
}

