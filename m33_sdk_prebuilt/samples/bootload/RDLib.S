	.set noreorder

#include "pspstub.s"

	STUB_START "RDLib",0x40090000,0x00030005
	STUB_FUNC  0xB805243E,RestoreExitGame
	STUB_FUNC  0x7F3D307A,SetConfFile
	STUB_FUNC  0xB64186D0,SetUmdFile
	STUB_END
