Generic analog to digital buttom spam

This was inspired by https://www.youtube.com/watch?v=3kNy_7blFTc

A more elegant solution for individual games would be to reverse them to find their internal brake/throttle/camera entry points, then map buttons to them accordingly

### Usage

- load prx with game, see https://www.ppsspp.org/docs/reference/plugins/ for ppsspp
- be sure to map right analog stick in ppsspp settings, note that it is possible to map analog triggers to them
- the hooking code may or may not work with a vita, don't have one to test, refer to how one can load psp prx plugins over there

### Config files

Configuration files are in the following format:

```
<right stick up button> <right stick down button> <right stick left button> <right stick right button> <window frames> <sceCtrlSetSamplingCycle override, 5555 - 20000> <spread/group>
```

button codes are the following:
```
up
right
down
left
ltrigger
rtrigger
triangle
circle
cross
square
none
```

During initialization, the plugin loads configurations from `ms0:/PSP/ra2d_conf/<DISC_ID>`

If a config file is not found, the following default config is applied, where right stick up is mapped to cross, right stick down is mapped to square, "analog input" is applied every 8 input frames, button inputs are injected into the beginning of every 8 frames, controller sampling rate is synced to render frame rate unless specified otherwise by the game. This default should work with most racing games.

```
cross square none none 8 0 group
```

eg. `ms0:/PSP/ra2d_conf/UCES01245`, Gran Turismo EU, with right trigger mapped as throttle and left trigger mapped as brake in-game, "analog input" is applied every 18 input frames, button inputs are injected into the beginning of every 18 frames, forcing 5555 micro seconds between each controller sampling (~180 input frames per second).

```
rtrigger ltrigger none none 18 5555 group

personal GTPSP config
```

eg. `ms0:/PSP/ra2d_conf/ULES00124`, Coded Arms EU, with face buttons as camera control, "analog input" is applied every 6 input frames, button inputs are injected evenly accross every 6 input frames if possible, forcing 5555 micro second between each controller sampling (180 input frames per second).

```
triangle cross square circle 6 5555 spread

personal coded arms config
```

The plugin will also attempt to load `ms0:/PSP/ra2d_conf/homebrew` if it cannot determine `DISC_ID` from sfo

### Window frames and button injection algo

To simulate analog input by spamming a digital button, button hold/spams are applied every window of frames. Below illustrate 50% analog input with 8 as the window frames size, with the group algo

```
<pressed> <pressed> <pressed> <pressed> <released> <released> <released> <released> ...(repeats)

frames --->
```

With the spread algo instead

```
<pressed> <released> <pressed> <released> <pressed> <released> <pressed> <released> ...(repeats)

frames --->
```

How the game behaves depends on how they handle fast button flips, whether a button held acceleration or smoothing is applied or not.

### Notes

- spamming button input general don't work well with camera controls, games don't really smooth out repeated button presses. While you can get slowed down camera movement, it'll usually be choppy
- somes games relies on sceCtrlSetSamplingCycle, more specificly sceCtrlReadBuffer* to maintain game/game physics speed, so a sceCtrlSetSamplingCycle override cannot be applied to those

### Hooking references

- https://github.com/TheOfficialFloW/RemasteredControls
- https://github.com/albe/joysens

### TODO

- when I have a psp again, finish real hardware hooking
