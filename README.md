# nmskat

Integration of No Man's Sky with KAT Walk C2 treadmill.

## Project status

The current version injects tracking of C2 treadmill rotation as a "snap turn" of the game.

For injection to work you need to enable rotation with "Snap" mode and disable vibration.

It's working nicely with only slight problem: you are on the treadmill as well, which means
both your body AND head is turning, which means in game **your head turned twice than body**.

If you have any ideas on how to fix that -- I'm all ears (and conitnue to looking for a
solution myself in meanwhile).

## Installation

Because of the bug above -- no installation package yet prepared. Just open in visual studio
and build yourself if you want to try it out.

Copy KATNativeSDK into game folder near the `nms.exe` file.
