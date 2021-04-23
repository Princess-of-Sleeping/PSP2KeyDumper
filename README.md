# PSP2KeyDumper

The key dumper for PS Vita.

# What is this Application?

An application that dumps(or extracts) the PS Vita key from the update file(.PUP).

# Installation

Install vpk and copy fw 3.60 PSP2UPDAT.PUP to `ux0:app/VKEY00001/`.

Users with Devkit can also copy to `host0:data/` instead of `ux0:app/VKEY00001/`.

# Enjoy

The launch PSP2KeyDumper.

If nothing is wrong, the key will be dumped properly and saved as a c language file in `host0:data/vita_key/` or `sd0:data/vita_key/` or `ux0:data/vita_key/`.

# Information

Currently only known keys of F00D are dumped.
As a result, kernel/user keys are not currently dumped, but will be supported in the future.

**If you dump with devkit you will need devkit PUP. The same is true for testkit.**

# Credits

Many stuff is from [reF00D](<https://github.com/dots-tb/reF00D>).

And from the HENkaku wiki, vitadev wiki.
