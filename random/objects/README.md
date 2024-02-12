# Summary

Source code for target is in UAF-Object.cpp, compiles into "logbook"

The binary allows a user to create a logbook and call one of its functions. The function is still callable after the object is free'd. The user can also request memory.

If the user deletes the logbook then requests a chunk of the same size as the logbook, they can overwrite the logbook's vtable. This hijacks the provided function.

I've pointed it at a one gadget. This is due to system() not being a viable candidate, as the first argument to the function will be the "self" pointer. system(self) isn't very useful...

I also had to do this in docker, as CET was pretty much impossible to get around as far as I could tell. This allowed me to build targetting an older libc (2.27). This libc also has easier one-gadgets.

# Instructions

Run ./run.sh and navigate to the /root directory.
Run ./exploit.py
Enjoy shell