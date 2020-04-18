TOCTAR - ideas
==============

TOCTAR is supposed to ...
0) be compatible with TAR (open source, reliable, available everywhere)
1) write checksums, provide checksum validation
2) provide fast indexing, to get a complete list of files within seconds
3) have a simple command interface, hiding some gory details
4) work with Ultrium LTO tapes under Linux

0)
Any closed-source tool would be a bad choice, not only because
you have to trust the vendor that it does the right thing and nothing else.
On the other hand, tar will always be there for you.
Even if you lose and forget about TOCTAR over the years,
you will still be able to extract archives created by TOCTAR.
That way, you'll get your files, even though tar won't verify them.

1)
Checksum validation allows you to verify that all file in the archive on tape
are still correct. This is done by recalculating the checksums and comparing
them to those that were calculated when the archive was created.
Those original checksums are calculated from the original files on disk,
before they're written to the tape.

2)
The lack of a central index is a downside of the tar format.
Using standard tar only, you'd have to scan the whole tape archive,
which might consist of multiple tapes (multi volume archive),
to generate a complete list of files. That would take hours.
TOCTAR creates a file index at the beginning of the tape,
which can later be read within seconds.
TODO
The downside of this approach is that TOCTAR has to overwrite and update
this index when appending files to the tape archive. That is, if something
is appended to the first tape archive rather than creating a new one in
a second "tape file" (the main archive being the first tape file),
losing the fast index feature.

3)
TOCTAR is supposed to work with LTO tapes, it defaults to the first tape drive
found on the system and it does not require any previous configuration.
The admin does not have to (and should not) configure a specific block size.
TOCTAR tries to take care of that all by itself.

4)
TOCTAR was designed and written for LTO tapes but that doesn't necessarily
mean that it won't work with other tapes.



APPENDING
---------

Appending to an existing tape archive is tricky because the index
has to be updated. To allow such updates, a large area at the beginning
of the archive is reserved.

In theory (and in the case of regular files instead of tapes), the
updated TOC index would have to be written to the tape,
overwriting the existing TOC, which would be a matter of seconds.
Unfortunately, by default a filemark would be written after the TOC update,
damaging (truncating) the existing archive:
"By default the driver writes one filemark when the device is closed after
writing and the last operation has been a write."
https://www.kernel.org/doc/Documentation/scsi/st.txt





