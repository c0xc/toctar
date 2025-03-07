TOCTAR
======

TOCTAR is a simple tape backup tool with checksum validation.

It uses the well known and age old tar program, so it's compatible with tar.
It features a central table of contents (toc) which allows it to give you
an instant overview of all files in the archive. Even if it's a multi-volume
tape archive, you don't have to wait for hours and switch tapes to find out
if the files you're looking for are in the archive or not.
That's because TOCTAR uses its own table of contents, whereas tar would scan
the whole archive which takes a lot of precious time.

TOCTAR allows you to verify the integrity of the archive to make sure
it's not damaged. This checksum validation works by calculating the
checksums of all the files in the archive and comparing them with the
original checksums that were calculated when the archive was created.
If some files weren't written correctly or have been changed or damaged,
this checksum validation would tell you.



Example
-------

Create TOCTAR archive of a directory:

    $ toctar create /zbod1/DUMP/test/2rand/
    # Using default tape device: /dev/nst0
    ### CREATING TARBALL BACKUP => nst0...
    ### THIS WILL OVERWRITE THE TAPE ARCHIVE AT /dev/nst0 [#0] ...
    ## CREATING TOC / SCANNING FILES...
    ...
    .TARTOC
    tar: Removing leading `/' from member names
    /zbod1/DUMP/test/2rand/
    /zbod1/DUMP/test/2rand/randrw.4.0
    tar: Removing leading `/' from hard link targets
    /zbod1/DUMP/test/2rand/randrw.5.0
    /zbod1/DUMP/test/2rand/randrw.1.0 blank
    /zbod1/DUMP/test/2rand/randrw.7.0
    /zbod1/DUMP/test/2rand/randrw.6.0
    /zbod1/DUMP/test/2rand/randrw.2.0
    /zbod1/DUMP/test/2rand/randrw.3.0
    /zbod1/DUMP/test/2rand/randrw.0.0

Without -t option, the tape in the first drive is used.

Detect archive on current tape:

    $ toctar info
    # Using default tape device: /dev/nst0
    TOCTAR archive found
    TOCTAR archive created: Sun Jan  5 01:36:06 PM CET 2025

List files from tape:

    $ toctar list
    # Using default tape device: /dev/nst0
    /zbod1/DUMP/test/2rand/randrw.4.0
    /zbod1/DUMP/test/2rand/randrw.5.0
    /zbod1/DUMP/test/2rand/randrw.1.0 blank
    /zbod1/DUMP/test/2rand/randrw.7.0
    /zbod1/DUMP/test/2rand/randrw.6.0
    /zbod1/DUMP/test/2rand/randrw.2.0
    /zbod1/DUMP/test/2rand/randrw.3.0
    /zbod1/DUMP/test/2rand/randrw.0.0

Manually write classic tar archive, fast forward, find the tape, insert it and
detect the archive on current tape:

    $ mt-st -f /dev/nst0 rewind
    $ tar cvf /dev/nst0 /zbod1/DUMP/test/2rand/randrw.2.0
    tar: Removing leading `/' from member names
    /zbod1/DUMP/test/2rand/randrw.2.0

    $ toctar info
    # Using default tape device: /dev/nst0
    NOT A TOCTAR ARCHIVE, but TAR archive detected



Installation
------------

You might place this script in `~/bin/toctar` to be able to call it as `toctar`.

For the most part, it uses standard tools like Bash, Perl and so on,
all of which are available on any normal Linux installation.

Tape handling is done using the `mt` or `mt-st` program.
Unless you need to be root to be able to read all files for the backup,
there's nothing in the script that requires root privileges.
Your user may have to be in the `tape` group though, to be able to access the st device.



Usage
-----

As TOCTAR was designed with LTO tapes in mind, it defaults to using
a (the first) tape device found in the system.
To work with an archive file somewhere on your filesystem,
use the `-f file.tar` option.
On tapes, TOCTAR works with the first tape file by default.
To work with more than one archive per tape, please refer to the index option
or check out the --auto-append feature.

To create a new archive (overwriting an existing file):

    toctar create [-C parent_dir1] dir1 [-C parent_dir2] dir2

To create an archive in the second tape file:

    toctar create -i 1 dir...

To create a new archive at the end, leaving existing archives:

    toctar create --auto-append dir...

This may fail if you have a corrupt/incomplete archive in a tape file.
For example, if you've created two archives and damaged the second one
but you haven't wiped the tape because you don't want to lose the first
archive on there, then use the index option (-i 1) to overwrite the second one.

To list the contents of an archive:

    toctar verify

To list the contents of the second archive:

    toctar verify -i 1

To verify an archive:

    toctar verify

To extract an archive:

    toctar extract

During a "create" process, you'll notice that most status messages
are prefixed with a hash sign (#) and sent to stderr.
That's done to make it easier to filter those away.



Rationale (or how to backup 10T+ of data)
---------

Thinking about how I could create and store off-site backups
of more than 10 terabytes of data, I decided that tar is the best tool
for the job, except it doesn't store checksums to deal with data corruption.
What's the point of having a backup to restore files after they were corrupted
on a bad hdd, just to find out that the backup archive is corrupted as well?
It may be unlikely, but with 10 TB of important files, I want to be able
to verify the integrity of each file to make sure it's not damaged
in the backup archive just like on the live system (ZFS).

The tar programm is called "tape archive" for a reason.
It's made for tapes and it's open source.
Tapes seem like the obvious choice as they're cheap.
Unlike hard disk drives with spinning disks, tapes are commonly used for backups exclusively.
Commercial backup software is not an option as it would be closed source,
which means you have to trust some company that their product works reliably
(checksum validation) and that it doesn't have any backdoors or
extra features ("to improve user experience all metadata is sent to our hq").

I believe tar is almost perfect for a backup like this one.
It's only missing checksumming and indexing.
These features are provided by TOCTAR.

Looking for existing solutions, I've read tips like this one:

> Make sure that if your folder names contains spaces, use single quotes ' within: tobk="'/mnt/extdisk/Disc 7/ISOs' /var/log". Finally, run it as root.
> (a 277 character long command line)
> Make sure to put the resulting .lst and .sha512 files into a small flash drive and/or CD-R alongside the LTO tape.

Tips like that one are helpful but they require too much command line voodoo.
And much more important: Why would you burn an optical disc with those hash lists?
Where would you store those round discs if your tapes are in storage cases?
What if those discs are damaged?

TOCTAR is an attempt to solve these problems without losing the compatibility with tar.
It stores all the checksums right in the archive.



Author
------

Philip Seeger (philip@c0xc.net)



License
-------

This program may be used, modified and redistributed free of charge.
I'd like to add one condition: Elements of the military-industrial complex
and organizations working on a 1984-like total surveillance state
are prohibited from using this program (modified or not).

Please see the file called LICENSE if you enjoy complicated legal jargon.



