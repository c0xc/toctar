#!/bin/bash
set -o pipefail
set +o histexpand

# TAPE BACKUP TOOL - TOCTAR

# TODO find mt-st
# TODO IS_TAPE vs USE_TAPE
# TODO IS_MULTI vs NO_MULTI
# TODO nst0 (tape drive index) + rewind/asf rather than st0 // compression
# TODO pass -C thru and put everything in subdir DATA/
# TODO doc/help text (pod)
#

# Check dependencies
# TODO mt
MT=mt
for d in tar mt; do
    if ! type $d &>/dev/null; then
        echo "Dependency not found: $d" >&2
        exit 1
    fi
done

################################################################################

# Cleanup routine
function cleanup {
    if ! (( KEEP_TEMP_DIR )); then
        # Delete temp dir
        # Be sure we're deleting a directory in /tmp
        if [[ $(readlink -e "$TMP_DIR") =~ ^/tmp/ ]]; then
            rm -rf "$TMP_DIR"
        fi
    else
        echo "Leaving temp dir: $TMP_DIR" >&2
    fi
}
trap cleanup EXIT

################################################################################

# Create temporary directory
#TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'toctar.tmp')
TMP_DIR=$(mktemp -d '/tmp/TOCTAR.XXXXXXXXXX')
if [[ $? -ne 0 ]]; then
    echo "ERROR - failed to create temporary directory" >&2
    exit 3
fi

# TOC size 128 MB
TOC_FIX_SIZE=$((1024**2*128))

# Tape block size: 512 KB (by default)
# (Tests showed a 1h speed increase and almost 1G less wasted space using
# 4M instead of the default 10K.)
TAPE_BS_K=4096
TAPE_BS_B=$((TAPE_BS_K*1024))
TAR_FACTOR=$((TAPE_BS_B/512))
if [[ $TAPE_BS_B -eq 0 || $TAR_FACTOR -eq 0 ]]; then
    echo "ERROR - block size of zero defined" >&2
    exit 3
fi
DETECTED_BS=0

# We expect the archive to be in the first tape file unless otherwise specified
TAPE_FILE_INDEX=0

# Misc
CWD=${PWD:-.}

################################################################################

# Command argument
if [ $# -eq 0 ]; then
    echo "Command argument missing" >&2
    exit 1
fi
case "$1" in
    -h|help)
        echo you need help
        ;;
    -*)
        echo "Command argument missing (options must follow command)" >&2
        exit 1
        ;;
    *)
        cmd=$1
        ;;
esac
shift

# Options and arguments
IS_TAPE=0
KEEP_TEMP_DIR=0
TAR_FILE=
IS_MULTI=0 # TODO
ITEMS=()
REL_DIRS=()
IS_AUTO_DETECT_BS=1
CHECK_EXISTING=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)
            IS_DEBUG=1
            ;;
        -f|--archive)
            TAR_FILE=$2
            shift
            ;;
        -t|--tape)
            if [[ "$2" =~ ^[0-9]+$ ]]; then
                # Tape drive #
                TAR_FILE="/dev/nst$2"
                IS_TAPE=1
            else
                echo "Tape index expected after --tape" >&2
                exit 1
            fi
            shift
            ;;
        --multi-volume)
            IS_MULTI=1
            ;;
        --no-multi-volume)
            IS_MULTI=0
            ;;
        # TODO -- stop parsing -> -C d1 f1 -C d2 f2 ...
        -C|--directory)
            parent_dir_entry="${#ITEMS[@]};$2"
            REL_DIRS+=("$parent_dir_entry")
            shift
            ;;
        --auto-detect-bs)
            IS_AUTO_DETECT_BS=1
            ;;
        --no-auto-detect-bs)
            IS_AUTO_DETECT_BS=0
            ;;
        --no-check-existing)
            CHECK_EXISTING=0
            ;;
        --keep-temp-dir)
            KEEP_TEMP_DIR=1
            ;;
        --)
            # Stop parsing and take remaining arguments (as filenames)
            # TODO Check for illegal filenames elsewhere
            break
            ;;
        -*)
            echo "Option not recognized: $1" >&2
            exit 1
            ;;
        .*)
            echo "Hidden files not allowed: $1" >&2
            exit 1
            ;;
        *)
            ITEMS+=("$1")
            ;;
    esac
    shift
done
if [[ $# -gt 0 ]]; then
    ITEMS+=("$@")
    shift $#
fi

################################################################################

# Decides which file/device to use
# TODO I cannot decide how to make this decision lol
function set_device {
    # Tape defaults
    local drive_index=0
    local default_tape=/dev/nst${drive_index}
    # TODO /dev/tape

    # Use (first) tape if no tar file/device specified
    if [[ -z "$TAR_FILE" ]]; then
        echo "# Using default tape device: $default_tape" >&2
        TAR_FILE=$default_tape
        # Set IS_TAPE to check -c below, to not create a regular file nst0!
        IS_TAPE=1
    fi

    # Enable tape mode if a tape device was specified manually
    if [[ -b "$TAR_FILE" || -c "$TAR_FILE" ]]; then
        IS_TAPE=1
    fi

    # In tape mode, the device must exist
    if [[ $IS_TAPE -eq 1 ]]; then
        if [[ ! -b "$TAR_FILE" && ! -c "$TAR_FILE" ]]; then
            echo "Tape device not found: $TAR_FILE" >&2
            exit 1
        fi
    fi

    #    if ! touch "$TAR_FILE"; then
    #        echo "ERROR - failed to create tar file: $TAR_FILE" >&2
    #        exit 2
    #    fi

    # Tar name
    TAR_NAME=${TAR_FILE##*/}

}
set_device

function rewind {
    local index={1:-0}

    if [[ $IS_TAPE -eq 0 ]]; then
        return 0
    fi

    $MT -f "$TAR_FILE" asf "$index" || return $?
}

function tape_status_number {
    if [[ $IS_TAPE -ne 0 ]]; then
        $MT -f "$TAR_FILE" status | grep number
    fi
}

function tmp_file {
    # Create and return temp file (in temp dir)
    mktemp --tmpdir="$TMP_DIR" ".TARTOC.XXXXXXXXXX" || return $?
}

function detect_bs_once {
    # Return already detected bs
    # : ${DETECTED_BS:=0}
    if [ $DETECTED_BS -ne 0 ]; then
        echo -n "$DETECTED_BS"
        return
    fi

    # Rewind tape
    if [[ $IS_TAPE -eq 0 ]]; then
        echo 0
        return 1
    fi
    rewind $TAPE_FILE_INDEX || return $?

    # Detect block size once
    DETECTED_BS=$(detect_block_size)
    echo -n "$DETECTED_BS"

    # Rewind tape
    rewind $TAPE_FILE_INDEX || return $?
}

################################################################################

# TOC file creator
# Takes a temp file path as argument
# Writes TOC to file (by appending if old TOC provided)
# Final TOC file is zero-padded to use up fixed TOC size
function create_toc_file {
    local toc_file=$1 # TODO no need for local, toc_file is a global const

    # Add TOC header entry
    local ts ts2 entry
    ts=$(date +%s)
    entry="# TOC @$ts : "$'\t'"SIZE"$'\t'"MTIME"$'\t'"FILE"
    echo "$entry" >>"$toc_file"
    echo >>"$toc_file"

    # Go through requested tar files (e.g., files/dirs to be added)
    local cwd_now=$cwd
    local item path item_items file
    for i in ${!ITEMS[@]}; do
        item="${ITEMS[i]}"
        cwd_now=$(cwd_at_item "$i" $cwd)
        path="$cwd_now/$item"
        # path - real path to item (file)
        # item - filename or path relative to current parent dir (-C)
        # item is what we're putting in the tarball and in the TOC

        # Make sure file or directory (item) exists
        local is_dir=0
        if [[ -d "$path" ]]; then
            is_dir=1
        else
            if [[ ! -e "$path" ]]; then
                echo "ERROR - item not found: $path" >&2
                return 2
            fi
        fi

        # Item list - current file or directory contents
        item_items=
        if [[ -f "$path" ]]; then
            item_items=$item
        elif [[ -d "$path" ]]; then
            # Scan dir recursively to add all files to TOC
            # Results in relative path arguments are prefixed accordingly
            if [[ -z "$cwd_now" ]]; then
                item_items=$(find "$path" -mindepth 1 -type f)
            else
                item_items=$(find "$path" -mindepth 1 -type f -exec realpath --relative-to "$cwd_now" {} \;)
            fi
            if (( $? || ${PIPESTATUS[0]} )); then
                echo "ERROR - failed to scan directory: $path" >&2
                return 2
            fi
        else
            echo "skipping: $path" >&2
        fi

        while IFS= read -r file; do
            # again, path is the full path, file is relative to tar
            # Prepend base path (if specified)
            path="$cwd_now/$file"
            path=$(realpath "$path")
            if [[ $? -ne 0 ]]; then
                echo "ERROR - failed to resolve path: $path ($file)" >&2
                return 2
            fi
            echo "$path ..."
            # Metadata
            local size mtime hash
            size=$(stat --printf '%s' "$path")
            mtime=$(stat --printf '%Y' "$path")
            if [[ -z "$size" || -z "$mtime" ]]; then
                echo "ERROR - failed to stat file: $path" >&2
                return 2
            fi
            # Calculate hashsum
            hash="-"
            if [[ -f "$path" ]]; then
                hash=$(cat "$path" | sha256sum -)
                if (( $? || ${PIPESTATUS[0]} )); then
                    echo "ERROR - failed to scan file: $path" >&2
                    return 2
                fi
            fi
            # MD5: 32 chars; SHA1: 40; SHA256: 64
            hash=${hash::64}
            # Add TOC entry
            entry="$hash"$'\t'"$size"$'\t'"$mtime"$'\t'"$file"
            echo "$entry" >>"$toc_file"
        done <<<"$item_items"

    done

    # Add TOC footer entry
    # List might be extended later though
    ts2=$(date +%s)
    entry=$'\n'"#!TOC @$ts @$ts2"$'\n'
    echo "$entry" >>"$toc_file"
    if (( $? || ${PIPESTATUS[0]} )); then
        echo "ERROR - failed to write to TOC file" >&2
        return 2
    fi

    # Expand TOC file to fixed TOC size (128 MB) by zero-padding
    # That way, it can be extended later
    toc_size=$(stat --printf "%s" "$toc_file")
    if [[ $toc_size -gt $TOC_FIX_SIZE ]]; then
        echo "ERROR - TOC too big ($toc_size B)" >&2
        return 2
    fi
    toc_diff=$(($TOC_FIX_SIZE-$toc_size))
    cat >>"$toc_file" < <(head -c "$toc_diff" </dev/zero)
    if (( $? || ${PIPESTATUS[0]} )); then
        echo "ERROR - failed to fill TOC file (+ $toc_diff B)" >&2
        return 2
    fi

}

# Block size helper
function detect_block_size {

    # Rewind tape
    if [[ $IS_TAPE -eq 0 ]]; then
        echo 0
        return 1
    fi
    rewind $TAPE_FILE_INDEX || return $?

    # Temp file
    local ts=$(date +%s)
    local tmp_file="$TMP_DIR/.TARTOC.TMP.$$.$ts"
    truncate -s 0 "$tmp_file" || return $?

    # Read first block with large block size
    # If read_bs > real_bs, we get real_bs bytes (or an error, maybe)
    # If read_bs < real_bs, we get an error:
    # dd: error reading '/dev/nst0': Cannot allocate memory
    local read_bs dd_out dd_line rc
    read_bs=$((1024**2*4))
    dd_out=$(dd bs="$read_bs" count=1 if="$TAR_FILE" of="$tmp_file" 2>&1)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        echo "ERROR - failed to read block for testing" >&2
        echo "$dd_out" >&2
        return $rc
    fi

    # Check how much data we've received
    # TODO we don't really need that file
    local read_b_dd read_b_file real_bs
    dd_line=$(echo "$dd_out" | grep -E '^[0-9]+ bytes.*copied') || return $?
    read_b_dd=$(echo "$dd_line" | grep -Eo '^[0-9]+') || return $?
    read_b_file=$(stat --printf "%s" "$tmp_file") || return $?
    if [[ "$read_b_dd" != "$read_b_file" ]]; then
        echo "ERROR - block size mismatch ($read_b_dd != $read_b_file)" >&2
        return 1
    fi
    real_bs=$read_b_file
    if [[ $real_bs -eq 0 ]]; then
        echo "ERROR - failed to detect block size - no data read" >&2
        echo -n 0
        return 1
    fi
    echo "$real_bs"

    # TODO repeat if 0 / error...

    # Calculate numer of blocks to be read
    # Then read full TOC to double-check that all TOC blocks have the same bs
    # Now reading with previously detected "real" block size
    local full_size count i
    full_size=$((512+TOC_FIX_SIZE))
    count=$((full_size/read_bs+1))
    for ((i=0; i<count; i++)); do
        dd_out=$(dd bs="$real_bs" count=1 if="$TAR_FILE" of="/dev/null" 2>&1)
        dd_line=$(echo "$dd_out" | grep -E '^[0-9]+ bytes.*copied') || return $?
        read_b_dd=$(echo "$dd_line" | grep -Eo '^[0-9]+') || return $?
        if [[ "$read_b_dd" != "$real_bs" ]]; then
            echo "WARNING - block $i appears to be $read_b_dd B, expected $real_bs B" >&2
            return 1
        fi
    done

    # Rewind tape
    rewind $TAPE_FILE_INDEX || return $?
}

# TOC file extractor
# Takes a temp file path as (first) argument (will be created/truncated)
# Extracts the TOC file (fixed size)
# May use a temporary file as buffer (can be specified in second argument)
function extract_toc_file {
    local toc_file=$1 # target temporary file or blank for stdout
    local tmp_file=$2

    # Temp file
    if [ -z "$tmp_file" ]; then
        tmp_file=$(tmp_file) || return 1
    else
        if ! [[ $(readlink -f "$tmp_file") =~ ^/tmp ]]; then
            # Temp file not in temp dir # TODO global safeguard function
            return 1
        fi
    fi

    # About block sizes
    # The tar program uses a default of 10 KB blocks.
    # It seems like pretty much any other value is better than that.
    # We wanted to define a fixed block size of 4 MB for everything.
    # Why is this important?
    # The extract function is the perfect example. It was first written
    # to use dd to skip over the first 512 byte block and then read
    # the TOC area which is of a known size (divided by block size etc.).
    # Unfortunately, that approach will probably fail almost always,
    # unless a tape was written to with a block size of 512 bytes.
    # If a tape archive was created in 512K blocks, having dd skip
    # the first block (meant to skip the first 512 bytes) would actually
    # skip the first 512 KB block (duh), which already includes part
    # of the TOC area that we're trying to read.

    # Detect block size and rewind tape
    local bs=$TAPE_BS_B
    if [[ $IS_TAPE -eq 1 ]]; then
        if [ $IS_AUTO_DETECT_BS -ne 0 ]; then
            bs=$(detect_bs_once) || return $?
        fi
        rewind $TAPE_FILE_INDEX || return $?
    fi

    # Extract TOC to file (or stdout)
    # Use detected tape block size or default and calculate number of blocks
    local in_min=$((TOC_FIX_SIZE+512))
    local in_count=$((in_min/bs+1))
    local toc_count=$((TOC_FIX_SIZE/512))
    if [[ -n "$toc_file" && "$toc_file" != "-" ]]; then
        # Write extracted TOC to $toc_file
        # bs - block size used for reading (detected or default)
        # in_min - how much we'll have to read from the beginning (B)
        # in_count - number of blocks we'll have to read
        # in_min is TOC size + 512 (tar header).
        # in_count + 1 (one additional block) just to be on the safe side.
        # toc_count - number of 512B blocks in a TOC (without tar header)

        # Create (empty) file
        if ! truncate -s 0 "$toc_file"; then
            echo "ERROR - failed to create temporary TOC file $toc_file" >&2
            return 2
        fi

        # Read section containing TOC (verbatim)
        # This wouldn't work with different sized blocks on tape:
        # dd ibs=512 skip=1 count="$count" if="$TAR_FILE" of="$toc_file" || return $?
        # This'll return < count*bs if the tape blocks are smaller.
        # Default tar tape blocks are 20*512 = 10K.
        # There's iflag=fullblock, but it doesn't help with the count thing.
        # Anyway... First, we'll read a bit more than we need.
        local dd_out
        dd_out=$(dd ibs=$bs count=$in_count if="$TAR_FILE" of="$tmp_file" 2>&1)
        if [[ $? -ne 0 ]]; then
            echo "$dd_out" >&2
            return 1
        fi

        # Now copy TOC from temporary file to target file
        dd_out=$(dd ibs=512 skip=1 count="$toc_count" if="$tmp_file" of="$toc_file" 2>&1)
        if [[ $? -ne 0 ]]; then
            echo "$dd_out" >&2
            return 1
        fi

        # Double-check size (if < count*bs)
        local read_bytes=$(stat --printf "%s" "$toc_file")
        if [[ $read_bytes -ne $TOC_FIX_SIZE ]]; then
            # TODO print tape status for debugging
            tape_status_number
            echo "ERROR - failed to read TOC (read $read_bytes)" >&2
            return 2
        fi

        # Here's another piece of code that I've written twice
        # local full_size count i dd_out
        # full_size=$((512+TOC_FIX_SIZE))
        # count=$((full_size/read_bs+1))
        # dd_out=$(dd bs="$bs" count=1 if="$TAR_FILE" of="/dev/null" 2>&1)
        # for ((i=0; i<count; i++)); do
        #     dd_out=$(dd bs="$bs" count=1 oflag=notrunc if="$TAR_FILE" of="/dev/null" 2>&1)
        #     dd_line=$(echo "$dd_out" | grep -E '^[0-9]+ bytes.*copied') || return $?
        #     read_b_dd=$(echo "$dd_line" | grep -Eo '^[0-9]+') || return $?
        # ...

        # Verify that we've extracted a TOC by checking beginning
        # TODO implement better verify routine
        if [[ $(head -c 1 <"$toc_file") != "#" ]]; then
            echo "ERROR - extracted section not a TOC - is this even an archive?" >&2
            return 2
        fi
    else
        # Read first block, check it and print it, then read/print the rest
        # TODO this is totally untested
        # TODO EXPERIMENTAL, DON'T DO THIS, UNFINISHED, I HAVEN'T REALLY THOUGHT THIS THROUGH
        echo "EXPERIMENTAL"
        return 1

        # TODO read in loop, check dd_out, this is going to be great

    fi
}

# Replaces the TOC of an existing archive
# The TOC is on the first tape (on a multi-volume archive)
# This TOC area must be overwritten without truncating the archive
# TODO THIS MAY DAMAGE THE TAPE ARCHIVE BY WRITING A FILEMARK AFTER 132M
# It seems like the filemark is always written at the current position
# when the file handle is closed. And after replacing/updating the TOC,
# the tape is positioned after the TOC area, not at the end of the tar archive.
# Calling mt to move the tape forward (to the end of the tape file)
# isn't possible either while this program still holds an open file handle:
# /dev/nst0: Device or resource busy
function replace_toc {
    local toc_file=$1 # new TOC (source)

    # The TOC is always on the first tape in any multi-volume tape archive
    # The caller should've asked the user for the first tape

    # To read a short story about block sizes, see extract_toc_file...

    # Double-check input size
    toc_size=$(stat --printf "%s" "$toc_file")
    if [[ $toc_size -ne $TOC_FIX_SIZE ]]; then
        echo "ERROR - new TOC is ${toc_size}B, must be ${TOC_FIX_SIZE}B" >&2
        return 2
    fi

    # Detect block size and rewind tape
    local bs=$TAPE_BS_B
    if [[ $IS_TAPE -eq 1 ]]; then
        if [ $IS_AUTO_DETECT_BS -ne 0 ]; then
            bs=$(detect_bs_once) || return $?
        fi
        rewind $TAPE_FILE_INDEX || return $?
    fi

    # Extract TOC section (from the beginning)
    tmp_toc_file=$(tmp_file) || return 1
    tmp_section_file=$(tmp_file) || return 1
    extract_toc_file "$tmp_toc_file" "$tmp_section_file" || return 1
    local size=$(stat --printf "%s" "$tmp_section_file")
    local out_count=$((size/bs))
    # Rewind again
    rewind $TAPE_FILE_INDEX || return $?

    # Now copy TOC from source file into temporary file (after header)
    local dd_out
    dd_out=$(dd obs=512 seek=1 conv=notrunc if="$toc_file" of="$tmp_section_file" 2>&1)
    if [[ $? -ne 0 ]]; then
        echo "$dd_out" >&2
        return 1
    fi

    # Write updated TOC section to archive, overwriting it from the beginning
    # The TOC section is slightly larger than the TOC itself (buffer, bs).
    # However, the only thing that's different in the section file
    # is the now updated TOC inside of it.
    # It also contains a tar header of 512B which we're overwriting,
    # but we've just read/extracted that header from the archive,
    # so we're effectively not changing it.
    dd_out=$(dd obs=$bs conv=notrunc if="$tmp_section_file" of="$TAR_FILE" 2>&1)
echo "tmp_section_file=$tmp_section_file ($dd_out) " >&2
    if [[ $? -ne 0 ]]; then
        echo "$dd_out" >&2
        echo "ERROR - failed to overwrite TOC section - archive may be damaged" >&2
        return 2
    fi

}

# Get parent dir of item at specified position
function cwd_at_item {
    local pos=$1
    local cwd=$2
    local cwd_now
    [ -z "$cwd" ] && cwd=$PWD
    cwd_now=
    # Not prepending cwd unless explicit path prefix specified
    # Otherwise, we might prepend cwd to an absolute path.

    # Check for user-defined parent directory (starting at index i)
    for j in ${!REL_DIRS[@]}; do
        cur_par="${REL_DIRS[j]}"
        cur_from_i=${cur_par%%;*}
        cur_parent=${cur_par#*;}
        # Apply if we're at that position only
        # "only"/eq: a base path is applied to the following arg only
        if [[ $cur_from_i -eq $pos ]]; then
            cwd_now=$cur_parent
        fi
    done

    echo "$cwd_now"
}

# Ask user to something (INTERACTIVE)
function ask {
    local q=$*
    q="$q"$'\n'"[type y to confirm or n to decline]"
    read -p "$q " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}

# Generates a script specifically for tar
function gen_script {
    local toc_file=$1

    local raw=$(sed 's/^    //' <<'END'
    #!/usr/bin/env perl

    # This is a temporary command script created by TOCTAR.
    # It receives the contents of a file being extracted by tar.
    # It verifies the extracted file by calculating the checksum.
    # If more complexity/functionality is added, we'll think about
    # refactoring and create separate functions and packages.
    # For now, this is sufficient as a first version.

    use strict; use warnings;
    use Data::Dumper;
    use IPC::Open3;
    use Digest::MD5;
    use Digest::SHA;

    # Prepare stdin to read file contents (extracted by tar)
    my $fh = \*STDIN;
    binmode $fh or die "Failed to binmode STDIN: $!";

    # Metadata
    my $tar_realname = $ENV{TAR_REALNAME};
    my $tar_size = $ENV{TAR_SIZE};

    # Skip TOC file
    if ($tar_realname eq '.TARTOC') {
        exit;
    }

    # Read TOC file (map)
    # If a later/newer TOC section contains an old file again,
    # it's just updated in the map.
    my $map = {};
    my $toc_file = "%TOC_FILE%";
    my $in_toc_section;
    if (open(my $fh, '<:encoding(UTF-8)', $toc_file)) {
        while (my $row = <$fh>) {
            chomp $row;
            if (index($row, "\0") > -1) {
                last;
            }
            next if $row =~ /^\s*$/;
            # Check for TOC header
            if (!$in_toc_section) {
                if ($row =~ /^# TOC/) {
                    $in_toc_section = 1;
                    next;
                }
            }
            else {
                if ($row =~ /^#!TOC/) {
                    $in_toc_section = 0;
                    next;
                }
            }
            # Read TOC entry with TOC section
            next unless $in_toc_section;
            my ($toc_hash, $toc_size, $toc_mtime, $toc_filename) = $row =~ /^(\w+)\s+(\w+)\s+(\w+)\s+(.+)$/;
            if (!length($toc_filename)) {
                warn "### FAILED TO PARSE TOC line: $row";
                next;
            }
            $map->{$toc_filename} = {
                name => $toc_filename,
                hash => $toc_hash,
                size => $toc_size,
                mtime => $toc_mtime,
            };
        }

    }
    else {
        die "### FAILED TO OPEN TOC: $toc_file";
    }
    my $toc = $map->{$tar_realname};
    if (!$toc) {
        die "### FAILED TO FIND CONTENT FILE IN TOC: $tar_realname";
    }

    # Prepare output stream
    my $md5 = Digest::MD5->new;
    my $sha256 = Digest::SHA->new(256);
    my $out_fh;
    print STDERR "$tar_realname ... ";

    # Read tar contents
    my $bs = 1024*512; # 1024*512
    while (sysread $fh, my $data, $bs) {
        # Block received
        my $len = length($data); # (<= $bs)
        # Write block to hash stream
        #$md5->add($data);
        $sha256->add($data);
        # Write block to target file, if specified
        if ($out_fh) {
            print {$out_fh} $data;
        }
    }
    my $hash;
    $hash = $sha256->hexdigest;
    print STDERR "$hash => ";

    # TODO get TOC (tmp file) and compare hash sum
    # Check if calculated hash matches hash in TOC
    my $continue_error;
    my $hash_match = $toc->{hash} eq $hash;
    if ($hash_match) {
        print STDERR "VERIFIED OK\n";
    }
    else {
        print STDERR "MISMATCH!\n";
        warn "ERROR: $tar_realname does not match stored checksum!\n";
        warn "File appears to be corrupt\n";
        return 1 unless $continue_error;
    }

END
)

    # Put path to TOC file in script
    raw=$(echo "$raw" | sed 's!%TOC_FILE%!'"$toc_file!")
    raw=$(echo "$raw" | sed 's!%TMP_DIR%!'"$TMP_DIR!")

    # Save script
    local file=$(tmp_file)
    echo "$raw" >"$file" || return $?
    chmod +x "$file" || return $?
    echo "$file"
}

# Read TOC file and extract TOC section lines (without header, footer)
# TODO if requested, return single section only
function toc_lines {
    local toc_file=$1

    local in_toc_section=0
    while IFS= read -r line; do
        # Skip over header, footer lines
        [[ "$line" =~ ^\s*$ ]] && continue
        # Check for TOC header
        if ! (( $in_toc_section )); then
            if [[ "$line" =~ ^#\ TOC ]]; then
                in_toc_section=1
                continue
            fi
        else
            # Exclamation marks are funny: set +o histexpand
            if [[ "$line" =~ ^#!TOC ]]; then
                in_toc_section=0
                continue
            fi
        fi
        # Read TOC entry with TOC section
        (( $in_toc_section )) || continue
        echo "$line"

    done <"$toc_file"
}

# Read TOC file and extract file list, one in each line
# TODO alternating toc formats (columns)? => Perl parser
function toc_file_list {
    local toc_file=$1
    local toc_lines
    toc_lines=$(toc_lines "$toc_file")

    while IFS= read -r line; do
        echo "$line" | perl -ne '/^[a-zA-Z0-9]+\s+[a-zA-Z0-9]+\s+[a-zA-Z0-9]+\s+(.+)$/ && print $1'
        echo

    done <<<"$toc_lines"
}

################################################################################

# Most info, warn and debug messages are sent to stderr by default.
# That way, this extra output can be turned off
# and it won't be mixed with content/data, which is written to stdout.
# As usual, a return code of zero indicates success, anything else is an error.

# Command
if [[ $cmd == "create" || $cmd == "append" ]]; then
    # Create tar backup
    # Run pre-checks, check for tape (and if first MB empty?), create tarball
    # Create 100 MB sparse file as first file to be used as TOC
    if [[ "${#ITEMS[@]}" -eq 0 ]]; then
        echo "No directory selected for new backup" >&2
        exit 2
    fi

    # TODO append to same archive... ask for last tape, then append ...
    # fsfm or similar to not create another tape file

    # Say something and confirm
    echo "### CREATING TARBALL BACKUP => ${TAR_NAME}..." >&2
    echo "### THIS WILL OVERWRITE THE TAPE ARCHIVE AT ${TAR_FILE} [#$TAPE_FILE_INDEX] ..." >&2
    if [[ $IS_MULTI -eq 1 ]]; then
        ask "Please insert the [first] drive and confirm (hit Ctrl+C or type N to abort)" || exit 2
    fi

    # Check for existing archive that would be overwritten
    if (( $CHECK_EXISTING )); then
        # Run extract call in subshell because an error shouldn't be fatal
        tmp_toc_file=$(tmp_file)
        out=$(extract_toc_file "$tmp_toc_file" 2>/dev/null 1>&2)
        if [[ $? -eq 0 ]]; then
            echo "# TAR ARCHIVE HEADER DETECTED IN CURRENT TAPE FILE..." >&2
            ask "Really continue, overwriting previous contents?" || exit 2

        fi
    fi

    # Prepare TOC file (fixed name)
    # In append mode, rewind first to read the OLD TOC
    old_toc_file="$TMP_DIR/.TARTOC.OLD"
    toc_file="$TMP_DIR/.TARTOC"
    if [[ $cmd == "append" ]]; then
        echo "## READING OLD TOC..." >&2

        # Read *old* TOC from tape
        extract_toc_file "$old_toc_file" || exit $?

        # Truncate and copy OLD TOC
        sed -i 's/\x00\+$//' "$old_toc_file" || exit $?
        cp -f "$old_toc_file" "$toc_file" || exit $?
    else
        # Create empty TOC file
        echo -n >"$toc_file" || exit 3
    fi

    # Create index and write it to TOC file (temporary)
    echo "## CREATING TOC / SCANNING FILES..." >&2
    create_toc_file "$toc_file" || exit $?

    # Put arguments for tar together, first file will be the toc file
    echo "## CREATING TARBALL / COPYING FILES..." >&2
    cwd=$PWD
    args=()
    args+=("-b" "$TAR_FACTOR")
    args+=("-f" "$TAR_FILE")
    args+=("-v")
    [[ $IS_MULTI -eq 1 ]] && args+=("--multi-volume")
    if [[ $cmd == "create" ]]; then
        # Specify TOC as first file in the new archive
        args+=("-c" "-C" "$TMP_DIR" "${toc_file##*/}")
        # Rewind to beginning of [first] tape file
        rewind $TAPE_FILE_INDEX || exit $?
    elif [[ $cmd == "append" ]]; then
        # Replace old TOC on tape with new TOC
        # This is the crucial part. We are overwriting the first section
        # of the archive to replace it with an extended version.
        # The first tape must be inserted, which is the case, see above.
        replace_toc "$toc_file" || exit $?
        # Tell Tar to update the archive
        args+=("--append")

        # Ask for last tape
        # TODO wouldn't it be great if tar would check for the last tape
        # TODO if is_multi ...
        if [[ $IS_TAPE -eq 1 ]]; then
            ask "Please insert the LAST tape and confirm"
            if [ $? -ne 0 ]; then
                echo "NOTE: The archive is in an inconsistent state." 2>&2
                echo "The TOC has already been updated but no new files have been appended to the archive." 2>&2
                ask "Are you sure you want to abort? Press Y to abort" && exit $?
            fi
        fi
        # Move tape to the end of the [first] tape file
        # $MT -f "$TAR_FILE" fsfm 0
        # /dev/nst0: Input/output error
        if [[ $IS_TAPE -eq 1 ]]; then
            rewind $TAPE_FILE_INDEX || exit $?
        fi
    fi

    # Add directory items (free arguments)
    cwd_now=$cwd
    for i in ${!ITEMS[@]}; do
        item="${ITEMS[i]}"
        cwd_now=$(cwd_at_item "$i" $cwd)
        # Add item (may be relative to a previously defined parent dir)
        if [[ -z "$cwd_now" ]]; then
            args+=("$item")
        else
            args+=("-C" "$cwd_now" "$item")
        fi
    done

    # Run tar to start the process
    # It'll interactively ask the user to switch tapes (insert next tape...)
    # when creating a multi-volume archive.
    tar "${args[@]}"
    if (( $? || ${PIPESTATUS[0]} )); then
        echo "ERROR - failed to write archive; possibly incomplete: $TAR_FILE" >&2
        exit 3
    fi
    #if [[ $cmd == "create" ]]; then
    #    if [[ $IS_TAPE -eq 1 ]]; then
    #        $MT -f "$TAR_FILE" eof || exit $?
    #    fi
    #fi

elif [[ $cmd == "toc" ]]; then
    # Extract and print TOC
    old_toc_file="$TMP_DIR/.TARTOC.OLD"
    echo "### READING OLD TOC <= ${TAR_NAME}..." >&2

    # Read TOC
    extract_toc_file "$old_toc_file" || exit $?
    #extract_toc_file # print directly to stdout (fixed bs only)

    # Truncate TOC
    sed -i 's/\x00\+$//' "$old_toc_file" || exit $?

    # Print TOC
    cat "$old_toc_file"

elif [[ $cmd == "detect" ]]; then
    # Detect TOCTAR tape archive by scanning TOC
    echo "### READING TOC / DETECTING TOCTAR ARCHIVE <= ${TAR_NAME}..." >&2
    tmp_toc_file=$(tmp_file)
    if [[ $IS_MULTI -eq 1 ]]; then
        ask "Please insert the [first] drive" || exit $?
    fi

    # Try to read TOC
    # If it fails (TOC area does not contain TOC), it's not a TOCTAR archive
    # Note that only the first tape contains the TOC
    if extract_toc_file "$tmp_toc_file"; then
        echo "### SUCCESS! TOC DETECTED! This looks like a TOCTAR archive." >&2
    else
        echo "### NO TOC DETECTED! This does not look like a TOCTAR archive." >&2
        exit 1
    fi

elif [[ $cmd == "bs" ]]; then
    # Detect block size
    echo "### READING FROM TAPE / ATTEMPTING TO DETECT BLOCK SIZE <= ${TAR_NAME}..." >&2

    bs=$(detect_block_size)
    rc=$?
    bs_k=
    [[ -n "$bs" ]] && bs_k=$((bs/1024))
    if [[ $rc -ne 0 ]]; then
        # Error detecting block size
        if [[ -n "$bs_k" ]]; then
            echo "### BLOCK SIZE APPEARS TO BE $bs_k KB ($bs)" >&2
        fi
        echo "### FAILED TO DETECT BLOCK SIZE ($rc)." >&2
        exit 1
    else
        echo "### BLOCK SIZE DETERMINED TO BE $bs_k KB ($bs)" >&2
    fi

elif [[ $cmd == "list" ]]; then
    # Load TOC and print file list

    tmp_toc_file=$(tmp_file)
    if [[ $? -ne 0 ]]; then
        echo "### FAILED TO CREATE TEMP FILE." >&2
        exit 1
    fi
    if ! extract_toc_file "$tmp_toc_file"; then
        echo "### FAILED TO READ TOC, CANNOT VERIFY." >&2
        exit 1
    fi
    toc_file_list "$tmp_toc_file"

elif [[ $cmd == "compare" ]]; then
    # Compare local files with their copies on tape
    # ...
    :

elif [[ $cmd == "verify" ]]; then
    # Verify files on tape by re-calculating their checksums
    ask "Please insert the [first] drive" || exit $?

    # Read TOC
    tmp_toc_file=$(tmp_file)
    if [[ $? -ne 0 ]]; then
        echo "### FAILED TO CREATE TEMP FILE." >&2
        exit 1
    fi
    if ! extract_toc_file "$tmp_toc_file"; then
        echo "### FAILED TO READ TOC, CANNOT VERIFY." >&2
        exit 1
    fi

    # Rewind tape (again)
    rewind $TAPE_FILE_INDEX || exit $?

    # Tar arguments
    args=()
    args+=("-b" "$TAR_FACTOR")
    args+=("-f" "$TAR_FILE")
    [[ $IS_MULTI -eq 1 ]] && args+=("--multi-volume")
    args+=("-x")
    args+=("--to-command=$script")

    # Run tar with custom verification script
    script=$(gen_script "$tmp_toc_file") || exit $?
    tar "${args[@]}"

elif [[ $cmd == "extract" ]]; then
    # Extract tape archive verifying each file in the process
    # ...
    :

fi



