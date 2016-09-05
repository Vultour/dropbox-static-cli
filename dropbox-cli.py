#!/usr/bin/env python

import os
import sys
import time
import logging
import dropbox
import argparse
import datetime


APP_NAME            = "dropbox-static-cli"
DEFAULT_KEY_PATH    = "{}/.dropbox-static-cli-key".format(os.environ["HOME"])
UPLOAD_CHUNK_SIZE   = 1024 * 1024 * 100 # Upload in 100MB chunks (150MB limit on the API)

L = None


def parse_arguments():
    parser = argparse.ArgumentParser(
            prog="dropbox-static-cli",
            description="A command line tool for interfacing with Dropbox without the need for local sync storage",
            epilog="Note: Put your API key in {} to avoid having to pass in --api-key with every command!".format(DEFAULT_KEY_PATH)
    )

    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose output")
    parser.add_argument("-k", "--api-key", default=DEFAULT_KEY_PATH, help="Dropbox API key")
    parser.set_defaults(func=exec_default)

    subparsers = parser.add_subparsers(title="Available subcommands")

    parser_list = subparsers.add_parser("list", help="List items in Dropbox")
    parser_list.add_argument("DROPBOX_PATH")
    parser_list.add_argument("-m", "--more", action="count", help="Display more pages (if available), repeat for further pages")
    parser_list.add_argument("-r", "--recursive", action="store_true", help="Recursively list directories")
    parser_list.add_argument("-d", "--deleted", action="store_true", help="Show deleted items")
    parser_list.set_defaults(func=exec_list)

    parser_get = subparsers.add_parser("get", help="Download items from Dropbox")
    parser_get_opt = parser_get.add_mutually_exclusive_group(required=True)
    parser_get_opt.add_argument("-o", "--output", help="Location where to save the downloaded file")
    parser_get_opt.add_argument("-s", "--stdout", action="store_true", help="Output the file to stdout (useful for piping further)")
    parser_get.add_argument("DROPBOX_PATH", help="Path inside your Dropbox")
    parser_get.set_defaults(func=exec_get)

    parser_put = subparsers.add_parser("put", help="Upload items to Dropbox")
    parser_put_opt = parser_put.add_mutually_exclusive_group(required=True)
    parser_put_opt.add_argument("-a", "--add", action="store_true", help="Add the file using the autorename strategy if it already exists")
    parser_put_opt.add_argument("-o", "--overwrite", action="store_true", help="Overwrite the file if it already exists")
    parser_put.add_argument("-m", "--mute", action="store_true", help="Mute the file change notification synced clients receive from this action")
    parser_put.add_argument("-f", "--file", required=True, default=sys.stdin, type=argparse.FileType("rb"), help="File to upload ('-' for standard input)")
    parser_put.add_argument("DROPBOX_PATH", help="Path inside your Dropbox")
    parser_put.set_defaults(func=exec_put)

    parser_info = subparsers.add_parser("info", help="Dropbox account information")
    parser_info_sub = parser_info.add_subparsers(title="Available subcommands")

    parser_info_sub.add_parser("user", help="User information").set_defaults(func=exec_info_user)

    parser_info_sub.add_parser("quota", help="Quota information").set_defaults(func=exec_info_quota)

    args = parser.parse_args()
    return global_init(args)


def global_init(args):
    global L

    log_level = logging.WARNING
    if (args.verbose == 1): log_level = logging.INFO
    if (args.verbose > 1) : log_level = logging.DEBUG

    init_logger(log_level)
    dbx = init_dropbox(parse_key(args.api_key))

    return args.func(args, dbx)

def init_logger(log_level):
    global L
    L = logging.getLogger(APP_NAME)
    L.setLevel(log_level)
 
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-5s]: %(message)s"))

    L.addHandler(ch)

    L.debug("Logger initialized")


def parse_key(key):
    global L
    if (os.path.isfile(key)):
        L.info("Using supplied key as a file - '{}'".format(key))
        s = "";
        with open(key) as f:
            s = f.read().strip()
        return s

    L.info("Supplied key is not a valid file, using as a raw Dropbox API key - '{}'".format(key))
    return key

def init_dropbox(key):
    global L
    L.info("Initializing Dropbox instance with key '{}'".format(key))
    dbx = dropbox.Dropbox(key)
    return dbx


def exec_default(args):
    print "Executing no command"
    L.error("No command matched the arguments")

def exec_list(args, dbx):
    L.info("Executing LIST command")

    path = validate_dropbox_path(args.DROPBOX_PATH, is_file=False)
    more = args.more

    result = dbx.files_list_folder(path, recursive=args.recursive, include_deleted=args.deleted)
    print_entries(result.entries)

    if (result.has_more and (more < 1)):
        print "There are more entries, run with --more to continue retrieving"
    if ((not result.has_more) and (more > 0)):
        L.warn("File listing ended but there were unconsumed --more parameters")

    while ((result.has_more) and (more > 0)):
        more -= 1
        result = dbx.files_list_folder_continue(result.cursor)

        print_entries(result.entries)

        if (result.has_more and (more < 1)):
            print "There are more entries, run with additional --more parameters to continue retrieving"
        if ((not result.has_more) and (more > 0)):
            L.warn("File listing ended but there were unconsumed --more parameters")


def exec_get(args, dbx):
    L.info("Executing GET command")

    path = validate_dropbox_path(args.DROPBOX_PATH, is_file=True)

    if (args.stdout):
        if (sys.platform == "win32"):
            import msvcrt
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        response = dbx.files_download(path)
        L.info("Retrieved file '{}', last modified {}".format(response[0].name, response[0].client_modified.strftime("%Y/%m/%d %H:%M:%S")))
        sys.stdout.write(response[1].content)
    else:
        response = dbx.files_download_to_file(args.output, path)
        L.info("Retrieved file '{}', last modified {}".format(response.name, response.client_modified.strftime("%Y/%m/%d %H:%M:%S")))

def exec_put(args, dbx):
    L.info("Executing PUT command")

    path = validate_dropbox_path(args.DROPBOX_PATH)
    mode = None

    if   (args.add):        mode = dropbox.files.WriteMode.add
    elif (args.overwrite):  mode = dropbox.files.WriteMode.overwrite
    else:
        L.error("Couldn't determine file mode")
        sys.exit(1)

    if (args.mute): L.info("Client sync notification will be muted")

    session = None
    try:
        L.info("Starting file upload")

        total_uploaded = 0
        chunk = args.file.read(UPLOAD_CHUNK_SIZE)

        L.info("Uploading first chunk, {} bytes ({}MB)".format(len(chunk), len(chunk) / 1024.0 / 1024.0))
        session = dbx.files_upload_session_start(chunk)
        total_uploaded += len(chunk)

        while True:
            chunk = args.file.read(UPLOAD_CHUNK_SIZE)

            if (len(chunk) == 0): break

            L.info("Uploading another chunk, {} bytes ({:.2f}MB) uploaded, next chunk contains {} bytes ({:.2f}MB)".format(total_uploaded, total_uploaded / 1024.0 / 1024.0, len(chunk), len(chunk) / 1024.0 / 1024.0))
            dbx.files_upload_session_append_v2(
                chunk,
                dropbox.files.UploadSessionCursor(session_id=session.session_id, offset=total_uploaded)
            )
            total_uploaded += len(chunk)

        L.info("Finishing upload")
        new_file = dbx.files_upload_session_finish(
            None,
            dropbox.files.UploadSessionCursor(session_id=session.session_id, offset=total_uploaded),
            dropbox.files.CommitInfo(
                path=path,
                mode=mode,
                autorename=True,
                client_modified=datetime.datetime.now(),
                mute=args.mute
            )
        )

        L.info("Uploaded file '{}'".format(_s(new_file.path_display)))
    except KeyboardInterrupt:
        L.warning("Cancelling upload")
        dbx.files_upload_session_append_v2(
            None,
            dropbox.files.UploadSessionCursor(session_id=session.session_id, offset=total_uploaded),
            close=True
        )

def exec_info_user(args, dbx):
    global L
    L.info("Executing INFO-USER command")
    user = dbx.users_get_current_account()

    print """\
User ID      : {}
Account type : {}

Display Name : {}
Familiar Name: {}
First Name   : {}
Last Name    : {}

E-Mail       : {}

Verified     : {}
Disabled     : {}

Referral link: {}\
""".format(
        user.account_id,
        user.account_type._tag,
        user.name.display_name,
        user.name.familiar_name,
        user.name.given_name,
        user.name.surname,
        user.email,
        user.email_verified,
        user.disabled,
        user.referral_link
    )   

def exec_info_quota(args, dbx):
    L.info("Executing INFO-QUOTA command")
    usage = dbx.users_get_space_usage()

    if (usage.allocation.is_individual()):
        print "Allocated: {:.2f}MB".format(usage.allocation.get_individual().allocated / 1024.0 / 1024.0)
        print "Used     : {:.2f}MB".format(usage.used / 1024.0 / 1024.0)
    else:
        L.error("Team accounts are not supported")


def validate_dropbox_path(path, is_file=False):
    global L

    if (is_file and (path[-1] == "/")):
        L.error("Invalid path '{}' (files cannnot end with '/')".format(path))
        sys.exit(1)

    if (is_file and (len(path) < 2)):
        L.error("Invalid path '{}' (didn't you forget to start with '/'?)".format(path))
        sys.exit(1)

    if ((len(path) == 1) and (path != "/")):
        L.error("Invalid path '{}' (you probably meant '/')".format(path))
        sys.exit(1)

    if ((len(path) > 1) and (path[0] != "/")):
        L.error("Invalid path '{}' (needs to start with '/')".format(path))
        sys.exit(1)

    return ("" if (path == "/") else path)

def print_entries(entries):
    for entry in entries:
        if (type(entry) is dropbox.files.FolderMetadata):
            print "[d] - {}/".format(_s(entry.path_display))
        elif (type(entry) is dropbox.files.FileMetadata):
            print "[ ] - {}".format(_s(entry.path_display))
        else:
            print "[?] - {}".format(_s(entry.path_display))

def _s(s):
    if (type(s) is str):
        return unicode(s, "utf-8", errors="ignore")
    else:
        return s.encode("utf-8")


def main():
    try:
        parse_arguments()
    except dropbox.exceptions.AuthError as e:
        L.error("Authentication error")
    except dropbox.exceptions.BadInputError as e:
        L.error("Invalid input: {}".format(e.message))
    except dropbox.exceptions.ApiError as e:
        if ((type(e.error) is dropbox.files.ListFolderError) or (type(e.error) is dropbox.files.DownloadError)):
            if (e.error.is_path()):
                if (e.error.get_path().is_malformed_path()):
                    L.error("API Error: Malformed path - {}".format(e.error.get_path().get_malformed_path()))
                if (e.error.get_path().is_not_file()):
                    L.error("API Error: Not a file")
                if (e.error.get_path().is_not_folder()):
                    L.error("API Error: Not a folder")
                if (e.error.get_path().is_not_found()):
                    L.error("API Error: File not found")
                if (e.error.get_path().is_other()):
                    L.error("API Error: Other (?)")
                if (e.error.get_path().is_restricted_content()):
                    L.error("API Error: Restricted content")
                else:
                    L.error("API Error: Unknown path issue")
                    raise e
            else:
                L.error("API Error: Unknown path issue")
                raise e
        elif (type(e.error) is dropbox.files.UploadSessionLookupError):
            if (e.error.is_incorrect_offset()):
                L.error("API Error: Incorrect offset, correct was {} (if this appeared after cancelling an upload you can safely ignore it)".format(e.error.get_incorrect_offset().correct_offset))
            else:
                L.error("API Error: Unknown upload error")
                raise e
        else:
            L.error("API Error: Unknown")
            raise e


if (__name__ == "__main__"):
    main()
