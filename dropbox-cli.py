#!/usr/bin/env python

import os
import logging
import dropbox
import argparse


APP_NAME            = "dropbox-static-cli"
DEFAULT_KEY_PATH    = "{}/.dropbox-static-cli-key".format(os.environ["HOME"])

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
    parser_list.add_argument("-m", "--more", action="count", help="Display more pages (if available)")
    parser_list.set_defaults(func=exec_list)

    parser_get = subparsers.add_parser("get", help="Download items from Dropbox")
    parser_get.add_argument("-o", "--output", required=True, help="Save path for the downloaded file")
    parser_get.add_argument("DROPBOX_PATH", help="Path inside your Dropbox")
    parser_get.set_defaults(func=exec_get)

    parser_put = subparsers.add_parser("put", help="Upload items to Dropbox")
    parser_put.add_argument("-f", "--file", required=True, help="File to upload")
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
    print args

def exec_list(args, dbx):
    print "Executing LIST command"
    print args

def exec_get(args):
    print "Executing GET command"
    print args

def exec_put(args):
    print "Executing PUT command"
    print args

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


def main():
    try:
        parse_arguments()
    except dropbox.exceptions.AuthError as e:
        L.error("Authentication error")
    except dropbox.exceptions.BadInputError as e:
        L.error("Invalid input: {}".format(e.message))


if (__name__ == "__main__"):
    main()
