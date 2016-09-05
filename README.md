# dropbox-static-cli
A CLI interface for remotely interacting with Dropbox

## Synopsis
This CLI tool allows you to interface with your Dropbox storage without the need for local dropbox daemon or sync storage.
This is accomplished using the Dropbox HTTP API.

## Prerequisites
The only external requirement is the official Dropbox SDK.

Run `pip install dropbox` to install it

## Setup
You need to obtain a developer API key for your dropbox account.
Dropbox makes it more painful than it should be to accomplish, but it shouldn't take you more than a minute.

Start by navigating to your [App Console](https://www.dropbox.com/developers/apps).
Click the **Create App** button in the top right, choose **Dropbox API** (business is not supported),
select **Full Dropbox** and give your app a name.
This can be whatever, just make sure it doesn't contain **dropbox** because Dropbox is touchy about that.
Click **Create App** to save.
You should get redirected to the page of your new app. On this page, about halfway through, is a caption saying **Generated access token** - click the **Generate** button below it.
You will be presented with your new API key, make sure to save this or you'll have to make a new one if it gets lost.

Great, now you've got your API key! This key is used with virtually every call to this Dropbox CLI (either by directly passing it in with `--api-key` or by saving it into a file - refer to the `--help` option for more details!).
