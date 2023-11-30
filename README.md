# patchbot

A Python script that runs basic formatting checks on Nvidia pull requests.

## Usage

You will need a clone of mainline linux as well as the repo on which you are applying patches.

```
./patchbot.py [-h] -r PATCH_REPO -m MAINLINE_REPO -b BASE_REF -p PATCH_REF
```
