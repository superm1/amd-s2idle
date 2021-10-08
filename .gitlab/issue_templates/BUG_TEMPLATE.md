### Before submitting your bug report:

< TODO: Drop this section >

- Check if your bug has already been reported [here](lspci -nn | grep VGA).
- For any logs, backtraces, etc - use [code blocks](https://docs.gitlab.com/ee/user/markdown.html#code-spans-and-blocks)
- As examples of good bug reports you may review one of these - #1698, #1536, #1734

Otherwise, fill the requested information below.
And please remove anything that doesn't apply to keep things readable :)

## Brief summary of the problem:
< TODO: Describe what you are doing, what you expect and what you're seeing
instead. How frequent is the issue? Is it a one time occurrence? Does it
appear multiple times but randomly? Can you easily reproduce it?

"It doesn't work" usually is not a helpful description of an issue.
The more detail about how things are going wrong, the better. >

## Hardware description:
 - CPU: < TODO >
 - GPU: < TODO: `lspci -nn | grep VGA` or `lshw -C display -numeric` >
 - System Memory: <TODO>
 - Display(s): <TODO>
 - Type of Display Connection: <TODO: DP, HDMI, DVI, etc>

## System information:
 - Distro name and Version: <TODO: e.g., Ubuntu 20.04.1 >
 - Kernel version: <TODO: `uname -a` >
 - Custom kernel: <TODO: e.g., N/A or Kernel from amd-staging-drm-next >
 - AMD official driver version: <TODO: e.g., N/A or released from AMD website version XYZ>

## How to reproduce the issue:

< TODO: Describe step-by-step how to reproduce the issue >
< NOTE: Add as much detail as possible >

## Attached files:

### Screenshots/video files

[ TODO: For rendering errors, attach screenshots of the problem and (if
possible) of how it should look. For freezes, it may be useful to provide a
screenshot of the affected game scene. Prefer screenshots over videos. ]

### Log files (for system lockups / game freezes / crashes)

 - Dmesg log (full log)
 - Xorg log
 - Any other log

/label ~bug
