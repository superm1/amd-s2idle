#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""S0i3/s2idle analysis script for AMD systems"""
import argparse
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import struct
from datetime import datetime, timedelta, date


class colors:
    DEBUG = "\033[90m"
    HEADER = "\033[95m"
    OK = "\033[94m"
    WARNING = "\033[32m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    UNDERLINE = "\033[4m"


class defaults:
    duration = 10
    wait = 4
    count = 1
    log_prefix = "s2idle_report"
    log_suffix = "txt"


class headers:
    Info = "Debugging script for s2idle on AMD systems"
    Prerequisites = "Checking prerequisites for s2idle"
    BrokenPrerequisites = "Your system does not meet s2idle prerequisites!"
    SuspendDuration = "Suspend timer programmed for"
    LastCycleResults = "Results from last s2idle cycle"
    CycleCount = "Suspend cycle"
    RootError = "Suspend must be initiated by root user"
    NvmeSimpleSuspend = "platform quirk: setting simple suspend"
    WokeFromIrq = "Woke up from IRQ"
    WakeTriggeredIrq = "Wakeup triggered from IRQ"
    MissingPyudev = "Udev access library `pyudev` is missing"
    MissingPackaging = "Python library `packaging` is missing"
    MissingIasl = "ACPI extraction tool `iasl` is missing"
    MissingJournald = "Python systemd/journald module is missing"
    MissingEthtool = "Ethtool is missing"
    Irq1Workaround = "Disabling IRQ1 wakeup source to avoid platform firmware bug"
    DurationDescription = "How long should suspend cycles last in seconds"
    WaitDescription = "How long to wait in between suspend cycles in seconds"
    CountDescription = "How many suspend cycles to run"
    LogDescription = "Location of log file"
    InstallAction = "Attempting to install"
    RerunAction = "Running this script as root will attempt to install it"
    ExplanationReport = "Explanations for your system"
    EcDebugging = "Turn on dynamic debug messages for EC during suspend"


def BIT(num):
    return 1 << num


def read_file(fn):
    with open(fn, "r") as r:
        return r.read().strip()


def capture_file_to_debug(fn):
    """Reads and captures all contents of fn"""
    try:
        contents = read_file(fn)
        for line in contents.split("\n"):
            logging.debug(line.rstrip())
        return contents
    except PermissionError:
        logging.debug(f"Unable to capture {fn}")


def get_property_pyudev(properties, key, fallback=""):
    """Get a property from a udev device"""
    try:
        return properties.get(key, fallback)
    except UnicodeDecodeError:
        return ""


def print_color(message, group):
    prefix = f"{group} "
    suffix = colors.ENDC
    if group == "🚦":
        color = colors.WARNING
    elif group == "🦟":
        color = colors.DEBUG
    elif any(mk in group for mk in ["❌", "👀", "🌡️"]):
        color = colors.FAIL
    elif any(mk in group for mk in ["✅", "🔋", "🐧", "💻", "○", "💤", "🥱"]):
        color = colors.OK
    else:
        color = group
        prefix = ""

    log_txt = f"{prefix}{message}".strip()
    if any(c in color for c in [colors.OK, colors.HEADER, colors.UNDERLINE]):
        logging.info(log_txt)
    elif color == colors.WARNING:
        logging.warning(log_txt)
    elif color == colors.FAIL:
        logging.error(log_txt)
    else:
        logging.debug(log_txt)

    if "TERM" in os.environ and os.environ["TERM"] == "dumb":
        suffix = ""
        color = ""
    print(f"{prefix}{color}{message}{suffix}")


def fatal_error(message):
    print_color(message, "👀")
    sys.exit(1)


def pm_debugging(func):
    def runner(*args, **kwargs):
        fn = os.path.join("/", "sys", "power", "pm_debug_messages")
        with open(fn, "w") as w:
            w.write("1")
        # getting the returned value
        ret = func(*args, **kwargs)
        with open(fn, "w") as w:
            w.write("0")
        return ret

    return runner


class S0i3Failure:
    def __init__(self):
        self.explanation = ""
        self.url = ""
        self.description = ""

    def get_failure(self):
        if self.description:
            print_color(self.description, "🚦")
        if self.explanation:
            print(self.explanation)
        if self.url:
            print(f"For more information on this failure see:\n\t{self.url}")


class RtcAlarmWrong(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "rtc_cmos is not configured to use ACPI alarm"
        self.explanation = (
            "\tSome problems can occur during wakeup cycles if the HPET RTC emulation is used to\n"
            "\twake systems. This can manifest in unexpected wakeups or high power consumption.\n"
        )
        self.url = "https://github.com/systemd/systemd/issues/24279"


class MissingAmdgpu(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "AMDGPU driver is missing"
        self.explanation = (
            "\tThe amdgpu driver is used for hardware acceleration as well\n"
            "\tas coordination of the power states for certain IP blocks on the SOC.\n"
            "\tBe sure that you have enabled CONFIG_AMDGPU in your kernel.\n"
        )


class MissingAmdgpuFirmware(S0i3Failure):
    def __init__(self, errors):
        super().__init__()
        self.description = "AMDGPU firmware is missing"
        self.explanation = (
            "\tThe amdgpu driver loads firmware from /lib/firmware/amdgpu\n"
            "\tIn some cases missing firmware will prevent a successful suspend cycle.\n"
            "\tUpgrade to a newer snapshot at https://gitlab.com/kernel-firmware/linux-firmware\n"
        )
        self.url = "https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1053856"
        for error in errors:
            self.explanation += f"\t{error}"


class AmdgpuPpFeatureMask(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "AMDGPU ppfeaturemask changed"
        self.explanation = (
            "\tThe ppfeaturemask for the amdgpu driver has been changed\n"
            "\tModifying this from the defaults may cause the system to not enter hardware sleep.\n"
        )
        self.url = "https://gitlab.freedesktop.org/drm/amd/-/issues/2808#note_2379968"


class MissingAmdPmc(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "AMD-PMC driver is missing"
        self.explanation = (
            "\tThe amd-pmc driver is required for the kernel to instruct the\n"
            "\tsoc to enter the hardware sleep state.\n"
            "\tBe sure that you have enabled CONFIG_AMD_PMC in your kernel.\n"
            "\n"
            "\tIf CONFIG_AMD_PMC is enabled but the amd-pmc driver isn't loading\n"
            "\tthen you may have found a bug and should report it."
        )


class MissingThunderbolt(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "thunderbolt driver is missing"
        self.explanation = (
            "\tThe thunderbolt driver is required for the USB4 routers included\n"
            "\twith the SOC to enter the proper power states.\n"
            "\tBe sure that you have enabled CONFIG_USB4 in your kernel.\n"
        )


class AcpiBiosError(S0i3Failure):
    def __init__(self, errors):
        super().__init__()
        self.description = "ACPI BIOS Errors detected"
        self.explanation = (
            "\tWhen running a firmware component utilized for s2idle\n"
            "\tthe ACPI interpreter in the Linux kernel encountered some\n"
            "\tproblems. This usually means it's a bug in the system BIOS\n"
            "\tthat should be fixed the system manufacturer.\n"
            "\n"
            "\tYou may have problems with certain devices after resume or high\n"
            "\tpower consumption when this error occurs.\n"
        )
        for error in errors:
            self.explanation += f"\t{error}"


class VendorWrong(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "Unsupported CPU vendor"
        self.explanation = (
            "\tThis tool specifically measures requirements utilized\n"
            "\tby AMD's S0i3 architecture.  Some of them may apply to other\n"
            "\tvendors, but definitely some are AMD specific."
        )


class UserNvmeConfiguration(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "NVME ACPI support is disabled"
        self.explanation = (
            "\tThe kernel command line has been configured to not support NVME ACPI support.\n"
            "\tThis is required for the NVME device to enter the proper power state.\n"
        )


class AcpiNvmeStorageD3Enable(S0i3Failure):
    def __init__(self, disk, num_ssds):
        super().__init__()
        self.description = f"{disk} missing ACPI attributes"
        self.explanation = (
            "\tAn NVME device was found, but it doesn't specify the StorageD3Enable\n"
            "\tattribute in the device specific data (_DSD).\n"
            "\tThis is a BIOS bug, but it may be possible to work around in the kernel.\n"
        )
        if num_ssds > 1:
            self.explanation += (
                "\n"
                "\tIf you added an aftermarket SSD to your system, the system vendor might not have added this\n"
                "\tproperty to the BIOS for the second port which could cause this behavior.\n"
                "\n"
                "\tPlease re-run this script with the --acpidump argument and file a bug to "
                "investigate.\n"
            )
        self.url = "https://bugzilla.kernel.org/show_bug.cgi?id=216440"


class DevSlpHostIssue(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "AHCI controller doesn't support DevSlp"
        self.explanation = (
            "\tThe AHCI controller is not configured to support DevSlp.\n"
            "\tThis must be enabled in BIOS for s2idle in Linux.\n"
        )


class DevSlpDiskIssue(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "SATA disk doesn't support DevSlp"
        self.explanation = (
            "\tThe SATA disk does not support DevSlp.\n"
            "\ts2idle in Linux requires SATA disks that support this feature.\n"
        )


class SleepModeWrong(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = (
            "The system hasn't been configured for Modern Standby in BIOS setup"
        )
        self.explanation = (
            "\tAMD systems must be configured for Modern Standby in BIOS setup\n"
            "\tfor s2idle to function properly in Linux.\n"
            "\tOn some OEM systems this is referred to as 'Windows' sleep mode.\n"
            "\tIf the BIOS is configured for S3 and you manually select s2idle\n"
            "\tin /sys/power/mem_sleep, the system will not enter the deepest hardware state."
        )


class DeepSleep(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = (
            "The kernel command line is asserting the system to use deep sleep"
        )
        self.explanation = (
            "\tAdding mem_sleep_default=deep doesn't work on AMD systems.\n"
            "\tPlease remove it from the kernel command line."
        )


class FadtWrong(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = (
            "The kernel didn't emit a message that low power idle was supported"
        )
        self.explanation = (
            "\tLow power idle is a bit documented in the FADT to indicate that\n"
            "\tlow power idle is supported.\n"
            "\tOnly newer kernels support emitting this message, so if you run on\n"
            "\tan older kernel you may get a false negative.\n"
            "\tWhen launched as root this script will try to directly introspect the\n"
            "\tACPI tables to confirm this."
        )


class Irq1Workaround(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "The wakeup showed an IRQ1 wakeup source, which might be a platform firmware bug"
        self.explanation = (
            "\tA number of Renoir, Lucienne, Cezanne, & Barcelo platforms have a platform firmware\n"
            "\tbug where IRQ1 is triggered during s0i3 resume.\n"
            "\tYou may have tripped up on this bug as IRQ1 was active during resume.\n"
            "\tIf you didn't press a keyboard key to wakeup the system then this can be\n"
            "\tthe cause of spurious wakeups.\n"
            "\n"
            "\tTo fix it, first try to upgrade to the latest firmware from your manufacturer.\n"
            "\tIf you're already upgraded to the latest firmware you can use one of two workarounds:\n"
            "\t 1. Manually disable wakeups from IRQ1 by running this command each boot:\n"
            "\t\t echo 'disabled' | sudo tee /sys/bus/serio/devices/serio0/power/wakeup \n"
            "\t 2. Use the below linked patch in your kernel."
        )
        self.url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/drivers/platform/x86/amd/pmc.c?id=8e60615e8932167057b363c11a7835da7f007106"


class KernelRingBufferWrapped(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "Kernel ringbuffer has wrapped"
        self.explanation = (
            "\tThis script relies upon analyzing the kernel log for markers.\n"
            "\tThe kernel's log provided by dmesg uses a ring buffer.\n"
            "\tWhen the ring buffer fills up it will wrap around and overwrite old messages.\n"
            "\n"
            "\tIn this case it's not possible to look for some of these markers\n"
            "\n"
            "\tPassing the pre-requisites check won't be possible without rebooting the machine.\n"
            "\tIf you are sure your system meets pre-requisites, you can re-run the script using.\n"
            "\tthe systemd logger or with --force.\n"
        )


class AmdHsmpBug(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "amd-hsmp built in to kernel"
        self.explanation = (
            "\tThe kernel has been compiled with CONFIG_AMD_HSMP=y.\n"
            "\tThis has been shown to cause suspend failures on some systems.\n"
            "\n"
            "\tEither recompile the kernel without CONFIG_AMD_HSMP,\n"
            "\tor use initcall_blacklist=hsmp_plt_init on your kernel command line to avoid triggering problems\n"
            "\n"
        )
        self.url = "https://gitlab.freedesktop.org/drm/amd/-/issues/2414"


class WCN6855Bug(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "The firmware loaded for the WCN6855 causes spurious wakeups"
        self.explanation = (
            "\tDuring s2idle on AMD systems PCIe devices are put into D3cold. During wakeup they're transitioned back\n"
            "\tinto the state they were before s2idle.  For many implementations this is D3hot.\n"
            "\tIf an ACPI event has been triggered by the EC, the hardware will resume from s2idle,\n"
            "\tbut the kernel should process the event and then put it back into s2idle.\n"
            "\n"
            "\tWhen this bug occurs, a GPIO connected to the WLAN card is active on the system making\n"
            "\the GPIO controller IRQ also active.  The kernel sees that the ACPI event IRQ and GPIO\n"
            "\tcontroller IRQ are both active and resumes the system.\n"
            "\n"
            "\tSome non-exhaustive events that will trigger this behavior:\n"
            "\t * Suspending the system and then closing the lid.\n"
            "\t * Suspending the system and then unplugging the AC adapter.\n"
            "\t * Suspending the system and the EC notifying the OS of a battery level change.\n"
            "\n"
            "\tThis issue is fixed by updated WCN6855 firmware which will avoid triggering the GPIO.\n"
            "\tThe version string containing the fix is 'WLAN.HSP.1.1-03125-QCAHSPSWPL_V1_V2_SILICONZ_LITE-3.6510.23'\n"
        )
        self.url = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/commit/?id=c7a57ef688f7d99d8338a5d8edddc8836ff0e6de"


class I2CHidBug(S0i3Failure):
    def __init__(self, name, remediation):
        super().__init__()
        self.description = f"The {name} device has been reported to cause high power consumption and spurious wakeups"
        self.explanation = (
            f"\tI2C devices work in an initiator/receiver relationship where the device is the receiver. In order for the receiver to indicate\n"
            "\tthe initiator needs to read data they will assert an attention GPIO pin.\n"
            "\tWhen a device misbehaves it may assert this pin spuriously which can cause the SoC to wakeup prematurely.\n"
            "\tThis typically manifests as high power consumption at runtime and spurious wakeups at suspend.\n"
            "\n"
            "\tThis issue can be worked around by unbinding the device from the kernel using this command:\n"
            "\n"
            "\t{remediation}\n"
            "\n"
            "\tTo fix this issue permanently the kernel will need to avoid binding to this device."
        )
        self.url = "https://gitlab.freedesktop.org/drm/amd/-/issues/2812"


class SpuriousWakeup(S0i3Failure):
    def __init__(self, duration):
        super().__init__()
        self.description = (
            f"Userspace wasn't asleep at least {timedelta(seconds=duration)}"
        )
        self.explanation = (
            f"\tThe system was programmed to sleep for {timedelta(seconds=duration)}, but woke up prematurely.\n"
            "\tThis typically happens when the system was woken up from a non-timer based source.\n"
            "\n"
            "\tIf you didn't intentionally wake it up, then there may be a kernel or firmware bug\n"
        )


class LowHardwareSleepResidency(S0i3Failure):
    def __init__(self, duration, percent):
        super().__init__()
        self.description = "System had low hardware sleep residency"
        self.explanation = (
            f"\tThe system was asleep for {timedelta(seconds=duration)}, but only spent {percent:.2%}\n"
            "\tof this time in a hardware sleep state.  In sleep cycles that are at least\n"
            "\t60 seconds long it's expected you spend above 90 percent of the cycle in"
            "\thardware sleep.\n"
        )


class MSRFailure(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "PC6 or CC6 state disabled"
        self.explanation = (
            "\tThe PC6 state of the package or the CC6 state of CPU cores was disabled.\n"
            "\tThis will prevent the system from getting to the deepest sleep state over suspend.\n"
        )


class TaintedKernel(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "Kernel is tainted"
        self.explanation = (
            "\tA tainted kernel may exhibit unpredictable bugs that are difficult for this script to characterize.\n"
            "\tIf this is intended behavior run the tool with --force.\n"
        )
        self.url = "https://gitlab.freedesktop.org/drm/amd/-/issues/3089"


class DMArNotEnabled(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "Pre-boot DMA protection disabled"
        self.explanation = (
            "\tPre-boot IOMMU DMA protection has been disabled.\n"
            "\tWhen the IOMMU is enabled this platform requires pre-boot DMA protection for suspend to work.\n"
        )


class MissingIommuACPI(S0i3Failure):
    def __init__(self, device):
        super().__init__()
        self.description = f"Device {device} missing from ACPI tables"
        self.explanation = (
            "\tThe ACPI device {device} is required for suspend to work when the IOMMU is enabled.\n"
            "\tPlease check your BIOS settings and if configured correctly, report a bug to your system vendor.\n"
        )
        self.url = "https://gitlab.freedesktop.org/drm/amd/-/issues/3738#note_2667140"


class SMTNotEnabled(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "SMT is not enabled"
        self.explanation = (
            "\tDisabling SMT prevents cores from going into the correct state.\n"
        )


class ASpmWrong(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "ASPM is overridden"
        self.explanation = (
            "\t Modifying ASPM may prevent PCIe devices from going into the\n"
            "\t correct state and lead to system stability issues.\n"
        )


class KernelLogger:
    def __init__(self):
        pass

    def seek(self):
        pass

    def process_callback(self, validator, callback):
        pass

    def match_line(self, matches):
        pass

    def match_pattern(self, pattern):
        pass

    def capture_full_dmesg(self, line):
        logging.debug(line)


class DmesgLogger(KernelLogger):
    def __init__(self):
        import subprocess

        self.since_support = False
        cmd = ["dmesg", "-h"]
        result = subprocess.run(cmd, check=True, capture_output=True)
        for line in result.stdout.decode("utf-8").split("\n"):
            if "--since" in line:
                self.since_support = True
        logging.debug("Since support: %d" % self.since_support)

        self.command = ["dmesg", "-t", "-k"]
        self._refresh_head()

    def _refresh_head(self):
        self.buffer = []
        self.seeked = False
        result = subprocess.run(self.command, check=True, capture_output=True)
        if result.returncode == 0:
            self.buffer = result.stdout.decode("utf-8")

    def seek(self, time=None):
        if time:
            if self.since_support:
                # look 10 seconds back because dmesg time isn't always accurate
                fuzz = time - timedelta(seconds=10)
                cmd = self.command + [
                    "--time-format=iso",
                    f"--since={fuzz.strftime('%Y-%m-%dT%H:%M:%S')}",
                ]
            else:
                cmd = self.command
            result = subprocess.run(cmd, check=True, capture_output=True)
            if result.returncode == 0:
                self.buffer = result.stdout.decode("utf-8")
                if self.since_support:
                    self.seeked = True
        elif self.seeked:
            self._refresh_head()

    def process_callback(self, callback):
        for entry in self.buffer.split("\n"):
            callback(entry)

    def match_line(self, matches):
        """Find lines that match all matches"""
        for entry in self.buffer.split("\n"):
            for match in matches:
                if match not in entry:
                    break
                return entry
        return None

    def match_pattern(self, pattern):
        for entry in self.buffer.split("\n"):
            if re.search(pattern, entry):
                return entry
        return None

    def capture_full_dmesg(self, line=None):
        self.seek()
        for entry in self.buffer.split("\n"):
            super().capture_full_dmesg(entry)

    def capture_header(self):
        return self.buffer.split("\n")[0]


class SystemdLogger(KernelLogger):
    def __init__(self):
        from systemd import journal

        self.journal = journal.Reader()
        self.journal.this_boot()
        self.journal.log_level(journal.LOG_INFO)
        self.journal.add_match(_TRANSPORT="kernel")
        self.journal.add_match(PRIORITY=journal.LOG_DEBUG)

    def seek(self, time=None):
        if time:
            self.journal.seek_realtime(time)
        else:
            self.journal.seek_head()

    def process_callback(self, callback):
        for entry in self.journal:
            callback(entry["MESSAGE"])

    def match_line(self, matches):
        """Find lines that match all matches"""
        for entry in self.journal:
            for match in matches:
                if match not in entry["MESSAGE"]:
                    break
                return entry["MESSAGE"]
        return None

    def match_pattern(self, pattern):
        for entry in self.journal:
            if re.search(pattern, entry["MESSAGE"]):
                return entry["MESSAGE"]
        return None

    def capture_full_dmesg(self, line=None):
        self.seek()
        for entry in self.journal:
            super().capture_full_dmesg(entry["MESSAGE"])


class DistroPackage:
    def __init__(self, deb, rpm, arch, pip, root):
        self.deb = deb
        self.rpm = rpm
        self.arch = arch
        self.pip = pip
        self.root = root

    def install(self, distro):
        if not self.root:
            sys.exit(1)
        if distro == "ubuntu" or distro == "debian":
            if not self.deb:
                return False
            installer = ["apt", "install", self.deb]
        elif distro == "fedora":
            if not self.rpm:
                return False
            release = read_file("/usr/lib/os-release")
            variant = None
            for line in release.split("\n"):
                if line.startswith("VARIANT_ID"):
                    variant = line.split("=")[-1]
            if variant != "workstation":
                return False
            installer = ["dnf", "install", "-y", self.rpm]
        elif distro == "cachyos" or distro == "arch":
            installer = ["pacman", "-Sy", self.arch]
        else:
            if not self.pip:
                return False
            installer = ["python3", "-m", "pip", "install", "--upgrade", self.pip]
        subprocess.check_call(installer)
        return True


class PyUdevPackage(DistroPackage):
    def __init__(self, root):
        super().__init__(
            deb="python3-pyudev",
            rpm="python3-pyudev",
            arch="python-pyudev",
            pip="pyudev",
            root=root,
        )


class IaslPackage(DistroPackage):
    def __init__(self, root):
        super().__init__(
            deb="acpica-tools", rpm="acpica-tools", arch="acpica", pip=None, root=root
        )


class PackagingPackage(DistroPackage):
    def __init__(self, root):
        super().__init__(
            deb="python3-packaging",
            rpm=None,
            arch="python-packaging",
            pip="python3-setuptools",
            root=root,
        )


class JournaldPackage(DistroPackage):
    def __init__(self, root):
        super().__init__(
            deb="python3-systemd",
            rpm="python3-pyudev",
            arch="python-systemd",
            pip=None,
            root=root,
        )


class EthtoolPackage(DistroPackage):
    def __init__(self, root):
        super().__init__(
            deb="ethtool",
            rpm="ethtool",
            arch="ethtool",
            pip=None,
            root=root,
        )


class WakeIRQ:
    def __init__(self, num, context):
        self.num = num
        p = os.path.join("/", "sys", "kernel", "irq", str(num))
        self.chip_name = read_file(os.path.join(p, "chip_name"))
        self.actions = read_file(os.path.join(p, "actions"))
        self.driver = ""
        self.name = ""
        wakeup = read_file(os.path.join(p, "wakeup"))

        # This is an IRQ tied to _AEI
        if self.chip_name == "amd_gpio":
            hw_gpio = read_file(os.path.join(p, "hwirq"))
            self.name = f"GPIO {hw_gpio}"
        # legacy IRQs
        elif "IR-IO-APIC" in self.chip_name:
            if self.actions == "acpi":
                self.name = "ACPI SCI"
            elif self.actions == "i8042":
                self.name = "PS/2 controller"
            elif self.actions == "pinctrl_amd":
                self.name = "GPIO Controller"
            elif self.actions == "rtc0":
                self.name = "RTC"
            elif self.actions == "timer":
                self.name = "Timer"
            self.actions = ""
        elif "PCI-MSI" in self.chip_name:
            bdf = self.chip_name.split("-")[-1]
            for dev in context.list_devices(subsystem="pci"):
                if dev.device_path.endswith(bdf):
                    vendor = dev.properties.get("ID_VENDOR_FROM_DATABASE")
                    desc = dev.properties.get("ID_PCI_CLASS_FROM_DATABASE")
                    if not desc:
                        desc = dev.properties.get("ID_PCI_INTERFACE_FROM_DATABASE")
                    name = dev.properties.get("PCI_SLOT_NAME")
                    self.driver = dev.properties.get("DRIVER")
                    self.name = f"{vendor} {desc} ({name})"
                    break

        # "might" look like an ACPI device, try to follow it
        if not self.name and self.actions:
            p = os.path.join("/", "sys", "bus", "acpi", "devices", self.actions)
            if os.path.exists(p):
                for d in os.listdir(p):
                    if "physical_node" not in d:
                        continue

                    for root, dirs, files in os.walk(
                        os.path.join(p, d), followlinks=True
                    ):
                        if "name" in files:
                            self.name = read_file(os.path.join(root, "name"))
                            t = os.path.join(root, "driver")
                            if os.path.exists(t):
                                self.driver = os.path.basename(os.readlink(t))
                            break
                    if self.name:
                        break

        # If the name isn't descriptive try to guess further
        if self.driver and self.actions == self.name:
            if self.driver == "i2c_hid_acpi":
                self.name = f"{self.name} I2C HID device"

        # check if it's disabled
        if not self.name and wakeup == "disabled":
            self.name = "Disabled interrupt"

    def __str__(self):
        actions = f" ({self.actions})" if self.actions else ""
        return f"{self.name}{actions}"


class S0i3Validator:
    def check_selinux(self):
        p = os.path.join("/", "sys", "fs", "selinux", "enforce")
        if os.path.exists(p):
            v = read_file(p)
            if v == "1" and not self.root_user:
                fatal_error("Unable to run with SELinux enabled without root")

    def show_install_message(self, message):
        action = headers.InstallAction if self.root_user else headers.RerunAction
        message = f"{message}. {action}."
        print_color(message, "👀")

    def __init__(self, log, acpidump, logind, debug_ec, kernel_log):
        # for saving a log file for analysis
        logging.basicConfig(
            format="%(asctime)s %(levelname)s:\t%(message)s",
            filename=log,
            filemode="w",
            level=logging.DEBUG,
        )

        # for installing and running suspend
        self.root_user = os.geteuid() == 0
        self.check_selinux()

        # capture all DSDT/SSDT or just one with _AEI
        self.acpidump = acpidump

        # initiate suspend cycles using logind
        self.logind = logind

        # turn on EC debug messages
        self.debug_ec = debug_ec

        # for matching against distro specific packages or bugs
        try:
            import distro

            self.distro = distro.id()
            self.pretty_distro = distro.distro.os_release_info()["pretty_name"]
        except ModuleNotFoundError:
            fatal_error("Missing python-distro package, unable to identify distro")
        # for analyzing devices
        try:
            from pyudev import Context

            self.pyudev = Context()
        except ModuleNotFoundError:
            self.pyudev = False

        if not self.pyudev:
            self.show_install_message(headers.MissingPyudev)
            package = PyUdevPackage(self.root_user)
            package.install(self.distro)
            try:
                from pyudev import Context
            except ModuleNotFoundError:
                fatal_error("Missing python-pyudev package, unable to identify devices")

            self.pyudev = Context()

        try:
            self.iasl = subprocess.call(["iasl", "-v"], stdout=subprocess.DEVNULL) == 0
        except:
            installer = False
            self.show_install_message(headers.MissingIasl)
            package = IaslPackage(self.root_user)
            self.iasl = package.install(self.distro)

        # for analyzing kernel logs
        if kernel_log == "auto":
            init_daemon = read_file("/proc/1/comm")
            if "systemd" in init_daemon:
                try:
                    self.kernel_log = SystemdLogger()
                except ImportError:
                    self.kernel_log = None
                if not self.kernel_log:
                    self.show_install_message(headers.MissingJournald)
                    package = JournaldPackage(self.root_user)
                    package.install(self.distro)
                    self.kernel_log = SystemdLogger()
            else:
                try:
                    self.kernel_log = DmesgLogger()
                except subprocess.CalledProcessError:
                    self.kernel_log = None
        elif kernel_log == "systemd":
            self.kernel_log = SystemdLogger()
        elif kernel_log == "dmesg":
            self.kernel_log = DmesgLogger()

        # for comparing SMU version
        try:
            from packaging import version
        except ImportError:
            self.show_install_message(headers.MissingPackaging)
            package = PackagingPackage(self.root_user)
            package.install(self.distro)
            from packaging import version

        self.cpu_family = ""
        self.cpu_model = ""
        self.cpu_model_string = ""
        self.smu_version = ""
        self.smu_program = ""

        # we only want kernel messages from our triggered suspend
        self.last_suspend = datetime.now()
        self.requested_duration = 0
        self.userspace_duration = 0
        self.kernel_duration = 0
        self.hw_sleep_duration = 0

        # failure reasons to display at the end
        self.failures = []

        # for comparing GPEs before/after sleep
        self.gpes = {}

        # for monitoring battery levels across suspend
        self.energy = {}
        self.charge = {}

        # for monitoring thermals across suspend
        self.thermal = {}

        # If we're locked down, a lot less errors make sense
        self.lockdown = False

    # See https://github.com/torvalds/linux/commit/ec6c0503190417abf8b8f8e3e955ae583a4e50d4
    def check_fadt(self):
        """Check the kernel emitted a message specific to 6.0 or later indicating FADT had a bit set."""
        found = False
        if not self.kernel_log:
            message = "Unable to test FADT from kernel log"
            print_color(message, "🚦")
        else:
            self.kernel_log.seek()
            matches = ["Low-power S0 idle used by default for system suspend"]
            found = self.kernel_log.match_line(matches)
        # try to look at FACP directly if not found (older kernel compat)
        if not found:
            if not self.root_user:
                logging.debug("Unable to capture ACPI tables without root")
                return True

            import struct

            logging.debug("Fetching low power idle bit directly from FADT")
            target = os.path.join("/", "sys", "firmware", "acpi", "tables", "FACP")
            try:
                with open(target, "rb") as r:
                    r.seek(0x70)
                    found = struct.unpack("<I", r.read(4))[0] & BIT(21)
            except PermissionError:
                print_color("FADT check unavailable", colors.WARNING)
                return True
        if found:
            message = "ACPI FADT supports Low-power S0 idle"
            print_color(message, "✅")
        else:
            message = "ACPI FADT doesn't support Low-power S0 idle"
            print_color(message, "❌")
            self.failures += [FadtWrong()]
        return found

    def check_msr(self):
        """Check if PC6 or CC6 has been disabled"""

        def read_msr(msr, cpu):
            p = "/dev/cpu/%d/msr" % cpu
            if not os.path.exists(p) and self.root_user:
                os.system("modprobe msr")
            f = os.open(p, os.O_RDONLY)
            os.lseek(f, msr, os.SEEK_SET)
            val = struct.unpack("Q", os.read(f, 8))[0]
            os.close(f)
            return val

        def check_bits(value, mask):
            return value & mask

        expect = {
            0xC0010292: BIT(32),  # PC6
            0xC0010296: (BIT(22) | BIT(14) | BIT(6)),  # CC6
        }
        try:
            for reg in expect:
                val = read_msr(reg, 0)
                if not check_bits(val, expect[reg]):
                    self.failures += [MSRFailure()]
                    return False
        except FileNotFoundError:
            print_color("Unabled to check MSRs: MSR kernel module not loaded", "❌")
            return False
        except PermissionError:
            print_color("MSR checks unavailable", "🚦")

        return True

    def capture_kernel_version(self):
        """Log the kernel version used"""
        kernel = platform.uname().release
        self.kernel_major = int(kernel.split(".")[0])
        self.kernel_minor = int(kernel.split(".")[1])
        if self.pretty_distro:
            print_color(f"{self.pretty_distro}", "🐧")
        print_color(f"Kernel {kernel}", "🐧")

    def check_thermal(self):
        devs = []
        for dev in self.pyudev.list_devices(subsystem="acpi", DRIVER="thermal"):
            devs.append(dev)

        logging.debug("Thermal zones")
        for dev in devs:
            prefix = "├─ " if dev != devs[-1] else "└─"
            detail_prefix = "│ \t" if dev != devs[-1] else "  \t"
            name = os.path.basename(dev.device_path)
            p = os.path.join(dev.sys_path, "thermal_zone")
            temp = int(read_file(os.path.join(p, "temp"))) / 1000

            logging.debug(f"{prefix} {name}")
            if name not in self.thermal:
                logging.debug(f"{detail_prefix} temp: {temp}°C")
            else:
                logging.debug(f"{detail_prefix} {self.thermal[name]}°C -> {temp}°C")

            # handle all trip points
            count = 0
            for f in os.listdir(p):
                if "trip_point" not in f:
                    continue
                if "temp" not in f:
                    continue
                count = count + 1

            for i in range(0, count):
                f = os.path.join(p, "trip_point_%d_type" % i)
                trip_type = read_file(f)
                f = os.path.join(p, "trip_point_%d_temp" % i)
                trip = int(read_file(f)) / 1000

                if name not in self.thermal:
                    logging.debug(f"{detail_prefix} {trip_type} trip: {trip}°C")

                if temp > trip:
                    print_color(
                        f"Thermal zone {name} past trip point {trip_type}: {trip}°C",
                        "🌡️",
                    )
                    return False
            self.thermal[name] = temp

        return True

    def check_battery(self):
        for dev in self.pyudev.list_devices(
            subsystem="power_supply", POWER_SUPPLY_TYPE="Battery"
        ):
            if not "PNP0C0A" in dev.device_path:
                continue

            energy_full_design = get_property_pyudev(
                dev.properties, "POWER_SUPPLY_ENERGY_FULL_DESIGN"
            )
            energy_full = get_property_pyudev(
                dev.properties, "POWER_SUPPLY_ENERGY_FULL"
            )
            energy = get_property_pyudev(dev.properties, "POWER_SUPPLY_ENERGY_NOW")
            charge_full_design = get_property_pyudev(
                dev.properties, "POWER_SUPPLY_CHARGE_FULL_DESIGN"
            )
            charge_full = get_property_pyudev(
                dev.properties, "POWER_SUPPLY_CHARGE_FULL"
            )
            charge = get_property_pyudev(dev.properties, "POWER_SUPPLY_CHARGE_NOW")
            man = get_property_pyudev(dev.properties, "POWER_SUPPLY_MANUFACTURER", "")
            model = get_property_pyudev(dev.properties, "POWER_SUPPLY_MODEL_NAME", "")
            name = get_property_pyudev(dev.properties, "POWER_SUPPLY_NAME", "Unknown")

            if energy_full_design:
                logging.debug(f"{name} energy level is {energy} µWh")
                if not name in self.energy:
                    print_color(
                        f"Battery {name} ({man} {model}) is operating at {float(energy_full) / int(energy_full_design):.2%} of design",
                        "🔋",
                    )
                else:
                    diff = abs(int(energy) - self.energy[name])
                    percent = float(diff) / int(energy_full)
                    if int(energy) > self.energy[name]:
                        action = "gained"
                    else:
                        action = "lost"
                    avg = round(
                        diff
                        / 1000000
                        / (self.userspace_duration.total_seconds() / 3600),
                        2,
                    )
                    print_color(
                        f"Battery {name} {action} {diff} µWh ({percent:.2%}) [Average rate {avg}W]",
                        "🔋",
                    )
                self.energy[name] = int(energy)

            if charge_full_design:
                logging.debug(f"{name} charge level is {charge} µAh")
                if not name in self.charge:
                    print_color(
                        f"Battery {name} ({man} {model}) is operating at {float(charge_full) / int(charge_full_design):.2%} of design",
                        "🔋",
                    )
                else:
                    diff = abs(int(charge) - self.charge[name])
                    percent = float(diff) / int(charge_full)
                    if int(charge) > self.charge[name]:
                        action = "gained"
                    else:
                        action = "lost"
                    avg = round(
                        diff
                        / 1000000
                        / (self.userspace_duration.total_seconds() / 3600),
                        2,
                    )
                    print_color(
                        f"Battery {name} {action} {diff} µAh ({percent:.2%}) [Average rate: {avg}A]",
                        "🔋",
                    )
                self.charge[name] = int(charge)

        return True

    def check_lps0(self):
        for m in ["acpi", "acpi_x86"]:
            p = os.path.join("/", "sys", "module", m, "parameters", "sleep_no_lps0")
            if not os.path.exists(p):
                continue
            fail = read_file(p) == "Y"
            if fail:
                print_color("LPS0 _DSM disabled", "❌")
            else:
                print_color("LPS0 _DSM enabled", "✅")
            return not fail
        print_color("LPS0 _DSM mpt found", "👀")
        return False

    def check_cpu_vendor(self):
        p = os.path.join("/", "proc", "cpuinfo")
        valid = False
        cpu = read_file(p)
        for line in cpu.split("\n"):
            if "AuthenticAMD" in line:
                valid = True
                continue
            elif "cpu family" in line:
                self.cpu_family = int(line.split()[-1])
                continue
            elif "model name" in line:
                self.cpu_model_string = line.split(":")[-1].strip()
                continue
            elif "model" in line:
                self.cpu_model = int(line.split()[-1])
                continue
            if self.cpu_family and self.cpu_model and self.cpu_model_string:
                print_color(
                    "%s (family %x model %x)"
                    % (self.cpu_model_string, self.cpu_family, self.cpu_model),
                    "✅",
                )
                break
        if not valid:
            self.failures += [VendorWrong()]
            print_color(
                "This tool is not designed for parts from this CPU vendor",
                "❌",
            )
        return valid

    def check_smt(self):
        p = os.path.join("/", "sys", "devices", "system", "cpu", "smt", "control")
        v = read_file(p)
        logging.debug(f"SMT control: {v}")
        if v == "notsupported":
            return True
        p = os.path.join("/", "sys", "devices", "system", "cpu", "smt", "active")
        v = read_file(p)
        if v == "0":
            self.failures += [SMTNotEnabled()]
            print_color("SMT is not enabled", "❌")
            return False
        print_color("SMT enabled", "✅")
        return True

    def capture_system_vendor(self):
        p = os.path.join("/", "sys", "class", "dmi", "id")
        try:
            ec = read_file(os.path.join(p, "ec_firmware_release"))
        except FileNotFoundError:
            ec = "unknown"
        try:
            vendor = read_file(os.path.join(p, "sys_vendor"))
            product = read_file(os.path.join(p, "product_name"))
            family = read_file(os.path.join(p, "product_family"))
            release = read_file(os.path.join(p, "bios_release"))
            version = read_file(os.path.join(p, "bios_version"))
            date = read_file(os.path.join(p, "bios_date"))
            print_color(
                f"{vendor} {product} ({family}) running BIOS {release} ({version}) released {date} and EC {ec}",
                "💻",
            )
        except FileNotFoundError:
            pass

    def check_sleep_mode(self):
        fn = os.path.join("/", "sys", "power", "mem_sleep")
        if not os.path.exists(fn):
            print_color("Kernel doesn't support sleep", "❌")
            return False

        cmdline = read_file(os.path.join("/proc", "cmdline"))
        if "mem_sleep_default=deep" in cmdline:
            print_color("Kernel command line is configured for 'deep' sleep", "❌")
            self.failures += [DeepSleep()]
            return False
        if "[s2idle]" not in read_file(fn):
            self.failures += [SleepModeWrong()]
            print_color("System isn't configured for s2idle in firmware setup", "❌")
            return False
        print_color("System is configured for s2idle", "✅")
        return True

    def check_storage(self):
        has_sata = False
        valid_nvme = {}
        invalid_nvme = {}
        valid_sata = False
        valid_ahci = False
        cmdline = read_file(os.path.join("/proc", "cmdline"))
        p = os.path.join("/", "sys", "module", "nvme", "parameters", "noacpi")
        c = os.path.exists(p) and read_file(p) == "Y"
        if ("nvme.noacpi" in cmdline) and c:
            print_color("NVME ACPI support is blocked by kernel command line", "❌")
            self.failures += [UserNvmeConfiguration()]
            return False

        if not self.kernel_log:
            message = "Unable to test storage from kernel log"
            print_color(message, "🚦")
            return True

        for dev in self.pyudev.list_devices(subsystem="pci", DRIVER="nvme"):
            pci_slot_name = dev.properties["PCI_SLOT_NAME"]
            vendor = get_property_pyudev(dev.properties, "ID_VENDOR_FROM_DATABASE", "")
            model = get_property_pyudev(dev.properties, "ID_MODEL_FROM_DATABASE", "")
            message = f"{vendor} {model}"
            self.kernel_log.seek()
            pattern = f"{pci_slot_name}.*{headers.NvmeSimpleSuspend}"
            if self.kernel_log.match_pattern(pattern):
                valid_nvme[pci_slot_name] = message
            if pci_slot_name not in valid_nvme:
                invalid_nvme[pci_slot_name] = message

            for dev in self.pyudev.list_devices(subsystem="ata", DRIVER="ahci"):
                has_sata = True
                break

            if has_sata:
                # Test AHCI
                self.kernel_log.seek()
                matches = ["ahci", "flags", "sds", "sadm"]
                if self.kernel_log.match_line(matches):
                    valid_ahci = True
                # Test SATA
                self.kernel_log.seek()
                matches = ["ata", "Features", "Dev-Sleep"]
                if self.kernel_log.match_line(matches):
                    valid_sata = True
        if invalid_nvme:
            for disk in invalid_nvme:
                print_color(
                    f"NVME {invalid_nvme[disk].strip()} is not configured for s2idle in BIOS",
                    "❌",
                )
                num = len(invalid_nvme) + len(valid_nvme)
                self.failures += [AcpiNvmeStorageD3Enable(invalid_nvme[disk], num)]
        if valid_nvme:
            for disk in valid_nvme:
                print_color(
                    f"NVME {valid_nvme[disk].strip()} is configured for s2idle in BIOS",
                    "✅",
                )
        if has_sata:
            if valid_sata:
                print_color("SATA supports DevSlp feature", "✅")
            else:
                invalid_nvme = True
                print_color("SATA does not support DevSlp feature", "❌")
                self.failures += [DevSlpDiskIssue()]

            if valid_ahci:
                print_color("AHCI is configured for DevSlp in BIOS", "✅")
            else:
                print_color("AHCI is not configured for DevSlp in BIOS", "❌")
                self.failures += [DevSlpHostIssue()]

        return (
            (len(invalid_nvme) == 0)
            and (valid_sata or not has_sata)
            and (valid_ahci or not has_sata)
        )

    def install_ethtool(self):
        try:
            subprocess.call(["ethtool", "-h"], stdout=subprocess.DEVNULL) == 0
            return True
        except FileNotFoundError:
            self.show_install_message(headers.MissingEthtool)
            package = EthtoolPackage(self.root_user)
            return package.install(self.distro)

    def check_network(self):
        ethtool = False
        for device in self.pyudev.list_devices(subsystem="net", ID_NET_DRIVER="r8169"):
            if not ethtool:
                ethtool = self.install_ethtool()
            if not ethtool:
                print_color("Ethernet checks unavailable without `ethtool`", "🚦")
                return True
            interface = device.properties.get("INTERFACE")
            cmd = ["ethtool", interface]
            wol_supported = False
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(
                "utf-8"
            )
            for line in output.split("\n"):
                if "Supports Wake-on" in line:
                    val = line.split(":")[1].strip()
                    if "g" in val:
                        logging.debug(f"{interface} supports WoL")
                        wol_supported = True
                    else:
                        logging.debug(f"{interface} doesn't support WoL ({val})")
                elif "Wake-on" in line and wol_supported:
                    val = line.split(":")[1].strip()
                    if "g" in val:
                        print_color(f"{interface} has WoL enabled", "✅")
                    else:
                        print_color(
                            f"Platform may have low hardware sleep residency with Wake-on-lan disabled. Run `ethtool -s {interface} wol g` to enable it if necessary.",
                            colors.WARNING,
                        )
        return True

    def check_device_firmware(self):
        try:
            import gi
            from gi.repository import GLib

            gi.require_version("Fwupd", "2.0")
            from gi.repository import Fwupd  # pylint: disable=wrong-import-position

        except ImportError:
            print_color(
                "Device firmware checks unavailable without gobject introspection",
                "🚦",
            )
            return True
        except ValueError:
            print_color(
                "Device firmware checks unavailable without fwupd gobject introspection",
                "🚦",
            )
            return True

        client = Fwupd.Client()
        devices = client.get_devices()
        for device in devices:
            # Dictionary of instance id to firmware version mappings that
            # have been "reported" to be problematic
            map = {
                "8c36f7ee-cc11-4a36-b090-6363f54ecac2": "0.1.26",  # https://gitlab.freedesktop.org/drm/amd/-/issues/3443
            }
            interesting_plugins = ["nvme", "tpm", "uefi_capsule"]
            if device.get_plugin() in interesting_plugins:
                logging.debug(
                    f"{device.get_vendor()} {device.get_name()} firmware version: '{device.get_version()}'"
                )
                logging.debug(f"| {device.get_guids()}")
                logging.debug(f"└─{device.get_instance_ids()}")
            for item in map:
                if (
                    item in device.get_guids() or item in device.get_instance_ids()
                ) and map[item] in device.get_version():
                    print_color(
                        f"Platform may have problems resuming.  Upgrade the firmware for '{device.get_name()}' if you have problems.",
                        colors.WARNING,
                    )
        return True

    def check_amd_hsmp(self):
        f = os.path.join("/", "boot", f"config-{platform.uname().release}")
        if os.path.exists(f):
            kconfig = read_file(f)
            if "CONFIG_AMD_HSMP=y" in kconfig:
                print_color(
                    "HSMP driver `amd_hsmp` driver may conflict with amd_pmc",
                    "❌",
                )
                self.failures += [AmdHsmpBug()]
                return False

        cmdline = read_file(os.path.join("/proc", "cmdline"))
        blocked = "initcall_blacklist=hsmp_plt_init" in cmdline

        p = os.path.join("/", "sys", "module", "amd_hsmp")
        if os.path.exists(p) and not blocked:
            print_color("`amd_hsmp` driver may conflict with amd_pmc", "❌")
            self.failures += [AmdHsmpBug()]
            return False

        print_color(
            f"HSMP driver `amd_hsmp` not detected (blocked: {blocked})",
            "✅",
        )
        return True

    def check_iommu(self):
        affected_1a = (
            list(range(0x20, 0x2F)) + list(range(0x60, 0x6F)) + list(range(0x70, 0x7F))
        )
        if self.cpu_family == 0x1A and self.cpu_model in affected_1a:
            found_iommu = False
            found_acpi = False
            found_dmar = False
            for dev in self.pyudev.list_devices(subsystem="iommu"):
                found_iommu = True
                logging.debug(f"Found IOMMU {dev.sys_path}")
                break
            if not found_iommu:
                print_color("IOMMU disabled", "✅")
                return True
            for dev in self.pyudev.list_devices(
                subsystem="thunderbolt", DEVTYPE="thunderbolt_domain"
            ):
                p = os.path.join(dev.sys_path, "iommu_dma_protection")
                v = int(read_file(p))
                logging.debug(f"{p}:{v}")
                found_dmar = v == 1
            if not found_dmar:
                print_color(
                    "IOMMU is misconfigured: Pre-boot DMA protection not enabled", "❌"
                )
                self.failures += [DMArNotEnabled()]
                return False
            for dev in self.pyudev.list_devices(subsystem="acpi"):
                if "MSFT0201" in dev.sys_path:
                    found_acpi = True
            if not found_acpi:
                print_color("IOMMU is misconfigured: missing MSFT0201 ACPI device", "❌")
                self.failures += [MissingIommuACPI("MSFT0201")]
                return False
            print_color("IOMMU properly configured", "✅")
        return True

    def check_port_pm_override(self):
        from packaging import version

        if self.cpu_family != 0x19:
            return
        if self.cpu_model not in [0x74, 0x78]:
            return
        if version.parse(self.smu_version) > version.parse("76.60.0"):
            return
        if version.parse(self.smu_version) < version.parse("76.18.0"):
            return
        cmdline = read_file(os.path.join("/proc", "cmdline"))
        if "pcie_port_pm=off" in cmdline:
            return
        print_color(
            "Platform may hang resuming.  Upgrade your firmware or add pcie_port_pm=off to kernel command line if you have problems.",
            colors.WARNING,
        )

    def check_wake_sources(self):
        def get_input_sibling_name(pyudev, parent):
            # input is a sibling not a parent to the wakeup
            for input in pyudev.list_devices(subsystem="input", parent=parent):
                if not "NAME" in input.properties:
                    continue
                return input.properties["NAME"]
            return ""

        devices = []
        for wake_dev in self.pyudev.list_devices(subsystem="wakeup"):
            p = os.path.join(wake_dev.sys_path, "device", "power", "wakeup")
            if not os.path.exists(p):
                continue
            wake_en = read_file(p)
            name = ""
            sys_name = wake_dev.sys_path
            # determine the type of device it hangs off of
            acpi = wake_dev.find_parent(subsystem="acpi")
            serio = wake_dev.find_parent(subsystem="serio")
            rtc = wake_dev.find_parent(subsystem="rtc")
            pci = wake_dev.find_parent(subsystem="pci")
            mhi = wake_dev.find_parent(subsystem="mhi")
            pnp = wake_dev.find_parent(subsystem="pnp")
            hid = wake_dev.find_parent(subsystem="hid")
            thunderbolt_device = wake_dev.find_parent(
                subsystem="thunderbolt", device_type="thunderbolt_device"
            )
            thunderbolt_domain = wake_dev.find_parent(
                subsystem="thunderbolt", device_type="thunderbolt_domain"
            )
            i2c = wake_dev.find_parent(subsystem="i2c")
            if i2c is not None:
                sys_name = i2c.sys_name
                name = get_input_sibling_name(self.pyudev, i2c)
            elif thunderbolt_device is not None:
                if "USB4_TYPE" in thunderbolt_device.properties:
                    name = "USB4 {type} controller".format(
                        type=thunderbolt_device.properties["USB4_TYPE"]
                    )
                sys_name = thunderbolt_device.sys_name
            elif thunderbolt_domain is not None:
                name = "Thunderbolt domain"
                sys_name = thunderbolt_domain.sys_name
            elif serio is not None:
                sys_name = serio.sys_name
                name = get_input_sibling_name(self.pyudev, serio)
            elif rtc is not None:
                sys_name = rtc.sys_name
                for parent in self.pyudev.list_devices(
                    subsystem="platform", parent=rtc, DRIVER="alarmtimer"
                ):
                    name = "Real Time Clock alarm timer"
            elif mhi is not None:
                sys_name = mhi.sys_name
                name = "Mobile Broadband host interface"
            elif hid is not None:
                name = hid.properties["HID_NAME"]
                sys_name = hid.sys_name
            elif pci is not None:
                sys_name = pci.sys_name
                if (
                    "ID_PCI_SUBCLASS_FROM_DATABASE" in pci.properties
                    and "ID_VENDOR_FROM_DATABASE" in pci.properties
                ):
                    name = "{vendor} {cls}".format(
                        vendor=pci.properties["ID_VENDOR_FROM_DATABASE"],
                        cls=pci.properties["ID_PCI_SUBCLASS_FROM_DATABASE"],
                    )
                else:
                    name = f"PCI {pci.properties['PCI_CLASS']}"
            elif acpi is not None:
                sys_name = acpi.sys_name
                if acpi.driver == "button":
                    for input in self.pyudev.list_devices(
                        subsystem="input", parent=acpi
                    ):
                        if not "NAME" in input.properties:
                            continue
                        name = f"ACPI {input.properties['NAME']}"
                elif acpi.driver == "battery" or acpi.driver == "ac":
                    for ps in self.pyudev.list_devices(
                        subsystem="power_supply", parent=acpi
                    ):
                        if not "POWER_SUPPLY_NAME" in ps.properties:
                            continue
                        name = f"ACPI {ps.properties['POWER_SUPPLY_TYPE']}"
            elif pnp is not None:
                name = "Plug-n-play"
                if pnp.driver == "rtc_cmos":
                    name = f"{name} Real Time Clock"
                sys_name = pnp.sys_name

            devices.append(f"{name.replace('\"', '')} [{sys_name}]: {wake_en}")
        devices.sort()
        logging.debug("Wakeup sources:")
        for dev in devices:
            # set prefix if last device
            prefix = "│ " if dev != devices[-1] else "└─"
            logging.debug(f"{prefix}{dev}")
        return True

    def check_amd_pmc(self):
        for device in self.pyudev.list_devices(subsystem="platform", DRIVER="amd_pmc"):
            message = "PMC driver `amd_pmc` loaded"
            p = os.path.join(device.sys_path, "smu_program")
            v = os.path.join(device.sys_path, "smu_fw_version")
            if os.path.exists(v):
                try:
                    self.smu_version = read_file(v)
                    self.smu_program = read_file(p)
                except TimeoutError:
                    print_color("failed to communicate using `amd_pmc` driver", "❌")
                    return False
                message += f" (Program {self.smu_program} Firmware {self.smu_version})"
            self.check_port_pm_override()
            print_color(message, "✅")
            return True
        self.failures += [MissingAmdPmc()]
        print_color("PMC driver `amd_pmc` did not bind to any ACPI device", "❌")
        return False

    def check_aspm(self):
        p = os.path.join("/", "sys", "module", "pcie_aspm", "parameters", "policy")
        contents = read_file(p)
        policy = ""
        for word in contents.split(" "):
            if word.startswith("["):
                policy = word
                break
        if policy != "[default]":
            print_color(f"ASPM policy set to {policy}", "❌")
            self.failures += [ASpmWrong()]
            return False
        print_color("ASPM policy set to 'default'", "✅")
        return True

    def check_usb4(self):
        for device in self.pyudev.list_devices(subsystem="pci", PCI_CLASS="C0340"):
            slot = device.properties["PCI_SLOT_NAME"]
            if device.properties.get("DRIVER") != "thunderbolt":
                print_color(
                    f"USB4 controller for {slot} not using `thunderbolt` driver", "❌"
                )
                self.failures += [MissingThunderbolt()]
                return False
            print_color(f"USB4 driver `thunderbolt` bound to {slot}", "✅")
        return True

    def check_pinctrl_amd(self):
        for device in self.pyudev.list_devices(subsystem="platform", DRIVER="amd_gpio"):
            print_color("GPIO driver `pinctrl_amd` available", "✅")
            p = os.path.join("/", "sys", "kernel", "debug", "gpio")
            try:
                contents = read_file(p)
            except PermissionError:
                logging.debug(f"Unable to capture {p}")
                contents = None
            header = False
            if contents:
                for line in contents.split("\n"):
                    if "WAKE_INT_MASTER_REG:" in line:
                        val = "en" if int(line.split()[1], 16) & BIT(15) else "dis"
                        logging.debug("Winblue GPIO 0 debounce: %sabled", val)
                        continue
                    if not header and re.search("trigger", line):
                        logging.debug(line)
                        header = True
                    if re.search("edge", line) or re.search("level", line):
                        logging.debug(line)
            return True
        print_color("GPIO driver `pinctrl_amd` not loaded", "❌")
        return False

    def check_rtc_cmos(self):
        # check /sys/module/rtc_cmos/parameters/use_acpi_alarm
        p = os.path.join(
            "/", "sys", "module", "rtc_cmos", "parameters", "use_acpi_alarm"
        )
        val = read_file(p)
        if val == "N":
            print_color("RTC driver `rtc_cmos` configured to use ACPI alarm", "🚦")
            self.failures += [RtcAlarmWrong()]

    def check_amdgpu(self):
        for device in self.pyudev.list_devices(subsystem="pci"):
            klass = device.properties.get("PCI_CLASS")
            if klass != "38000" and klass != "30000":
                continue
            pci_id = device.properties.get("PCI_ID")
            if not pci_id.startswith("1002"):
                continue
            if device.properties.get("DRIVER") != "amdgpu":
                print_color("GPU driver `amdgpu` not loaded", "❌")
                self.failures += [MissingAmdgpu()]
                return False
            slot = device.properties.get("PCI_SLOT_NAME")
            print_color(f"GPU driver `amdgpu` bound to {slot}", "✅")
        p = os.path.join("/", "sys", "module", "amdgpu", "parameters", "ppfeaturemask")
        if os.path.exists(p):
            v = read_file(p)
            if v != "0xfff7bfff":
                print_color(f"AMDGPU ppfeaturemask overridden to {v}", "❌")
                self.failures += [AmdgpuPpFeatureMask()]
                return False
        if not self.kernel_log:
            message = "Unable to test for amdgpu from kernel log"
            print_color(message, "🚦")
            return True
        self.kernel_log.seek()
        match = self.kernel_log.match_pattern("Direct firmware load for amdgpu.*failed")
        if match and not "amdgpu/isp" in match:
            print_color("GPU firmware missing", "❌")
            self.failures += [MissingAmdgpuFirmware([match])]
            return False
        return True

    def check_wcn6855_bug(self):
        if not self.kernel_log:
            message = "Unable to test for wcn6855 bug from kernel log"
            print_color(message, "🚦")
            return True
        wcn6855 = False
        self.kernel_log.seek()
        if self.kernel_log.match_pattern("ath11k_pci.*wcn6855"):
            match = self.kernel_log.match_pattern("ath11k_pci.*fw_version")
            if match:
                logging.debug("WCN6855 version string: %s", match)
                objects = match.split()
                for i in range(0, len(objects)):
                    if objects[i] == "fw_build_id":
                        wcn6855 = objects[i + 1]

        if wcn6855:
            components = wcn6855.split(".")
            if int(components[-1]) >= 37 or int(components[-1]) == 23:
                print_color(
                    f"WCN6855 WLAN (fw build id {wcn6855})",
                    "✅",
                )
            else:
                print_color(
                    f"WCN6855 WLAN may cause spurious wakeups (fw build id {wcn6855})",
                    "❌",
                )
                self.failures += [WCN6855Bug()]

        return True

    def capture_amdgpu_ips_status(self):
        for device in self.pyudev.list_devices(subsystem="pci", PCI_CLASS="38000"):
            pci_id = device.properties.get("PCI_ID")
            if not pci_id.startswith("1002"):
                continue
            slot = device.properties.get("PCI_SLOT_NAME")
            p = os.path.join(
                "/", "sys", "kernel", "debug", "dri", slot, "amdgpu_dm_ips_status"
            )
            if not os.path.exists(p):
                continue
            logging.debug("IPS status")
            lines = read_file(p).split("\n")
            for line in lines:
                prefix = "│ " if line != lines[-1] else "└─"
                logging.debug(f"{prefix} {line}")

    def capture_lid(self):
        p = os.path.join("/", "proc", "acpi", "button", "lid")
        for root, dirs, files in os.walk(p):
            for fname in files:
                p = os.path.join(root, fname)
                state = read_file(p).split(":")[1].strip()
                logging.debug(f"ACPI Lid ({p}): {state}")

    def capture_gpes(self):
        base = os.path.join("/", "sys", "firmware", "acpi", "interrupts")
        for root, dirs, files in os.walk(base, topdown=False):
            for fname in files:
                if not fname.startswith("gpe") or fname == "gpe_all":
                    continue
                target = os.path.join(root, fname)
                val = 0
                with open(target, "r") as r:
                    val = int(r.read().split()[0])
                if fname in self.gpes and self.gpes[fname] != val:
                    logging.debug(
                        "%s increased from %d to %d" % (fname, self.gpes[fname], val)
                    )
                self.gpes[fname] = val

    def check_wakeup_irq(self):
        p = os.path.join("/", "sys", "power", "pm_wakeup_irq")
        try:
            n = int(read_file(p))
            for irq in self.irqs:
                if irq[0] == n:
                    message = f"{headers.WokeFromIrq} {irq[0]}: {irq[1]}"
                    print_color(message, "🥱")
                    break
        except OSError:
            pass
        return True

    def check_hw_sleep(self):
        result = False
        if self.hw_sleep_duration:
            result = True
        if not self.hw_sleep_duration:
            p = os.path.join("/", "sys", "power", "suspend_stats", "last_hw_sleep")
            if os.path.exists(p):
                try:
                    self.hw_sleep_duration = int(read_file(p)) / 10**6
                    if self.hw_sleep_duration > 0:
                        result = True
                except FileNotFoundError as e:
                    logging.debug(f"Failed to read hardware sleep data from {p}: {e}")
        if not self.hw_sleep_duration:
            p = os.path.join("/", "sys", "kernel", "debug", "amd_pmc", "smu_fw_info")
            try:
                val = read_file(p)
                for line in val.split("\n"):
                    if "Last S0i3 Status" in line:
                        if "Success" in line:
                            result = True
                        continue
                    if "Time (in us) in S0i3" in line:
                        self.hw_sleep_duration = int(line.split(":")[1]) / 10**6
            except PermissionError:
                if self.lockdown:
                    print_color(
                        "Unable to gather hardware sleep data.",
                        colors.WARNING,
                    )
                else:
                    print_color("Failed to read hardware sleep data", colors.WARNING)
                return False
            except FileNotFoundError:
                print_color("HW sleep statistics file missing", "❌")
                return False
        if result:
            if self.userspace_duration:
                percent = float(
                    self.hw_sleep_duration / self.userspace_duration.total_seconds()
                )
            else:
                percent = 0
            if percent and self.userspace_duration.total_seconds() >= 60:
                if percent > 0.9:
                    symbol = "✅"
                else:
                    symbol = "❌"
                    self.failures += [
                        LowHardwareSleepResidency(
                            self.userspace_duration.total_seconds(), percent
                        )
                    ]
            else:
                symbol = "💤"
            percent_msg = "" if not percent else f"({percent:.2%})"
            print_color(
                f"In a hardware sleep state for {timedelta(seconds=self.hw_sleep_duration)} {percent_msg}",
                symbol,
            )
        else:
            print_color("Did not reach hardware sleep state", "❌")
        return result

    def check_permissions(self):
        p = os.path.join("/", "sys", "power", "state")
        try:
            with open(p, "w") as w:
                pass
        except PermissionError:
            print_color(f"{headers.RootError}", "👀")
            return False
        return True

    def check_i2c_hid(self):
        devices = []
        for dev in self.pyudev.list_devices(subsystem="input"):
            if "NAME" not in dev.properties:
                continue
            parent = dev.find_parent(subsystem="i2c")
            if parent is None:
                continue
            devices.append(dev)
        if not devices:
            return True
        logging.debug("I2C HID devices")
        for dev in devices:
            name = dev.properties["NAME"]
            parent = dev.find_parent(subsystem="i2c")
            p = os.path.join(parent.sys_path, "firmware_node", "path")
            if os.path.exists(p):
                acpi_path = read_file(p)
            else:
                acpi_path = ""
            p = os.path.join(parent.sys_path, "firmware_node", "hid")
            if os.path.exists(p):
                acpi_hid = read_file(p)
            else:
                acpi_hid = ""
            # set prefix if last device
            prefix = "│ " if dev != devices[-1] else "└─"
            logging.debug(f"{prefix}{name} [{acpi_hid}] : {acpi_path}")
            if "IDEA5002" in name:
                remediation = (
                    "echo {} | sudo tee /sys/bus/i2c/drivers/{}/unbind".format(
                        parent.sys_path.split("/")[-1], parent.driver
                    )
                )

                print_color(
                    f"{name} may cause spurious wakeups",
                    "❌",
                )
                self.failures += [I2CHidBug(name, remediation)]
                return False
        return True

    def map_acpi_pci(self):
        devices = []
        for dev in self.pyudev.list_devices(subsystem="pci"):
            devices.append(dev)
        logging.debug("PCI devices")
        for dev in devices:
            pci_id = dev.properties["PCI_ID"].lower()
            pci_slot_name = dev.properties["PCI_SLOT_NAME"]
            database_class = get_property_pyudev(
                dev.properties, "ID_PCI_SUBCLASS_FROM_DATABASE", ""
            )
            database_vendor = get_property_pyudev(
                dev.properties, "ID_VENDOR_FROM_DATABASE", ""
            )
            if dev.parent.subsystem != "pci":
                if dev == devices[-1]:
                    prefix = "└─"
                else:
                    prefix = "│ "
            else:
                if dev == devices[-1]:
                    prefix = "└─"
                else:
                    prefix = "├─ "
            p = os.path.join(dev.sys_path, "firmware_node", "path")
            if os.path.exists(p):
                acpi = read_file(p)
                logging.debug(
                    f"{prefix}{pci_slot_name} : {database_vendor} {database_class} [{pci_id}] : {acpi}"
                )
            else:
                logging.debug(
                    f"{prefix}{pci_slot_name} : {database_vendor} {database_class} [{pci_id}]"
                )
        return True

    def capture_irq(self):
        p = os.path.join("/sys", "kernel", "irq")
        self.irqs = []
        for d in os.listdir(p):
            if os.path.isdir(os.path.join(p, d)):
                w = WakeIRQ(d, self.pyudev)
                self.irqs.append([int(d), str(w)])
        self.irqs.sort()
        logging.debug("Interrupts")
        for irq in self.irqs:
            # set prefix if last IRQ
            prefix = "│ " if irq != self.irqs[-1] else "└─"
            logging.debug(f"{prefix}{irq[0]}: {irq[1]}")
        return True

    def capture_acpi(self):
        if not self.iasl:
            print_color(headers.MissingIasl, colors.WARNING)
            return True
        if not self.root_user:
            logging.debug("Unable to capture ACPI tables without root")
            return True
        base = os.path.join("/", "sys", "firmware", "acpi", "tables")
        for root, dirs, files in os.walk(base, topdown=False):
            for fname in files:
                target = os.path.join(root, fname)
                # capture all DSDT/SSDT when run with --acpidump
                if self.acpidump:
                    if not "DSDT" in fname and not "SSDT" in fname:
                        continue
                else:
                    with open(target, "rb") as f:
                        s = f.read()
                        if s.find(b"_AEI") < 0:
                            continue
                try:
                    d = tempfile.mkdtemp()
                    prefix = os.path.join(d, "acpi")
                    subprocess.check_call(
                        ["iasl", "-p", prefix, "-d", target],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    capture_file_to_debug(f"{prefix}.dsl")
                except subprocess.CalledProcessError as e:
                    print_color(f"Failed to capture ACPI table: {e.output}", "👀")
                finally:
                    shutil.rmtree(d)
        return True

    def capture_linux_firmware(self):
        if self.distro == "ubuntu" or self.distro == "debian":
            import apt

            cache = apt.Cache()
            packages = ["linux-firmware"]
            for obj in cache.get_providing_packages("amdgpu-firmware-nda"):
                packages += [obj.name]
            for p in packages:
                pkg = cache.get(p)
                if not pkg:
                    continue
                changelog = ""
                if "amdgpu" in p:
                    for f in pkg.installed_files:
                        import gzip

                        if not "changelog" in f:
                            continue
                        changelog = gzip.GzipFile(f).read().decode("utf-8")
                if changelog:
                    for line in changelog.split("\n"):
                        logging.debug(line)
                else:
                    logging.debug(pkg.installed)

        for num in range(0, 2):
            p = os.path.join(
                "/", "sys", "kernel", "debug", "dri", "%d" % num, "amdgpu_firmware_info"
            )
            if os.path.exists(p):
                capture_file_to_debug(p)
        return True

    def capture_command_line(self):
        cmdline = read_file(os.path.join("/proc", "cmdline"))
        # borrowed from https://github.com/fwupd/fwupd/blob/1.9.5/libfwupdplugin/fu-common-linux.c#L95
        filtered = [
            "apparmor",
            "audit",
            "auto",
            "boot",
            "BOOT_IMAGE",
            "console",
            "crashkernel",
            "cryptdevice",
            "cryptkey",
            "dm",
            "earlycon",
            "earlyprintk",
            "ether",
            "initrd",
            "ip",
            "LANG",
            "loglevel",
            "luks.key",
            "luks.name",
            "luks.options",
            "luks.uuid",
            "mitigations",
            "mount.usr",
            "mount.usrflags",
            "mount.usrfstype",
            "netdev",
            "netroot",
            "nfsaddrs",
            "nfs.nfs4_unique_id",
            "nfsroot",
            "noplymouth",
            "ostree",
            "quiet",
            "rd.dm.uuid",
            "rd.luks.allow-discards",
            "rd.luks.key",
            "rd.luks.name",
            "rd.luks.options",
            "rd.luks.uuid",
            "rd.lvm.lv",
            "rd.lvm.vg",
            "rd.md.uuid",
            "rd.systemd.mask",
            "rd.systemd.wants",
            "resume",
            "resumeflags",
            "rhgb",
            "ro",
            "root",
            "rootflags",
            "roothash",
            "rw",
            "security",
            "showopts",
            "splash",
            "swap",
            "systemd.mask",
            "systemd.show_status",
            "systemd.unit",
            "systemd.verity_root_data",
            "systemd.verity_root_hash",
            "systemd.wants",
            "udev.log_priority",
            "verbose",
            "vt.handoff",
            "zfs",
        ]
        # remove anything that starts with something in filtered from cmdline
        cmdline = " ".join(
            [x for x in cmdline.split() if not x.startswith(tuple(filtered))]
        )
        logging.debug(f"/proc/cmdline: {cmdline}")
        return True

    def capture_logind(self):
        base = os.path.join("/", "etc", "systemd", "logind.conf")
        if not os.path.exists(base):
            return True
        import configparser

        config = configparser.ConfigParser()
        config.read(base)
        section = config["Login"]
        if not section.keys():
            logging.debug("LOGIND: no configuration changes")
            return True
        logging.debug("LOGIND: configuration changes:")
        for key in section.keys():
            logging.debug(f"\t{key}: {section[key]}")
        return True

    def capture_disabled_pins(self):
        base = os.path.join("/", "sys", "module", "gpiolib_acpi", "parameters")
        for parameter in ["ignore_wake", "ignore_interrupt"]:
            f = os.path.join(base, parameter)
            if not os.path.exists(f):
                continue
            with open(f, "r") as r:
                d = r.read().rstrip()
                if d == "(null)":
                    logging.debug(f"{f} is not configured")
                else:
                    logging.debug(f"{f} is configured to {d}")
        return True

    def capture_full_dmesg(self):
        if not self.kernel_log:
            message = "Unable to analyze kernel log"
            print_color(message, colors.WARNING)
            return
        self.kernel_log.capture_full_dmesg()

    def check_logger(self):
        if isinstance(self.kernel_log, SystemdLogger):
            print_color("Logs are provided via systemd", "✅")
        elif isinstance(self.kernel_log, DmesgLogger):
            print_color(
                "🚦Logs are provided via dmesg, timestamps may not be accurate over multiple cycles",
                colors.WARNING,
            )
            header = self.kernel_log.capture_header()
            if not header.startswith("Linux version"):
                print_color(
                    "Kernel ringbuffer has wrapped, unable to accurately validate pre-requisites",
                    "❌",
                )
                self.failures += [KernelRingBufferWrapped()]
                return False
        else:
            return False
        return True

    def check_logind(self):
        if not self.logind:
            return True
        try:
            import dbus
        except ImportError:
            print_color("Unable to import dbus", "❌")
            return False
        try:
            bus = dbus.SystemBus()
            obj = bus.get_object("org.freedesktop.login1", "/org/freedesktop/login1")
            intf = dbus.Interface(obj, "org.freedesktop.login1.Manager")
            if intf.CanSuspend() != "yes":
                print_color("Unable to suspend with logind", "❌")
                return False
        except dbus.exceptions.DBusException as e:
            print_color("Unable to communicate with logind", "❌")
            return False
        return True

    def check_power_profile(self):
        cmd = ["/usr/bin/powerprofilesctl"]
        if os.path.exists(cmd[0]):
            logging.debug("Power profiles:")
            output = subprocess.check_output(cmd).decode("utf-8")
            for line in output.split("\n"):
                logging.debug(f" {line}")
        return True

    def check_taint(self):
        fn = os.path.join("/", "proc", "sys", "kernel", "tainted")
        taint = int(read_file(fn))
        # ignore kernel warnings
        taint &= ~BIT(9)
        if taint != 0:
            print_color(f"Kernel is tainted: {taint}", "❌")
            self.failures += [TaintedKernel()]
            return False
        return True

    def prerequisites(self):
        print_color(headers.Info, colors.HEADER)
        info = [
            self.capture_system_vendor,
            self.capture_kernel_version,
            self.check_battery,
            self.check_thermal,
        ]
        for i in info:
            i()

        print_color(headers.Prerequisites, colors.HEADER)
        checks = [
            self.check_logger,
            self.check_cpu_vendor,
            self.check_aspm,
            self.check_smt,
            self.check_lps0,
            self.check_fadt,
            self.capture_disabled_pins,
            self.capture_command_line,
            self.capture_logind,
            self.check_amd_hsmp,
            self.check_amd_pmc,
            self.check_usb4,
            self.cpu_offers_hpet_wa,
            self.check_amdgpu,
            self.check_sleep_mode,
            self.check_storage,
            self.check_pinctrl_amd,
            self.check_device_firmware,
            self.check_network,
            self.check_wcn6855_bug,
            self.check_lockdown,
            self.check_msr,
            self.check_iommu,
            self.check_permissions,
            self.capture_linux_firmware,
            self.map_acpi_pci,
            self.capture_irq,
            self.check_i2c_hid,
            self.check_wake_sources,
            self.capture_acpi,
            self.check_logind,
            self.check_power_profile,
            self.check_taint,
        ]
        result = True
        for check in checks:
            if not check():
                result = False
        if not result:
            print_color(headers.BrokenPrerequisites, colors.UNDERLINE)
            self.capture_full_dmesg()
        return result

    def check_lockdown(self):
        fn = os.path.join("/", "sys", "kernel", "security", "lockdown")
        try:
            lockdown = read_file(fn)
        except FileNotFoundError:
            logging.debug("Lockdown not available")
            return True
        logging.debug(f"Lockdown: {lockdown}")
        if lockdown.split()[0] != "[none]":
            self.lockdown = True
        return True

    def minimum_kernel(self, major, minor):
        """Checks if the kernel version is at least major.minor"""
        if self.kernel_major > major:
            return True
        if self.kernel_major < major:
            return False
        return self.kernel_minor >= minor

    def toggle_dynamic_debugging(self, enable):
        try:
            fn = os.path.join("/", "sys", "kernel", "debug", "dynamic_debug", "control")
            setting = "+" if enable else "-"
            if not self.minimum_kernel(6, 2):
                with open(fn, "w") as w:
                    w.write(f"file drivers/acpi/x86/s2idle.c {setting}p")
            if not self.minimum_kernel(6, 5):
                # only needed if missing https://github.com/torvalds/linux/commit/c9a236419ff936755eb5db8a894c3047440e65a8
                with open(fn, "w") as w:
                    w.write(f"file drivers/pinctrl/pinctrl-amd.c {setting}p")
                # only needed if missing https://github.com/torvalds/linux/commit/b77505ed8a885c67a589c049c38824082a569068
                with open(fn, "w") as w:
                    w.write(f"file drivers/platform/x86/amd/pmc.c {setting}p")
            if self.debug_ec:
                with open(fn, "w") as w:
                    w.write(f"file drivers/acpi/ec.c {setting}p")
        except PermissionError:
            # caught by lockdown test
            pass

    def _analyze_kernel_log_line(self, line):
        if "Timekeeping suspended for" in line:
            self.cycle_count += 1
            for f in line.split():
                try:
                    self.kernel_duration += float(f)
                except ValueError:
                    pass
        elif "Successfully transitioned to state" in line:
            self.upep = True
            if "Successfully transitioned to state lps0 ms entry" in line:
                self.upep_microsoft = True
        elif "_DSM function" in line:
            self.upep = True
            if "_DSM function 7" in line:
                self.upep_microsoft = True
        elif "PM: suspend entry" in line:
            self.suspend_count += 1
        elif "Last suspend in deepest state for" in line:
            for f in line.split():
                if not f.endswith("us"):
                    continue
                try:
                    self.hw_sleep_duration += float(f.strip("us")) / 10**6
                except ValueError:
                    pass
        elif "Triggering wakeup from IRQ" in line:
            irq = int(line.split()[-1])
            if irq and irq not in self.wakeup_irqs:
                self.wakeup_irqs += [irq]
        elif "SMU idlemask s0i3" in line:
            self.idle_masks += [line.split()[-1]]
        elif "ACPI BIOS Error" in line or "ACPI Error" in line:
            self.acpi_errors += [line]
        elif re.search("GPIO.*is active", line):
            self.active_gpios += re.findall(
                r"\d+", re.search("GPIO.*is active", line).group()
            )
        elif headers.Irq1Workaround in line:
            self.irq1_workaround = True
        logging.debug(line)

    def cpu_offers_hpet_wa(self):
        from packaging import version

        show_warning = False
        if self.cpu_family == 0x17:
            if self.cpu_model == 0x68 or self.cpu_model == 0x60:
                show_warning = True
        elif self.cpu_family == 0x19:
            if self.cpu_model == 0x50:
                if self.smu_version:
                    show_warning = version.parse(self.smu_version) < version.parse(
                        "64.53.0"
                    )
        if show_warning:
            print_color(
                "Timer based wakeup doesn't work properly for your ASIC/firmware, please manually wake the system",
                colors.WARNING,
            )
        return True

    def cpu_needs_irq1_wa(self):
        from packaging import version

        if self.cpu_family == 0x17:
            if self.cpu_model == 0x68 or self.cpu_model == 0x60:
                return True
        elif self.cpu_family == 0x19:
            if self.cpu_model == 0x50:
                return version.parse(self.smu_version) < version.parse("64.66.0")
        return False

    def analyze_kernel_log(self):
        self.suspend_count = 0
        self.cycle_count = 0
        self.upep = False
        self.upep_microsoft = False
        self.wakeup_irqs = []
        self.idle_masks = []
        self.acpi_errors = []
        self.active_gpios = []
        self.irq1_workaround = False
        self.kernel_log.seek(self.last_suspend)
        self.kernel_log.process_callback(self._analyze_kernel_log_line)

        if self.suspend_count:
            print_color(
                f"Suspend count: {self.suspend_count}",
                "💤",
            )

        if self.cycle_count:
            print_color(
                f"Hardware sleep cycle count: {self.cycle_count}",
                "💤",
            )
        if self.active_gpios:
            print_color(f"GPIOs active: {self.active_gpios}", "○")
        if self.wakeup_irqs:
            for n in self.wakeup_irqs:
                for irq in self.irqs:
                    if irq[0] == int(n):
                        print_color(
                            f"{headers.WakeTriggeredIrq} {irq[0]}: {irq[1]}", "🥱"
                        )
            if 1 in self.wakeup_irqs and self.cpu_needs_irq1_wa():
                if self.irq1_workaround:
                    print_color("Kernel workaround for IRQ1 issue utilized")
                else:
                    print_color("IRQ1 found during wakeup", colors.WARNING)
                    self.failures += [Irq1Workaround()]
        if self.idle_masks:
            bit_changed = 0
            for i in range(0, len(self.idle_masks)):
                for j in range(i, len(self.idle_masks)):
                    if self.idle_masks[i] != self.idle_masks[j]:
                        bit_changed = bit_changed | (
                            int(self.idle_masks[i], 16) & ~int(self.idle_masks[j], 16)
                        )
            if bit_changed:
                for bit in range(0, 31):
                    if bit_changed & BIT(bit):
                        print_color(
                            "Idle mask bit %d (0x%x) changed during suspend"
                            % (bit, BIT(bit)),
                            "○",
                        )
        if self.upep:
            if self.upep_microsoft:
                logging.debug("Used Microsoft uPEP GUID in LPS0 _DSM")
            else:
                logging.debug("Used AMD uPEP GUID in LPS0 _DSM")
        if self.acpi_errors:
            print_color("ACPI BIOS errors found", "❌")
            self.failures += [AcpiBiosError(self.acpi_errors)]

    def analyze_masks(self):
        try:
            from common import add_model_checks

            func = add_model_checks(self.cpu_model, self.cpu_family)
            for mask in self.idle_masks:
                func(mask)
        except ImportError:
            pass

    def analyze_duration(self):
        now = datetime.now()
        self.userspace_duration = now - self.last_suspend
        min_suspend_duration = timedelta(seconds=self.requested_duration * 0.9)
        expected_wake_time = self.last_suspend + min_suspend_duration
        if now > expected_wake_time:
            logging.debug(f"Userspace suspended for {self.userspace_duration}")
        else:
            print_color(
                f"Userspace suspended for {self.userspace_duration} (< minimum expected {min_suspend_duration})",
                "❌",
            )
            self.failures += [SpuriousWakeup(self.requested_duration)]
        if self.kernel_duration:
            if self.userspace_duration:
                percent = (
                    float(self.kernel_duration)
                    / self.userspace_duration.total_seconds()
                )
            else:
                percent = 0
            logging.debug(
                f"Kernel suspended for total of {timedelta(seconds=self.kernel_duration)} ({percent:.2%})"
            )

    def analyze_results(self):
        print_color(headers.LastCycleResults, colors.HEADER)
        result = True
        checks = [
            self.analyze_kernel_log,
            self.check_wakeup_irq,
            self.capture_gpes,
            self.capture_lid,
            self.analyze_duration,
            self.check_hw_sleep,
            self.check_battery,
            self.check_thermal,
            self.check_rtc_cmos,
        ]
        for check in checks:
            check()

    def run_countdown(self, prefix, t):
        msg = ""
        while t > 0:
            msg = f"{prefix} in {timedelta(seconds=t)}"
            print(msg, end="\r", flush=True)
            time.sleep(1)
            t -= 1
        print(" " * len(msg), end="\r")

    @pm_debugging
    def execute_suspend(self):
        if self.logind:
            try:
                import dbus

                bus = dbus.SystemBus()
                obj = bus.get_object(
                    "org.freedesktop.login1", "/org/freedesktop/login1"
                )
                intf = dbus.Interface(obj, "org.freedesktop.login1.Manager")
                propf = dbus.Interface(obj, "org.freedesktop.DBus.Properties")
                intf.Suspend(True)
                while propf.Get("org.freedesktop.login1.Manager", "PreparingForSleep"):
                    time.sleep(1)
                return True
            except dbus.exceptions.DBusException as e:
                print_color("Unable to communicate with logind", "❌")
                return False
        else:
            p = os.path.join("/", "sys", "power", "state")
            try:
                with open(p, "w") as w:
                    w.write("mem")
            except OSError as e:
                print_color("Failed to suspend", "❌")
                logging.debug(e)
                return False
        return True

    def unlock_session(self):
        if self.logind:
            try:
                import dbus

                bus = dbus.SystemBus()
                obj = bus.get_object(
                    "org.freedesktop.login1", "/org/freedesktop/login1"
                )
                intf = dbus.Interface(obj, "org.freedesktop.login1.Manager")
                intf.UnlockSessions()
            except dbus.exceptions.DBusException as e:
                print_color("Unable to communicate with logind", "❌")
                return False
        return True

    def test_suspend(self, duration, count, wait):
        if not count:
            return True

        if count > 1:
            length = timedelta(seconds=(duration + wait) * count)
            print_color(
                "Running {count} cycles (Test finish expected @ {time})".format(
                    count=count, time=datetime.now() + length
                ),
                colors.HEADER,
            )

        self.requested_duration = duration
        logging.debug(
            f"{headers.SuspendDuration} {timedelta(seconds=self.requested_duration)}",
        )
        wakealarm = None
        for device in self.pyudev.list_devices(subsystem="rtc"):
            wakealarm = os.path.join(device.sys_path, "wakealarm")
        self.toggle_dynamic_debugging(True)

        for i in range(1, count + 1):
            self.capture_gpes()
            self.capture_lid()
            self.capture_amdgpu_ips_status()
            self.run_countdown("Suspending system", wait / 2)
            self.last_suspend = datetime.now()
            self.kernel_duration = 0
            self.hw_sleep_duration = 0
            if count > 1:
                header = f"{headers.CycleCount} {i}: "
            else:
                header = ""
            print_color(
                "{header}Started at {start} (cycle finish expected @ {finish})".format(
                    header=header,
                    start=self.last_suspend,
                    finish=datetime.now()
                    + timedelta(seconds=self.requested_duration + wait),
                ),
                colors.HEADER,
            )
            if wakealarm:
                try:
                    with open(wakealarm, "w") as w:
                        w.write("0")
                    with open(wakealarm, "w") as w:
                        w.write(f"+{self.requested_duration}\n")
                except OSError as e:
                    print_color(
                        "Failed to program wakealarm, please manually wake system", "🚦"
                    )
                    logging.debug(e)
            else:
                print_color("No RTC device found, please manually wake system", "🚦")
            if self.execute_suspend():
                self.unlock_session()
                self.run_countdown("Collecting data", wait / 2)
                self.analyze_results()
        self.toggle_dynamic_debugging(False)
        return True

    def get_failure_report(self):
        if len(self.failures) == 0:
            return True
        print_color(headers.ExplanationReport, colors.HEADER)
        for item in self.failures:
            item.get_failure()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Test for common s2idle problems on systems with AMD processors.",
        epilog="Arguments are optional, and if they are not provided will prompted.\n"
        "To use non-interactively, please populate all optional arguments.",
    )
    parser.add_argument(
        "--log",
        help=headers.LogDescription,
    )
    parser.add_argument(
        "--duration",
        help=headers.DurationDescription,
    )
    parser.add_argument(
        "--wait",
        help=headers.WaitDescription,
    )
    parser.add_argument(
        "--kernel-log-provider",
        default="auto",
        choices=["auto", "systemd", "dmesg"],
        help="Kernel log provider",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Run suspend test even if prerequisites failed",
    )
    parser.add_argument("--count", help=headers.CountDescription)
    parser.add_argument(
        "--acpidump",
        action="store_true",
        help="Include and extract full ACPI dump in report",
    )
    parser.add_argument(
        "--logind", action="store_true", help="Use logind to suspend system"
    )
    parser.add_argument("--debug-ec", action="store_true", help=headers.EcDebugging)
    return parser.parse_args()


def configure_log(log):
    if not log:
        fname = f"{defaults.log_prefix}-{date.today()}.{defaults.log_suffix}"
        log = input(f"{headers.LogDescription} (default {fname})? ")
        if not log:
            log = fname
    return log


def configure_suspend(duration, wait, count):
    if not duration:
        duration = input(
            f"{headers.DurationDescription} (default {defaults.duration})? "
        )
        if not duration:
            duration = defaults.duration
    if not wait:
        wait = input(f"{headers.WaitDescription} (default {defaults.wait})? ")
        if not wait:
            wait = defaults.wait
    if not count:
        count = input(f"{headers.CountDescription} (default {defaults.count})? ")
        if not count:
            count = defaults.count
    return [int(duration), int(wait), int(count)]


if __name__ == "__main__":
    args = parse_args()
    log = configure_log(args.log)

    app = S0i3Validator(
        log, args.acpidump, args.logind, args.debug_ec, args.kernel_log_provider
    )
    test = app.prerequisites()
    if test or args.force:
        duration, wait, count = configure_suspend(
            duration=args.duration, wait=args.wait, count=args.count
        )
        app.test_suspend(duration=duration, wait=wait, count=count)
    app.get_failure_report()
