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
from datetime import datetime, timedelta, date


class colors:
    DEBUG = "\033[90m"
    HEADER = "\033[95m"
    OK = "\033[94m"
    WARNING = "\033[93m"
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
    MissingPyudev = "Udev access library `pyudev` is missing"
    MissingPackaging = "Python library `packaging` is missing"
    MissingIasl = "ACPI extraction tool `iasl` is missing"
    Irq1Workaround = "Disabling IRQ1 wakeup source to avoid platform firmware bug"
    DurationDescription = "How long should suspend cycles last in seconds"
    WaitDescription = "How long to wait in between suspend cycles in seconds"
    CountDescription = "How many suspend cycles to run"
    LogDescription = "Location of log file"
    InstallAction = "Attempting to install"
    RerunAction = "Running this script as root will attempt to install it"
    FailureReport = "S0i3 failures reported on your system"


def read_file(fn):
    with open(fn, "r") as r:
        return r.read().strip()


def compare_sysfs(fn, expect):
    return read_file(fn) == expect


def check_dynamic_debug(message):
    """Check if dynamic debug supports a given message"""
    fn = os.path.join("/", "sys", "kernel", "debug", "dynamic_debug", "control")
    try:
        dbg = read_file(fn)
        for line in dbg.split("\n"):
            if re.search(message, line):
                return True
    except PermissionError:
        pass
    return False


def capture_file_to_debug(fn):
    """Reads and captures all contents of fn"""
    try:
        contents = read_file(fn)
        for line in contents.split("\n"):
            logging.debug(line.rstrip())
    except PermissionError:
        logging.debug("Unable to capture %s" % fn)


def print_color(message, color):
    print("{color}{message}{end}".format(color=color, message=message, end=colors.ENDC))


class S0i3Failure:
    def __init__(self):
        self.explanation = ""
        self.url = ""
        self.description = ""

    def get_failure(self):
        if self.description:
            print_color(self.description, colors.WARNING)
        if self.explanation:
            print(self.explanation)
        if self.url:
            print("For more information on this failure see:\n\t%s" % self.url)


class MissingAmdgpu(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "AMDGPU driver is missing"
        self.explanation = (
            "\tThe amdgpu driver is used for hardware acceleration as well\n"
            "\tas coordination of the power states for certain IP blocks on the SOC.\n"
            "\tBe sure that you have enabled CONFIG_AMDGPU in your kernel.\n"
        )


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
            self.explanation += "\t%s" % error


class VendorWrong(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "Unsupported CPU vendor"
        self.explanation = (
            "\tThis tool specifically measures requirements utilized\n"
            "\tby AMD's S0i3 architecture.  Some of them may apply to other\n"
            "\tvendors, but definitely some are AMD specific."
        )


class AcpiNvmeStorageD3Enable(S0i3Failure):
    def __init__(self, disk, num_ssds):
        super().__init__()
        self.description = "{disk} missing ACPI attributes".format(disk=disk)
        self.explanation = (
            "\tAn NVME device was found, but it doesn't specify the StorageD3Enable\n"
            "\tattribute in the device specific data (_DSD).\n"
            "\tThis is a BIOS bug, but it may be possible to work around in the kernel.\n"
        )
        if num_ssds > 1:
            self.explanation += (
                "\n"
                "\tIf you added an aftermarket SSD to your system, the system vendor might not added this\n"
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


class KernelLockdown(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "Kernel lockdown engaged"
        self.explanation = (
            "\tKernel lockdown is a security feature that makes sure that processes can't tamper\n"
            "\twith the security state of the kernel.\n"
            "\tThis is generally a good security feature, but it will prevent the capture of some.\n"
            "\tdebugging information\n"
            "\n"
            "\tPlease disable it and re-run this script for a more accurate report.\n"
            "\tIf you didn't manually enable it, some Linux distributions enable it when UEFI secure\n"
            "\tboot has been enabled. So you may want to manually disable it to capture debugging data.\n"
        )


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


class uPepMissing(S0i3Failure):
    def __init__(self):
        super().__init__()
        self.description = "LPS0 _DSM might not have been executed"
        self.explanation = (
            "\tThe Linux kernel will execute an ACPI callback during s2idle entry.\n"
            "\tThis callback is typically used to notify the Embedded Controller (EC) on the system.\n"
            "\tDepending upon the OEM implementation these requests may have been populated behind.\n"
            "\tan 'AMD' GUID or an 'Microsoft' GUID. This script turns on extra dynamic debugging.\n"
            "\tmessages to determine which path was used.\n"
            "\n"
            "\tIf no message was detected this might not mean there is a problem, it just means this\n"
            "\tscript couldn't confirm it.  These are some of the possible causes:\n"
            "\t * It has been intentionally turned off on the kernel command line by a user.\n"
            "\t * The BIOS is missing support for it.\n"
            "\t * Kernel lockdown is engaged.\n"
            "\t * Dynamic debugging couldn't be used to turn on the messages.\n"
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


class SpuriousWakeup(S0i3Failure):
    def __init__(self, duration):
        super().__init__()
        self.description = "Userspace wasn't asleep at least {time}".format(
            time=timedelta(seconds=duration)
        )
        self.explanation = (
            "\tThe system was programmed to sleep for {time}, but woke up prematurely.\n"
            "\tThis typically happens when the system was woken up from a non-timer based source.\n"
            "\n"
            "\tIf you didn't intentionally wake it up, then there may be a kernel or firmware bug\n".format(
                time=timedelta(seconds=duration)
            )
        )


class LowHardwareSleepResidency(S0i3Failure):
    def __init__(self, duration, percent):
        super().__init__()
        self.description = "System had low hardware sleep residency"
        self.explanation = (
            "\tThe system was asleep for {time}, but only spent {percent:.2%}\n"
            "\tof this time in a hardware sleep state.  In sleep cycles that are at least\n"
            "\t60 seconds long it's expected you spend above 90 percent of the cycle in"
            "\thardware sleep.\n"
        ).format(time=timedelta(seconds=duration), percent=percent)


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
            # look 10 seconds back because dmesg time isn't always accurate
            fuzz = time - timedelta(seconds=10)
            cmd = self.command + [
                "--time-format=iso",
                "--since=%s" % fuzz.strftime("%Y-%m-%dT%H:%M:%S"),
            ]
            result = subprocess.run(cmd, check=True, capture_output=True)
            if result.returncode == 0:
                self.buffer = result.stdout.decode("utf-8")
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
                return entry
        return None

    def capture_full_dmesg(self, line=None):
        self.seek()
        for entry in self.journal:
            super().capture_full_dmesg(entry["MESSAGE"])


class DistroPackage:
    def __init__(self, deb, rpm, pip, root):
        self.deb = deb
        self.rpm = rpm
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
            installer = ["dnf", "install", "-y", self.rpm]
        else:
            if not self.pip:
                return False
            installer = ["python3", "-m", "pip", "install", "--upgrade", self.pip]
        subprocess.check_call(installer)
        return True


class PyUdevPackage(DistroPackage):
    def __init__(self, root):
        super().__init__(
            deb="python3-pyudev", rpm="python3-pyudev", pip="pyudev", root=root
        )


class IaslPackage(DistroPackage):
    def __init__(self, root):
        super().__init__(deb="acpica-tools", rpm="python3-pyudev", pip=None, root=root)


class PackagingPackage(DistroPackage):
    def __init__(self, root):
        super().__init__(
            deb="python3-packaging", rpm=None, pip="python3-setuptools", root=root
        )


class S0i3Validator:
    def log(self, message, color):
        if color == colors.FAIL:
            logging.error(message)
        elif color == colors.UNDERLINE or color == colors.WARNING:
            logging.warning(message)
        else:
            logging.info(message)
        print_color(message, color)

    def show_install_message(self, message):
        action = headers.InstallAction if self.root_user else headers.RerunAction
        message = "👀 {message}. {action}.".format(message=message, action=action)
        self.log(message, colors.FAIL)

    def __init__(self, log, acpidump, kernel_log):
        # for saving a log file for analysis
        logging.basicConfig(
            format="%(asctime)s %(levelname)s:\t%(message)s",
            filename=log,
            filemode="w",
            level=logging.DEBUG,
        )

        # for installing and running suspend
        self.root_user = os.geteuid() == 0

        # capture all DSDT/SSDT or just one with _AEI
        self.acpidump = acpidump

        # for analyzing devices
        try:
            import distro

            self.distro = distro.id()
        except ModuleNotFoundError:
            self.distro = ""
            self.pretty_distro = ""
        try:
            if self.distro:
                self.pretty_distro = distro.distro.os_release_info()["pretty_name"]
        except AttributeError:
            self.pretty_distro = ""
        try:
            from pyudev import Context

            self.pyudev = Context()
        except ModuleNotFoundError:
            self.pyudev = False

        if not self.pyudev:
            self.show_install_message(headers.MissingPyudev)
            package = PyUdevPackage(self.root_user)
            package.install(self.distro)
            from pyudev import Context

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
            try:
                self.kernel_log = SystemdLogger()
            except ImportError:
                self.kernel_log = None
            if not self.kernel_log:
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

        # for analyzing offline reports
        self.offline = None
        self.offline_report = False

        # for comparing GPEs before/after sleep
        self.gpes = {}

        # for monitoring battery levels across suspend
        self.energy = {}
        self.charge = {}

        # If we're locked down, a lot less errors make sense
        self.lockdown = False

    # See https://github.com/torvalds/linux/commit/ec6c0503190417abf8b8f8e3e955ae583a4e50d4
    def check_fadt(self):
        """Check the kernel emitted a message specific to 6.0 or later indicating FADT had a bit set."""
        found = False
        if self.offline:
            for line in self.offline:
                if "Low-power S0 idle used by default for system suspend" in line:
                    found = True
                    break
                # re-entrant; don't re-run
                if "✅ ACPI FADT supports Low-power S0 idle" in line:
                    return
        else:
            if not self.kernel_log:
                message = "🚦 Unable to test FADT from kernel log"
                self.log(message, colors.WARNING)
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
            with open(target, "rb") as r:
                r.seek(0x70)
                found = struct.unpack("<I", r.read(4))[0] & (1 << 21)
        if found:
            message = "✅ ACPI FADT supports Low-power S0 idle"
            self.log(message, colors.OK)
        else:
            message = "❌ ACPI FADT doesn't support Low-power S0 idle"
            self.log(message, colors.FAIL)
            self.failures += [FadtWrong()]
        return found

    def capture_kernel_version(self):
        """Log the kernel version used"""
        if self.pretty_distro:
            self.log("🐧 {distro}".format(distro=self.pretty_distro), colors.OK)
        self.log(
            "🐧 Kernel {version}".format(version=platform.uname().release), colors.OK
        )

    def check_battery(self):
        for dev in self.pyudev.list_devices(
            subsystem="power_supply", POWER_SUPPLY_TYPE="Battery"
        ):
            if not "PNP0C0A" in dev.device_path:
                continue

            energy_full_design = dev.properties.get("POWER_SUPPLY_ENERGY_FULL_DESIGN")
            energy_full = dev.properties.get("POWER_SUPPLY_ENERGY_FULL")
            energy = dev.properties.get("POWER_SUPPLY_ENERGY_NOW")
            charge_full_design = dev.properties.get("POWER_SUPPLY_CHARGE_FULL_DESIGN")
            charge_full = dev.properties.get("POWER_SUPPLY_CHARGE_FULL")
            charge = dev.properties.get("POWER_SUPPLY_CHARGE_NOW")
            man = dev.properties.get("POWER_SUPPLY_MANUFACTURER")
            model = dev.properties.get("POWER_SUPPLY_MODEL_NAME")
            name = dev.properties.get("POWER_SUPPLY_NAME")

            if energy_full_design:
                logging.debug(
                    "{battery} energy level is {energy} µWh".format(
                        battery=name, energy=energy
                    )
                )
                if not name in self.energy:
                    self.log(
                        "🔋 Battery {name} ({man} {model}) is operating at {percent:.2%} of design".format(
                            name=name,
                            man=man,
                            model=model,
                            percent=float(energy_full) / int(energy_full_design),
                        ),
                        colors.OK,
                    )
                else:
                    diff = abs(int(energy) - self.energy[name])
                    percent = float(diff) / int(energy_full)
                    if int(energy) > self.energy[name]:
                        action = "gained"
                    else:
                        action = "lost"
                    self.log(
                        "🔋 Battery {name} {action} {energy} µWh ({percent:.2%})".format(
                            name=name, action=action, energy=diff, percent=percent
                        ),
                        colors.OK,
                    )
                self.energy[name] = int(energy)

            if charge_full_design:
                logging.debug(
                    "{battery} charge level is {charge} µAh".format(
                        battery=name, charge=charge
                    )
                )
                if not name in self.energy:
                    self.log(
                        "○ Battery {name} ({man} {model}) is operating at {percent:.2%} of design".format(
                            name=name,
                            man=man,
                            model=model,
                            percent=float(charge_full) / int(charge_full_design),
                        ),
                        colors.OK,
                    )
                else:
                    diff = abs(int(charge) - self.charge[name])
                    percent = float(diff) / int(charge_full)
                    if int(charge) > self.charge[name]:
                        action = "gained"
                    else:
                        action = "lost"
                    self.log(
                        "○ Battery {name} {action} {charge} µAh ({percent:.2%})".format(
                            name=name, action=action, charge=diff, percent=percent
                        ),
                        colors.OK,
                    )
                self.charge[name] = int(charge)

        return True

    def check_lps0(self):
        p = os.path.join("/", "sys", "module", "acpi", "parameters", "sleep_no_lps0")
        fail = read_file(p) == "Y"
        if fail:
            self.log("❌ LPS0 _DSM disabled", colors.FAIL)
        else:
            self.log("✅ LPS0 _DSM enabled", colors.OK)
        return not fail

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
                self.log(
                    "✅ %s (family %x model %x)"
                    % (self.cpu_model_string, self.cpu_family, self.cpu_model),
                    colors.OK,
                )
                break
        if not valid:
            self.failures += [VendorWrong()]
            self.log(
                "❌ This tool is not designed for parts from this CPU vendor",
                colors.FAIL,
            )
        return valid

    def capture_system_vendor(self):
        p = os.path.join("/", "sys", "class", "dmi", "id")
        try:
            vendor = read_file(os.path.join(p, "sys_vendor"))
            product = read_file(os.path.join(p, "product_name"))
            family = read_file(os.path.join(p, "product_family"))
            release = read_file(os.path.join(p, "bios_release"))
            version = read_file(os.path.join(p, "bios_version"))
            date = read_file(os.path.join(p, "bios_date"))
            self.log(
                "💻 {vendor} {product} ({family}) running BIOS {release} ({version}) released {date}".format(
                    vendor=vendor,
                    product=product,
                    family=family,
                    release=release,
                    version=version,
                    date=date,
                ),
                colors.OK,
            )
        except FileNotFoundError:
            pass

    def check_sleep_mode(self):
        fn = os.path.join("/", "sys", "power", "mem_sleep")
        if not os.path.exists(fn):
            self.log("❌ Kernel doesn't support sleep", colors.FAIL)
            return False
        if not compare_sysfs(fn, "[s2idle]"):
            self.failures += [SleepModeWrong()]
            self.log(
                "❌ System isn't configured for s2idle in firmware setup", colors.FAIL
            )
            return False
        self.log("✅ System is configured for s2idle", colors.OK)
        return True

    def check_storage(self):
        has_sata = False
        valid_nvme = {}
        invalid_nvme = {}
        valid_sata = False
        valid_ahci = False

        if self.offline:
            for line in self.offline:
                if "nvme" in line:
                    has_nvme = True
                if "SATA link up" in line:
                    has_sata = True
                if headers.NvmeSimpleSuspend in line:
                    objects = line.split()
                    for i in range(0, len(objects)):
                        if objects[i] == "nvme":
                            valid_nvme[objects[i + 1]] = objects[i + 1]
                if has_sata and _check_ahci_devslp(line):
                    valid_ahci = True
                if has_sata and _check_ata_devslp(line):
                    valid_sata = True
                # re-entrant; don't re-run
                if "✅ NVME" in line:
                    return True
                if "❌ NVME" in line:
                    return True
                if "✅ AHCI" in line:
                    return True
                if "✅ SATA" in line:
                    return True

        else:
            if not self.kernel_log:
                message = "🚦 Unable to test storage from kernel log"
                self.log(message, colors.WARNING)
                return True

            for dev in self.pyudev.list_devices(subsystem="pci", DRIVER="nvme"):
                pci_slot_name = dev.properties["PCI_SLOT_NAME"]
                vendor = dev.properties.get("ID_VENDOR_FROM_DATABASE", "")
                model = dev.properties.get("ID_MODEL_FROM_DATABASE", "")
                message = "{vendor} {model}".format(vendor=vendor, model=model)
                self.kernel_log.seek()
                pattern = "%s.*%s" % (pci_slot_name, headers.NvmeSimpleSuspend)
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
                message = "❌ NVME {disk} is not configured for s2idle in BIOS".format(
                    disk=invalid_nvme[disk]
                )
                self.log(message, colors.FAIL)
                num = len(invalid_nvme) + len(valid_nvme)
                self.failures += [AcpiNvmeStorageD3Enable(invalid_nvme[disk], num)]
        if valid_nvme:
            for disk in valid_nvme:
                message = "✅ NVME {disk} is configured for s2idle in BIOS".format(
                    disk=valid_nvme[disk]
                )
                self.log(message, colors.OK)
        if has_sata:
            if valid_sata:
                message = "✅ SATA supports DevSlp feature"
            else:
                invalid_nvme = True
                message = "❌ SATA does not support DevSlp feature"
                self.log(message, colors.FAIL)
                self.failures += [DevSlpDiskIssue()]

            if valid_ahci:
                message = "✅ AHCI is configured for DevSlp in BIOS"
            else:
                message = "❌ AHCI is not configured for DevSlp in BIOS"
                self.log(message, colors.FAIL)
                self.failures += [DevSlpHostIssue()]

        return (
            (len(invalid_nvme) == 0)
            and (valid_sata or not has_sata)
            and (valid_ahci or not has_sata)
        )

    def check_amd_hsmp(self):
        if self.offline:
            for line in self.offline:
                if re.search("amd_hsmp.*HSMP is not supported", line):
                    self.log(
                        "❌ HSMP driver `amd_hsmp` driver may conflict with amd_pmc",
                        colors.FAIL,
                    )
                    break
        else:
            if not self.kernel_log:
                message = "🚦 Unable to test for amd_hsmp bug from kernel log"
                self.log(message, colors.WARNING)
                return True
            self.kernel_log.seek()
            if self.kernel_log.match_pattern("amd_hsmp.*HSMP is not supported"):
                self.log(
                    "❌ HSMP driver `amd_hsmp` driver may conflict with amd_pmc",
                    colors.FAIL,
                )
                self.failures += [AmdHsmpBug()]
                return False

            cmdline = read_file(os.path.join("/proc", "cmdline"))
            blocked = "initcall_blacklist=hsmp_plt_init" in cmdline

            p = os.path.join("/", "sys", "module", "amd_hsmp")
            if os.path.exists(p) and not blacklisted:
                self.log("❌ `amd_hsmp` driver may conflict with amd_pmc", colors.FAIL)
                self.failures += [AmdHsmpBug()]
                return False

            self.log(
                "✅ HSMP driver `amd_hsmp` not detected (blocked: {blocked})".format(
                    blocked=blocked
                ),
                colors.OK,
            )
        return True

    def check_amd_pmc(self):
        for device in self.pyudev.list_devices(subsystem="platform", DRIVER="amd_pmc"):
            message = "✅ PMC driver `amd_pmc` loaded"
            p = os.path.join(device.sys_path, "smu_program")
            v = os.path.join(device.sys_path, "smu_fw_version")
            if os.path.exists(v):
                try:
                    self.smu_version = read_file(v)
                    self.smu_program = read_file(p)
                except TimeoutError:
                    self.log(
                        "❌ failed to communicate using `amd_pmc` driver", colors.FAIL
                    )
                    return False
                message += " (Program {program} Firmware {version})".format(
                    program=self.smu_program, version=self.smu_version
                )
            self.log(message, colors.OK)
            return True
        self.failures += [MissingAmdPmc()]
        self.log("❌ PMC driver `amd_pmc` not loaded", colors.FAIL)
        return False

    def check_usb4(self):
        has_usb4 = False
        for device in self.pyudev.list_devices(subsystem="pci", PCI_CLASS="C0340"):
            has_usb4 = True
        if not has_usb4:
            return True
        for device in self.pyudev.list_devices(subsystem="pci", DRIVER="thunderbolt"):
            self.log("✅ USB4 driver `thunderbolt` loaded", colors.OK)
            return True
        self.log("❌ USB4 driver `thunderbolt` missing", colors.FAIL)
        self.failures += [MissingThunderbolt()]
        return False

    def check_pinctrl_amd(self):
        for device in self.pyudev.list_devices(subsystem="platform", DRIVER="amd_gpio"):
            self.log("✅ GPIO driver `pinctrl_amd` available", colors.OK)
            p = os.path.join("/", "sys", "kernel", "debug", "gpio")
            capture_file_to_debug(p)
            if not check_dynamic_debug(
                "drivers/pinctrl/pinctrl-amd.*GPIO %d is active"
            ):
                self.log(
                    "🚦 GPIO dynamic debugging information unavailable", colors.WARNING
                )
            return True
        self.log("❌ GPIO driver `pinctrl_amd` not loaded", colors.FAIL)
        return False

    def check_amdgpu(self):
        for device in self.pyudev.list_devices(subsystem="pci", DRIVER="amdgpu"):
            self.log("✅ GPU driver `amdgpu` available", colors.OK)
            return True
        self.log("❌ GPU driver `amdgpu` not loaded", colors.FAIL)
        self.failures += [MissingAmdgpu()]
        return False

    def _process_ath11k_line(self, line) -> bool:
        if re.search("ath11k_pci.*fw_version", line):
            logging.debug("WCN6855 version string: %s", line)
            objects = line.split()
            for i in range(0, len(objects)):
                if objects[i] == "fw_version":
                    return int(objects[i + 1], 16)
        return False

    def check_wcn6855_bug(self):
        if not self.kernel_log:
            message = "🚦 Unable to test for wcn6855 bug from kernel log"
            self.log(message, colors.WARNING)
            return True
        wcn6855 = False
        self.kernel_log.seek()
        if self.kernel_log.match_pattern("ath11k_pci.*wcn6855"):
            match = self.kernel_log.match_pattern("ath11k_pci.*fw_version")
            if match:
                logging.debug("WCN6855 version string: %s", match)
                objects = match.split()
                for i in range(0, len(objects)):
                    if objects[i] == "fw_version":
                        wcn6855 = int(objects[i + 1], 16)

        if wcn6855:
            if wcn6855 >= 0x110B196E:
                self.log(
                    "✅ WCN6855 WLAN (fw version {version})".format(
                        version=hex(wcn6855)
                    ),
                    colors.OK,
                )
            else:
                self.log(
                    "❌ WCN6855 WLAN may cause spurious wakeups (fw version {version})".format(
                        version=hex(wcn6855)
                    ),
                    colors.FAIL,
                )
                self.failures += [WCN6855Bug()]

        return True

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
                    self.log(
                        "○ %s increased from %d to %d" % (fname, self.gpes[fname], val),
                        colors.OK,
                    )
                self.gpes[fname] = val

    def check_wakeup_irq(self):
        p = os.path.join("/", "sys", "power", "pm_wakeup_irq")
        try:
            n = read_file(p)
            p = os.path.join("/", "sys", "kernel", "irq", n)
            chip_name = read_file(os.path.join(p, "chip_name"))
            name = read_file(os.path.join(p, "name"))
            hw = read_file(os.path.join(p, "hwirq"))
            actions = read_file(os.path.join(p, "actions"))
            message = "○ {header} {number} ({chip_name} {hw}-{name} {actions})".format(
                header=headers.WokeFromIrq,
                number=n,
                chip_name=chip_name,
                hw=hw,
                name=name,
                actions=actions,
            )
            self.log(message, colors.OK)
        except OSError:
            pass
        return True

    def check_hw_sleep(self):
        result = False
        if self.hw_sleep_duration:
            result = True
        if self.offline:
            for line in self.offline:
                # re-entrant; don't re-run
                if "✅ In a hardware sleep state" in line or "❌ Did not reach" in line:
                    return
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
                    self.log(
                        "🚦 Unable to gather hardware sleep data with lockdown engaged",
                        colors.WARNING,
                    )
                else:
                    self.log("🚦 Failed to read hardware sleep data", colors.WARNING)
                return False
            except FileNotFoundError:
                self.log("○ HW sleep statistics file missing", colors.FAIL)
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
                symbol = "✅"
            self.log(
                "{symbol} In a hardware sleep state for {time} {percent_msg}".format(
                    symbol=symbol,
                    time=timedelta(seconds=self.hw_sleep_duration),
                    percent_msg="" if not percent else "({:.2%})".format(percent),
                ),
                colors.OK,
            )
        else:
            self.log("❌ Did not reach hardware sleep state", colors.FAIL)
        return result

    def check_permissions(self):
        p = os.path.join("/", "sys", "power", "state")
        try:
            with open(p, "w") as w:
                pass
        except PermissionError:
            self.log("👀 %s" % headers.RootError, colors.FAIL)
            return False
        return True

    def map_acpi_pci(self):
        for dev in self.pyudev.list_devices(subsystem="pci"):
            p = os.path.join(dev.sys_path, "firmware_node", "path")
            if os.path.exists(p):
                acpi = read_file(p)
                pci_id = dev.properties["PCI_ID"]
                pci_slot_name = dev.properties["PCI_SLOT_NAME"]
                database_vendor = dev.properties.get("ID_VENDOR_FROM_DATABASE", "")
                database_class = dev.properties.get("ID_PCI_CLASS_FROM_DATABASE", "")
                logging.debug(
                    "{pci_slot_name} : {cls} {vendor} [{id}] : {acpi}".format(
                        pci_slot_name=pci_slot_name,
                        vendor=database_vendor,
                        cls=database_class,
                        id=pci_id,
                        acpi=acpi,
                    )
                )
        return True

    def capture_acpi(self):
        if not self.iasl:
            self.log(headers.MissingIasl, colors.WARNING)
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
                    capture_file_to_debug("%s.dsl" % prefix)
                except subprocess.CalledProcessError as e:
                    self.log("Failed to capture ACPI table: %s" % e.output, colors.FAIL)
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

        path = os.path.join(
            "/", "sys", "kernel", "debug", "dri", "0", "amdgpu_firmware_info"
        )
        capture_file_to_debug(path)
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
                    logging.debug("%s is not configured" % (f))
                else:
                    logging.debug("%s is configured to %s" % (f, d))
        if not self.kernel_log:
            message = "🚦 Unable to validate disabled pins from kernel log"
            self.log(message, colors.WARNING)
            return True
        self.kernel_log.seek()
        result = self.kernel_log.match_pattern("Ignoring.* on pin")
        if result:
            self.log("○ %s" % result, colors.OK)
        return True

    def capture_full_dmesg(self):
        if not self.kernel_log:
            message = "🚦 Unable to analyze kernel log"
            self.log(message, colors.WARNING)
            return
        self.kernel_log.capture_full_dmesg()

    def check_logger(self):
        if isinstance(self.kernel_log, SystemdLogger):
            self.log("✅ Logs are provided via systemd", colors.OK)
        if isinstance(self.kernel_log, DmesgLogger):
            self.log(
                "🚦Logs are provided via dmesg, timestamps may not be accurate over multiple cycles",
                colors.WARNING,
            )
            header = self.kernel_log.capture_header()
            if not header.startswith("Linux version"):
                self.log(
                    "❌ Kernel ringbuffer has wrapped, unable to accurately validate pre-requisites",
                    colors.FAIL,
                )
                self.failures += [KernelRingBufferWrapped()]
                return False
        return True

    def prerequisites(self):
        self.log(headers.Info, colors.HEADER)
        info = [
            self.capture_system_vendor,
            self.capture_kernel_version,
            self.check_battery,
        ]
        for i in info:
            i()

        self.log(headers.Prerequisites, colors.HEADER)
        checks = [
            self.check_logger,
            self.check_cpu_vendor,
            self.check_lps0,
            self.check_fadt,
            self.capture_disabled_pins,
            self.check_amd_hsmp,
            self.check_amd_pmc,
            self.check_usb4,
            self.cpu_offers_hpet_wa,
            self.check_amdgpu,
            self.check_sleep_mode,
            self.check_storage,
            self.check_pinctrl_amd,
            self.check_wcn6855_bug,
            self.check_lockdown,
            self.check_permissions,
            self.capture_linux_firmware,
            self.map_acpi_pci,
            self.capture_acpi,
        ]
        result = True
        for check in checks:
            if not check():
                result = False
        if not result:
            self.log(headers.BrokenPrerequisites, colors.UNDERLINE)
            self.capture_full_dmesg()
        return result

    def check_lockdown(self):
        fn = os.path.join("/", "sys", "kernel", "security", "lockdown")
        lockdown = read_file(fn)
        logging.debug("Lockdown: %s" % lockdown)
        if lockdown.split()[0] != "[none]":
            self.log(
                "🚦 Kernel lockdown is engaged, this script will have limited debugging",
                colors.WARNING,
            )
            self.failures += [KernelLockdown()]
            self.lockdown = True
        return True

    def toggle_debugging(self, enable):
        fn = os.path.join("/", "sys", "power", "pm_debug_messages")
        setting = "1" if enable else "0"
        with open(fn, "w") as w:
            w.write(setting)
        try:
            fn = os.path.join("/", "sys", "kernel", "debug", "dynamic_debug", "control")
            setting = "+" if enable else "-"
            with open(fn, "w") as w:
                w.write("file drivers/acpi/x86/s2idle.c %sp" % setting)
            with open(fn, "w") as w:
                w.write("file drivers/pinctrl/pinctrl-amd.c %sp" % setting)
            with open(fn, "w") as w:
                w.write("file drivers/platform/x86/amd/pmc.c %sp" % setting)
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
            self.log(
                "🚦 Timer based wakeup doesn't work properly for your ASIC/firmware, please manually wake the system",
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
        if self.offline:
            for line in self.offline:
                self._analyze_kernel_log_line(line)
        else:
            self.kernel_log.seek(self.last_suspend)
            self.kernel_log.process_callback(self._analyze_kernel_log_line)

        if self.offline_report:
            return True

        if self.suspend_count:
            self.log(
                "○ Suspend count: {count}".format(count=self.suspend_count),
                colors.OK,
            )

        if self.cycle_count:
            self.log(
                "○ Hardware sleep cycle count: {count}".format(count=self.cycle_count),
                colors.OK,
            )
        if self.active_gpios:
            self.log("○ GPIOs active: %s" % self.active_gpios, colors.OK)
        if self.wakeup_irqs:
            self.log("○ Wakeups triggered from IRQs: %s" % self.wakeup_irqs, colors.OK)
            if 1 in self.wakeup_irqs and self.cpu_needs_irq1_wa():
                if self.irq1_workaround:
                    self.log("○ Kernel workaround for IRQ1 issue utilized")
                else:
                    self.log("🚦 IRQ1 found during wakeup", colors.WARNING)
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
                    if bit_changed & (1 << bit):
                        self.log(
                            "○ Idle mask bit %d (0x%x) changed during suspend"
                            % (bit, (1 << bit)),
                            colors.OK,
                        )
        if self.upep:
            if self.upep_microsoft:
                self.log("○ Used Microsoft uPEP GUID in LPS0 _DSM", colors.OK)
            else:
                self.log("○ Used AMD uPEP GUID in LPS0 _DSM", colors.OK)
        elif not self.lockdown:
            self.log("❌ LPS0 _DSM not executed", colors.FAIL)
            self.failures += [uPepMissing()]
        if self.acpi_errors:
            self.log("❌ ACPI BIOS errors found", colors.FAIL)
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
            self.log(
                "✅ Userspace suspended for {delta}".format(
                    delta=self.userspace_duration
                ),
                colors.OK,
            )
        else:
            self.log(
                "❌ Userspace suspended for {delta} (< minimum expected {expected})".format(
                    delta=self.userspace_duration, expected=min_suspend_duration
                ),
                colors.FAIL,
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
            self.log(
                "✅ Kernel suspended for total of {time} ({percent:.2%})".format(
                    time=timedelta(seconds=self.kernel_duration),
                    percent=percent,
                ),
                colors.OK,
            )

    def analyze_results(self):
        self.log(headers.LastCycleResults, colors.HEADER)
        result = True
        checks = [
            self.analyze_kernel_log,
            self.check_wakeup_irq,
            self.capture_gpes,
            self.check_battery,
            self.analyze_duration,
            self.check_hw_sleep,
        ]
        for check in checks:
            check()

    def run_countdown(self, t):
        msg = ""
        while t:
            msg = "Suspending system in {time}".format(time=timedelta(seconds=t))
            print(msg, end="\r", flush=True)
            time.sleep(1)
            t -= 1
        print(" " * len(msg), end="\r")

    def test_suspend(self, duration, count, wait):
        if not count:
            return True

        if count > 1:
            length = timedelta(seconds=(duration + wait) * count)
            self.log(
                "Running {count} cycles (Test finish expected @ {time})".format(
                    count=count, time=datetime.now() + length
                ),
                colors.HEADER,
            )

        self.requested_duration = duration
        logging.debug(
            "{msg} {time}".format(
                msg=headers.SuspendDuration,
                time=timedelta(seconds=self.requested_duration),
            ),
        )
        wakealarm = None
        for device in self.pyudev.list_devices(subsystem="rtc"):
            wakealarm = os.path.join(device.sys_path, "wakealarm")
        self.toggle_debugging(True)
        self.capture_gpes()

        for i in range(1, count + 1):
            self.run_countdown(wait)
            self.last_suspend = datetime.now()
            self.kernel_duration = 0
            self.hw_sleep_duration = 0
            if count > 1:
                header = "{header} {count}: ".format(header=headers.CycleCount, count=i)
            else:
                header = ""
            self.log(
                "{header}Started at {start} (cycle finish expected @ {finish})".format(
                    header=header,
                    start=self.last_suspend,
                    finish=datetime.now()
                    + timedelta(seconds=self.requested_duration + wait),
                ),
                colors.HEADER,
            )
            with open(wakealarm, "w") as w:
                w.write("0")
            with open(wakealarm, "w") as w:
                w.write("+%s\n" % self.requested_duration)
            p = os.path.join("/", "sys", "power", "state")
            with open(p, "w") as w:
                w.write("mem")
            self.analyze_results()
        self.toggle_debugging(False)
        return True

    def get_failure_report(self):
        if len(self.failures) == 0:
            return True
        print_color(headers.FailureReport, colors.HEADER)
        for item in self.failures:
            item.get_failure()

    def replay_checks(self):
        for line in self.offline:
            # don't run on regular dmesg
            if headers.Prerequisites in line or headers.Info in line:
                self.offline_report = True
            if not self.offline_report:
                return
            # replay s0i3 reports
            if "INFO:" in line:
                line = line.split("INFO:\t")[-1].strip()
                if any(mk in line for mk in ["✅", "🔋", "🐧", "💻", "○"]):
                    self.log(line, colors.OK)
                elif (
                    headers.Prerequisites in line
                    or headers.Info in line
                    or headers.CycleCount in line
                    or headers.LastCycleResults in line
                ):
                    self.log(line, colors.HEADER)
                if re.search(".*(family.* model.*)", line):
                    nums = re.findall(r"\d+", line)
                    self.cpu_model = int(nums[-1], 16)
                    self.cpu_family = int(nums[-2], 16)
            elif "ERROR:" in line:
                line = line.split("ERROR:\t")[-1].strip()
                if any(mk in line for mk in ["👀", "❌"]):
                    self.log(line, colors.FAIL)
            elif "WARNING:" in line:
                line = line.split("WARNING:\t")[-1].strip()
                self.log(line, colors.WARNING)
            elif "DEBUG:" in line:
                line = line.split("DEBUG:\t")[-1].rstrip()
                self.log("🦟 %s" % line, colors.DEBUG)

    def check_offline(self, input):
        with open(input, "r") as r:
            self.offline = r.readlines()
        checks = [
            self.replay_checks,
            self.check_storage,
            self.check_fadt,
            self.analyze_kernel_log,
            self.check_hw_sleep,
            self.analyze_masks,
        ]
        for check in checks:
            check()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Test for common s2idle problems on systems with AMD processors.",
        epilog="Arguments are optional, and if they are not provided will prompted.\n"
        "To use non-interactively, please populate all optional arguments.",
    )
    parser.add_argument("--offline", action="store_true", help="Analyze shared logs")
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
    return parser.parse_args()


def configure_log(log):
    if not log:
        fname = "{prefix}-{date}.{suffix}".format(
            prefix=defaults.log_prefix, suffix=defaults.log_suffix, date=date.today()
        )
        log = input(
            "{question} (default {fname})? ".format(
                question=headers.LogDescription, fname=fname
            )
        )
        if not log:
            log = fname
    return log


def configure_suspend(duration, wait, count):
    if not duration:
        duration = input(
            "{question} (default {val})? ".format(
                question=headers.DurationDescription, val=defaults.duration
            )
        )
        if not duration:
            duration = defaults.duration
    if not wait:
        wait = input(
            "{question} (default {val})? ".format(
                question=headers.WaitDescription, val=defaults.wait
            )
        )
        if not wait:
            wait = defaults.wait
    if not count:
        count = input(
            "{question} (default {val})? ".format(
                question=headers.CountDescription, val=defaults.count
            )
        )
        if not count:
            count = defaults.count
    return [int(duration), int(wait), int(count)]


if __name__ == "__main__":
    args = parse_args()
    log = configure_log(args.log)
    if args.offline:
        if not os.path.exists(log):
            sys.exit("{log} is missing".format(log=log))
        app = S0i3Validator("/dev/null", False, None)
        app.check_offline(log)
        app.get_failure_report()
    else:
        app = S0i3Validator(log, args.acpidump, args.kernel_log_provider)
        test = app.prerequisites()
        if test or args.force:
            duration, wait, count = configure_suspend(
                duration=args.duration, wait=args.wait, count=args.count
            )
            app.test_suspend(duration=duration, wait=wait, count=count)
        app.get_failure_report()
