"""chameleon_cli_unit — command definitions.

The shared foundation (imports, base classes, CLITree groups) now lives in
cli_core; this module defines the command classes and registers them on the
shared `root` tree. `from chameleon_cli_unit import root` still works.
Step 1 of the split: foundation extracted, commands still here."""

from cli_core import *  # noqa: F401,F403 - foundation: bases, groups, helpers, imports
import cli_core
from fdxb_country import ISO3166_NUMERIC
from canary_cmd import canary_cmd_name
# re-export everything cli_core defined so command bodies resolve names
globals().update({k: v for k, v in vars(cli_core).items() if not k.startswith('__')})

# --- split-out command modules (register on `root` by import side-effect) ---
import cli_hf_des  # noqa: F401,E402  (hf des ...)
import cli_lf      # noqa: F401,E402  (lf ...)
import cli_hf_mf   # noqa: F401,E402  (hf mf ...)
import cli_hf_mfu  # noqa: F401,E402  (hf mfu ...)
import cli_hf_st25ta  # noqa: F401,E402  (hf st25ta ...)
import cli_hf_mfplus  # noqa: F401,E402  (hf mfplus ...)
import cli_hw_log  # noqa: F401,E402  (hw log ...)

@root.command("clear")
class RootClear(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Clear screen"
        return parser

    def on_exec(self, args: argparse.Namespace):
        os.system("clear" if os.name == "posix" else "cls")


@root.command("rem")
class RootRem(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Timestamped comment"
        parser.add_argument("comment", nargs="*", help="Your comment")
        return parser

    def on_exec(self, args: argparse.Namespace):
        # precision: second
        # iso_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        # precision: nanosecond (note that the comment will take some time too, ~75ns, check your system)
        iso_timestamp = datetime.utcnow().isoformat() + "Z"
        comment = " ".join(args.comment)
        print(f"{iso_timestamp} remark: {comment}")


@root.command("exit")
class RootExit(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Exit client"
        return parser

    def on_exec(self, args: argparse.Namespace):
        print("Bye, thank you.  ^.^ ")
        self.device_com.close()
        sys.exit(996)


@root.command("dump_help")
class RootDumpHelp(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Dump available commands"
        parser.add_argument(
            "-d",
            "--show-desc",
            action="store_true",
            help="Dump full command description",
        )
        parser.add_argument(
            "-g",
            "--show-groups",
            action="store_true",
            help="Dump command groups as well",
        )
        return parser

    @staticmethod
    def dump_help(cmd_node, depth=0, dump_cmd_groups=False, dump_description=False):
        visual_col1_width = 28
        col1_width = visual_col1_width + len(f"{CG}{C0}")
        if cmd_node.cls:
            p = cmd_node.cls().args_parser()
            assert p is not None
            if dump_description:
                p.print_help()
            else:
                cmd_title = color_string((CG, cmd_node.fullname))
                print(f"{cmd_title}".ljust(col1_width), end="")
                p.prog = " " * (visual_col1_width - len("usage: ") - 1)
                usage = p.format_usage().removeprefix("usage: ").strip()
                print(color_string((CY, usage)))
        else:
            if dump_cmd_groups and not cmd_node.root:
                if dump_description:
                    print("=" * 80)
                    print(color_string((CR, cmd_node.fullname)))
                    print(color_string((CC, cmd_node.help_text)))
                else:
                    print(color_string((CB, f"== {cmd_node.fullname} ==")))
            for child in cmd_node.children:
                RootDumpHelp.dump_help(
                    child, depth + 1, dump_cmd_groups, dump_description
                )

    def on_exec(self, args: argparse.Namespace):
        self.dump_help(
            root, dump_cmd_groups=args.show_groups, dump_description=args.show_desc
        )


@hw.command("connect")
class HWConnect(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Connect to chameleon by serial port, TCP, or BLE. "
                              "Examples: -p /dev/ttyACM0 | -p tcp:127.0.0.1:4321 | "
                              "-p ble (scan) | -p ble:AA:BB:CC:DD:EE:FF (needs 'bleak')")
        parser.add_argument("-p", "--port", type=str, required=False)
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            if args.port is None:  # Chameleon auto-detect if no port is supplied
                platform_name = uname().release
                if "Microsoft" in platform_name:
                    path = os.environ["PATH"].split(os.pathsep)
                    path.append("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/")
                    powershell_path = None
                    for prefix in path:
                        fn = os.path.join(prefix, "powershell.exe")
                        if not os.path.isdir(fn) and os.access(fn, os.X_OK):
                            powershell_path = fn
                            break
                    if powershell_path:
                        process = subprocess.Popen(
                            [
                                powershell_path,
                                "Get-PnPDevice -Class Ports -PresentOnly |"
                                " where {$_.DeviceID -like '*VID_6868&PID_8686*'} |"
                                " Select-Object -First 1 FriendlyName |"
                                " % FriendlyName |"
                                " select-string COM\\d+ |"
                                "% { $_.matches.value }",
                            ],
                            stdout=subprocess.PIPE,
                        )
                        res = process.communicate()[0]
                        _comport = res.decode("utf-8").strip()
                        if _comport:
                            args.port = _comport.replace("COM", "/dev/ttyS")
                else:
                    # loop through all ports and find chameleon
                    for port in serial.tools.list_ports.comports():
                        if port.vid == 0x6868:
                            args.port = port.device
                            break
                if args.port is None:  # If no chameleon was found, exit
                    print(
                        "Chameleon not found, please connect the device or try connecting manually with the -p flag."
                    )
                    return
            self.device_com.open(args.port)
            self.device_com.commands = self.cmd.get_device_capabilities()
            major, minor = self.cmd.get_app_version()
            model = ["Ultra", "Lite"][self.cmd.get_device_model()]
            print(f" {{ Chameleon {model} connected: v{major}.{minor} }}")

        except Exception as e:
            print(color_string((CR, f"Chameleon Connect fail: {str(e)}")))
            self.device_com.close()


@hw.command("disconnect")
class HWDisconnect(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Disconnect chameleon"
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.device_com.close()


@hw.command("mode")
class HWMode(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get or change device mode: tag reader or tag emulator"
        mode_group = parser.add_mutually_exclusive_group()
        mode_group.add_argument(
            "-r", "--reader", action="store_true", help="Set reader mode"
        )
        mode_group.add_argument(
            "-e", "--emulator", action="store_true", help="Set emulator mode"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.reader:
            self.cmd.set_device_reader_mode(True)
            print("Switch to {  Tag Reader  } mode successfully.")
        elif args.emulator:
            self.cmd.set_device_reader_mode(False)
            print("Switch to { Tag Emulator } mode successfully.")
        else:
            print(
                f"- Device Mode ( Tag {'Reader' if self.cmd.is_device_reader_mode() else 'Emulator'} )"
            )


@hw.command("chipid")
class HWChipId(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get device chipset ID"
        return parser

    def on_exec(self, args: argparse.Namespace):
        print(" - Device chip ID: " + self.cmd.get_device_chip_id())


@hw.command("address")
class HWAddress(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get device address (used with Bluetooth)"
        return parser

    def on_exec(self, args: argparse.Namespace):
        print(" - Device address: " + self.cmd.get_device_address())


@hw.command("version")
class HWVersion(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get current device firmware version"
        return parser

    def on_exec(self, args: argparse.Namespace):
        fw_version_tuple = self.cmd.get_app_version()
        fw_version = f"v{fw_version_tuple[0]}.{fw_version_tuple[1]}"
        git_version = self.cmd.get_git_version()
        model = ["Ultra", "Lite"][self.cmd.get_device_model()]
        print(f" - Phreakbyte edition ({model}), Version: {fw_version} ({git_version})")


@hw.command("status")
class HWStatus(DeviceRequiredUnit):
    # How much remaining battery is considered low?
    BATTERY_LOW_LEVEL = 30

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Show a one-shot summary of connection, firmware and hardware status"
        return parser

    def get_link_speed(self) -> Union[str, None]:
        transport = getattr(self.device_com, "transport_type", None)
        link = getattr(self.device_com, "transport", None)
        if transport is None or link is None:
            return None
        if transport is chameleon_com.TransportType.SERIAL:
            baudrate = getattr(link, "baudrate", None)
            return f"{baudrate:,} baud" if baudrate else None
        if transport is chameleon_com.TransportType.BLE:
            payload = getattr(link, "payload_size", None)
            return f"{payload} bytes/packet (BLE ATT payload)" if payload else None
        if transport is chameleon_com.TransportType.SOCKET:
            return "TCP (network, variable)"
        return None

    def on_exec(self, args: argparse.Namespace):
        transport = getattr(self.device_com, "transport_type", None)
        transport_name = transport.name if transport is not None else "UNKNOWN"
        model = ["Ultra", "Lite"][self.cmd.get_device_model()]

        t0 = time.perf_counter()
        fw_version_tuple = self.cmd.get_app_version()
        latency_ms = (time.perf_counter() - t0) * 1000
        fw_version = f"v{fw_version_tuple[0]}.{fw_version_tuple[1]}"
        git_version = self.cmd.get_git_version()

        print(" - Device status")
        print(f"   connection  -> {transport_name}")
        link_speed = self.get_link_speed()
        if link_speed:
            print(f"   link speed  -> {link_speed}")
        print(f"   latency     -> {latency_ms:.1f} ms (round-trip)")
        print(f"   model       -> Phreakbyte edition ({model})")
        print(f"   firmware    -> {fw_version} ({git_version})")

        try:
            bl_version = self.cmd.get_bootloader_version()
            print(f"   bootloader  -> {bl_version}")
        except chameleon_com.CMDInvalidException:
            print("   bootloader  -> not supported by current firmware")

        try:
            app_version = self.cmd.get_dfu_app_version()
            print(f"   application -> {app_version}")
        except chameleon_com.CMDInvalidException:
            print("   application -> not supported by current firmware")

        print(f"   chip ID     -> {self.cmd.get_device_chip_id()}")
        print(f"   address     -> {self.cmd.get_device_address()}")

        try:
            ble_name = self.cmd.get_ble_name()
            ble_name_display = ble_name if ble_name else color_string((CY, "(default)"))
            print(f"   ble name    -> {ble_name_display}")
        except chameleon_com.CMDInvalidException:
            print("   ble name    -> not supported by current firmware")

        print(f"   mode        -> Tag {'Reader' if self.cmd.is_device_reader_mode() else 'Emulator'}")

        try:
            active_slot = SlotNumber.from_fw(self.cmd.get_active_slot())
            print(f"   active slot -> {active_slot.value}")
        except Exception:
            pass

        try:
            voltage, percentage = self.cmd.get_battery_info()
            low = " " + color_string((CR, "[!] Low battery")) if percentage < self.BATTERY_LOW_LEVEL else ""
            print(f"   battery     -> {voltage} mV, {percentage}%{low}")
        except chameleon_com.CMDInvalidException:
            print("   battery     -> not supported by current firmware")

        try:
            mem = self.cmd.get_free_memory()
            free, total = mem['free'], mem['total']
            used = total - free
            pct = (used / total * 100.0) if total > 0 else 0.0
            print(f"   heap        -> {used:,}/{total:,} bytes used ({pct:.1f}%)")
        except chameleon_com.CMDInvalidException:
            print("   heap        -> not supported by current firmware")

@hf_14a.command("config")
class HF14AConfig(DeviceRequiredUnit):
    class Config(Enum):
        def __new__(cls, value, desc):
            obj = object.__new__(cls)
            obj._value_ = value
            obj.desc = desc
            return obj

        @classmethod
        def choices(cls):
            return [elem.name for elem in cls]

        @classmethod
        def format(cls, index):
            item = cls(index)
            color = CG if index == 0 else CR
            return f" - {cls.__name__.upper()} override: {color_string((color, item.name))} ( {item.desc} )"

        @classmethod
        def help(cls):
            return " / ".join([f"{elem.desc}" for elem in cls])

    class Bcc(Config):
        std = (0, "follow standard")
        fix = (1, "fix bad BCC")
        ignore = (2, "ignore bad BCC, always use card BCC")

    class Cl2(Config):
        std = (0, "follow standard")
        force = (1, "always do CL2")
        skip = (2, "always skip CL2")

    class Cl3(Config):
        std = (0, "follow standard")
        force = (1, "always do CL3")
        skip = (2, "always skip CL3")

    class Rats(Config):
        std = (0, "follow standard")
        force = (1, "always do RATS")
        skip = (2, "always skip RATS")

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Configure 14a settings (use with caution)"
        parser.add_argument(
            "--std",
            action="store_true",
            help="Reset default configuration (follow standard)",
        )
        parser.add_argument(
            "--bcc", type=str, choices=self.Bcc.choices(), help=self.Bcc.help()
        )
        parser.add_argument(
            "--cl2", type=str, choices=self.Cl2.choices(), help=self.Cl2.help()
        )
        parser.add_argument(
            "--cl3", type=str, choices=self.Cl3.choices(), help=self.Cl3.help()
        )
        parser.add_argument(
            "--rats", type=str, choices=self.Rats.choices(), help=self.Rats.help()
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        change_requested = False
        if args.std:
            config = {"bcc": 0, "cl2": 0, "cl3": 0, "rats": 0}
            change_requested = True
        else:
            config = self.cmd.hf14a_get_config()
        if args.bcc:
            config["bcc"] = self.Bcc[args.bcc].value
            change_requested = True
        if args.cl2:
            config["cl2"] = self.Cl2[args.cl2].value
            change_requested = True
        if args.cl3:
            config["cl3"] = self.Cl3[args.cl3].value
            change_requested = True
        if args.rats:
            config["rats"] = self.Rats[args.rats].value
            change_requested = True
        if change_requested:
            self.cmd.hf14a_set_config(config)
            config = self.cmd.hf14a_get_config()
        print("HF 14a config")
        print(self.Bcc.format(config["bcc"]))
        print(self.Cl2.format(config["cl2"]))
        print(self.Cl3.format(config["cl3"]))
        print(self.Rats.format(config["rats"]))

@hw.command("blver")
class HWBootloaderVersion(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get bootloader version"
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            version = self.cmd.get_bootloader_version()
            print(f" - Bootloader Version: {version}")
        except chameleon_com.CMDInvalidException:
            print(" - Bootloader version not supported by current firmware, please update")


@hw.command("freemem")
class HWFreeMemory(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get device heap memory usage"
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            mem = self.cmd.get_free_memory()
            free  = mem['free']
            total = mem['total']
            used  = total - free
            pct   = (used / total * 100.0) if total > 0 else 0.0
            print(f" - Heap free  : {free:,} bytes")
            print(f" - Heap used  : {used:,} bytes")
            print(f" - Heap total : {total:,} bytes  ({pct:.1f}% used)")
        except chameleon_com.CMDInvalidException:
            print(" - Free memory not supported by current firmware, please update")

@hf_14a.command("scan")
class HF14AScan(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan 14a tag, and print basic information"
        return parser

    def check_mf1_nt(self):
        # detect mf1 support
        prng_type = None
        magic_gen = None
        if self.cmd.mf1_detect_support():
            # detect prng
            print("- Mifare Classic technology")
            prng_type = self.cmd.mf1_detect_prng()
            print(f"  # Prng: {MifareClassicPrngType(prng_type)}")
            # read-only magic-card probe (gen1a/gen3/gen4); see cli_hf_mf for
            # why gen2/CUID isn't (reliably) probeable here
            magic_gen = cli_hf_mf.identify_magic_gen(self.cmd)
            if magic_gen:
                print(f"  # Magic: {CY}{magic_gen}{C0} backdoor detected")
        self._recommend(prng_type=prng_type, magic_gen=magic_gen)

    def sak_info(self, data_tag):
        # detect the technology in use based on SAK
        int_sak = data_tag["sak"][0]
        if int_sak in type_id_SAK_dict:
            print(f"- Guessed type(s) from SAK: {type_id_SAK_dict[int_sak]}")
        self._sak = int_sak
        self._has_ats = len(data_tag.get("ats", b"")) > 0

    def _recommend(self, prng_type=None, magic_gen=None):
        """Print a single 'what would I run next' suggestion. Only fires for
        cases this scan can actually tell apart; stays silent rather than
        guess when the SAK/ATS are ambiguous (e.g. SAK 0x20 covers Plus EV,
        DESFire and NTAG 4xx alike)."""
        if magic_gen == "gen1a":
            print(f"  # {CY}Recommended:{C0} hf mf cview (read via backdoor, no keys needed), "
                  f"or hf mf cload -f <dump.bin> (write)")
            return
        if magic_gen == "gen3":
            print(f"  # {CY}Recommended:{C0} hf mf gen3uid / gen3blk")
            return
        if magic_gen == "gen4":
            print(f"  # {CY}Recommended:{C0} hf mf ggetblk / gconfig "
                  f"(default pwd 00000000 unless set otherwise)")
            return
        if prng_type is not None:
            print(f"  # {CY}Recommended:{C0} hf mf autopwn")
            return
        sak = getattr(self, "_sak", None)
        has_ats = getattr(self, "_has_ats", False)
        if sak == 0x00 and not has_ats:
            print(f"  # {CY}Recommended:{C0} hf mfu dump")
        elif has_ats and sak in (0x20, None):
            print(f"  # {CY}Recommended:{C0} hf des chk --pattern1b")

    def scan(self, deep=False):
        resp = self.cmd.hf14a_scan()
        if resp is not None:
            for data_tag in resp:
                print(f"- UID  : {data_tag['uid'].hex().upper()}")
                print(
                    f"- ATQA : {data_tag['atqa'].hex().upper()} "
                    f"(0x{int.from_bytes(data_tag['atqa'], byteorder='little'):04x})"
                )
                print(f"- SAK  : {data_tag['sak'].hex().upper()}")
                if len(data_tag["ats"]) > 0:
                    print(f"- ATS  : {data_tag['ats'].hex().upper()}")
                if deep:
                    self.sak_info(data_tag)
                    # TODO: following checks cannot be done yet if multiple cards are present
                    if len(resp) == 1:
                        self.check_mf1_nt()
                        # TODO: check for ATS support on 14A3 tags
                    else:
                        print("Multiple tags detected, skipping deep tests...")
        else:
            print("ISO14443-A Tag no found")

    def on_exec(self, args: argparse.Namespace):
        self.scan()


@hf_14a.command("info")
class HF14AInfo(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Scan 14a tag, and print detail information"
        return parser

    def on_exec(self, args: argparse.Namespace):
        scan = HF14AScan()
        scan.device_com = self.device_com
        scan.scan(deep=True)


class CrackEffect:
    """
    A class to create a visual effect of cracking blocks of data.
    """

    def __init__(
        self, num_blocks: int = 4, block_size: int = 8, scramble_delay: float = 0.01
    ):
        """
        Initialize the CrackEffect class with the given parameters.

        Args:
            num_blocks (int): Number of blocks to display. Default is 4.
            block_size (int): Size of each block in characters. Default is 8.
            scramble_delay (float): Delay between each scramble update in seconds. Default is 0.01.
        """
        self.num_blocks = num_blocks
        self.block_size = block_size
        self.scramble_delay = scramble_delay
        self.message_queue = queue.Queue()
        self.revealed = [""] * num_blocks
        self.stop_event = threading.Event()
        self.cracked_blocks = set()
        self.display_lock = threading.Lock()
        self.output_enabled = True

    def generate_random_hex(self) -> str:
        """Generate a random hex string of block_size length."""
        import random

        hex_chars = "0123456789ABCDEF"
        return "".join(random.choice(hex_chars) for _ in range(self.block_size))

    def format_block(self, block: str, is_cracked: bool) -> str:
        """Format a block with appropriate color based on its state."""
        if is_cracked:
            return f"\033[1;34m{block}\033[0m"  # Bold blue
        return f"\033[96m{block}\033[0m"  # Bright cyan

    def draw_static_box(self):
        """Draw the initial static box."""
        if not self.output_enabled:
            return
        width = (self.block_size + 1) * self.num_blocks + 4
        print("")  # Add some padding above
        print("╔" + "═" * width + "╗")
        print("║" + " " * width + "║")
        print("║" + " " * width + "║")
        print("║" + " " * width + "║")
        print("╚" + "═" * width + "╝")
        # Move cursor to the middle line
        sys.stdout.write("\033[3A")  # Move up 3 lines to middle row
        sys.stdout.flush()

    def print_above(self, data):
        """Print the given data above the box and redraws the box."""
        if not self.output_enabled:
            print(data)
            return
        with self.display_lock:
            # Move cursor above the box and clean the line
            sys.stdout.write("\033[2A\033[1G\033[K" + data)
            self.draw_static_box()

    def display_current_state(self):
        """Display the current state of all blocks."""
        if not self.output_enabled:
            return
        with self.display_lock:
            formatted_blocks = [
                self.format_block(block, i in self.cracked_blocks)
                for i, block in enumerate(self.revealed)
            ]
            display_text = " ".join(formatted_blocks)

            # Update only the middle line
            sys.stdout.write(f"\r║  {display_text}   ║")
            sys.stdout.flush()

    def scramble_effect(self):
        """Run the main loop for the scrambling effect."""
        if not self.output_enabled:
            return
        while not self.stop_event.is_set():
            # Update all non-cracked blocks with random values
            for block in range(self.num_blocks):
                if block not in self.cracked_blocks:
                    self.revealed[block] = self.generate_random_hex()

            self.display_current_state()
            time.sleep(self.scramble_delay)

    def erase_key(self):
        """Erase random parts of the key."""
        if not self.output_enabled:
            return
        for block in range(self.num_blocks):
            if block not in self.cracked_blocks:
                self.revealed[block] = "." * self.block_size
        self.display_current_state()

    def process_message_queue(self):
        """Process incoming cracked blocks from the queue."""
        if not self.output_enabled:
            return
        while not self.stop_event.is_set():
            try:
                block_idx, cracked_text = self.message_queue.get(timeout=0.1)
                self.revealed[block_idx] = cracked_text
                self.cracked_blocks.add(block_idx)
                self.display_current_state()

                # Check if all blocks are cracked
                if len(self.cracked_blocks) == self.num_blocks:
                    self.stop_event.set()
                    print("\n" * 3)  # Add newlines after completion
                    break
            except queue.Empty:
                continue
            except Exception as e:
                print(f"\nError processing message: {e}")
                break

    def add_cracked_block(self, block_idx: int, text: str):
        """Add a cracked block to the message queue."""
        if not 0 <= block_idx < self.num_blocks:
            raise ValueError(f"Block index {block_idx} out of range")
        if len(text) != self.block_size:
            raise ValueError(f"Block text must be {self.block_size} characters")
        self.message_queue.put((block_idx, text))

    def start(self):
        """Start the cracking effect."""
        self.draw_static_box()

        # Create and start the worker threads
        scramble_thread = threading.Thread(target=self.scramble_effect)
        process_thread = threading.Thread(target=self.process_message_queue)

        scramble_thread.daemon = True
        process_thread.daemon = True

        scramble_thread.start()
        process_thread.start()

        # Wait for both threads to complete
        process_thread.join()
        self.stop_event.set()
        scramble_thread.join()


def _t55_hex4(s: str, name: str) -> bytes:
    """Parse exactly 4 hex bytes, or raise a clean ArgsParserError."""
    try:
        b = bytes.fromhex(s)
    except ValueError:
        raise ArgsParserError(f"{name} must be 8 hex digits (4 bytes)")
    if len(b) != 4:
        raise ArgsParserError(f"{name} must be 8 hex digits (4 bytes)")
    return b


def _t55_amplitude_halfbits(samples, rf_n):
    """Binarize a SAADC amplitude capture and recover the half-bit level stream
    with a phase-locked sampler. Half-cell = rf_n/2 samples (SAADC samples once
    per carrier cycle), known a priori. The half-bit level is a majority vote at
    the cell centre, and the clock re-anchors on the nearest real transition each
    cell, so run-length jitter and stretched/merged runs in the settling region
    don't slip Manchester phase (the RLE round(run/unit) approach did). Returns
    the half-bit list, or []."""
    n = len(samples)
    if n < 96:
        return []
    lo, hi = min(samples), max(samples)
    if hi - lo < 8:
        return []
    thr = (lo + hi) / 2.0
    b = [1 if s >= thr else 0 for s in samples]
    hb_len = max(2, rf_n // 2)
    edges = [i for i in range(1, n) if b[i] != b[i - 1]]
    if not edges:
        return []
    win = max(2, hb_len // 3)
    pos = edges[0]  # anchor phase on the first transition
    hb = []
    while pos + hb_len <= n:
        c = pos + hb_len // 2
        seg = b[max(0, c - win):c + win + 1]
        hb.append(1 if sum(seg) * 2 >= len(seg) else 0)
        nb = pos + hb_len
        cand = [e for e in edges if abs(e - nb) <= hb_len // 3]
        pos = min(cand, key=lambda e: abs(e - nb)) if cand else nb
    return hb


def _t55_manchester_decode(hb, off):
    """Manchester-decode a half-bit stream from a start phase, with phase-slip
    resync. Returns (bitstring, violations)."""
    bits, viol, i = [], 0, off
    while i + 1 < len(hb):
        a, d = hb[i], hb[i + 1]
        if a == 1 and d == 0:
            bits.append(1); i += 2
        elif a == 0 and d == 1:
            bits.append(0); i += 2
        else:
            viol += 1; i += 1  # slip one half-cell to resync
    return "".join(map(str, bits)), viol


def _t55_amplitude_bits(samples, rf_n):
    """Decode the amplitude capture to a bitstring (lower-violation phase)."""
    hb = _t55_amplitude_halfbits(samples, rf_n)
    if not hb:
        return ""
    s0, v0 = _t55_manchester_decode(hb, 0)
    s1, v1 = _t55_manchester_decode(hb, 1)
    return s0 if v0 <= v1 else s1


def _t55_find_word(samples, word_bytes, rf_n):
    """Search both half-bit phases and both Manchester polarities for a 32-bit
    word. Returns (polarity, bit_offset) or None."""
    hb = _t55_amplitude_halfbits(samples, rf_n)
    if not hb:
        return None
    target = "".join(f"{x:08b}" for x in word_bytes)
    for off in (0, 1):
        s, _ = _t55_manchester_decode(hb, off)
        if target in s:
            return ("normal", s.index(target))
        inv = "".join("1" if ch == "0" else "0" for ch in s)
        if target in inv:
            return ("inverted", inv.index(target))
    return None


def _t55_stream_block(bits):
    """A T55xx block is 32 bits and the tag streams it repeatedly, so a correct
    read is one 32-bit period — not the whole demodulated smear. Find the
    smallest repeating period in the bitstream and return (period_bits,
    period_bitstring). period_bits == 32 means a clean block; a proper divisor
    of 32 (e.g. 16) means the read-back collapsed to a shorter period (the known
    dense-word framing issue) and is NOT a trustworthy 32-bit value. Returns
    (None, None) if no stable period is found."""
    n = len(bits)
    if n < 16:
        return None, None
    # Skip a long constant settling lead-in (the field-on ramp demodulates as one
    # sustained level and otherwise dominates the period search).
    lead = 1
    while lead < n and bits[lead] == bits[0]:
        lead += 1
    if lead > 48:
        bits = bits[lead:]
        n = len(bits)
        if n < 16:
            return None, None
    for p in range(8, min(33, n // 2 + 1)):
        agree = sum(1 for i in range(n - p) if bits[i] == bits[i + p])
        if agree / (n - p) >= 0.92:
            return p, bits[:p]
    return None, None


# T5577 block-0 (configuration) decode, field layout per PM3 SetConfigWithBlock0Ex
# (RfidResearchGroup/proxmark3 client/src/cmdlft55xx.c). Verified against known
# configs 0x000880E0 (Manchester RF/32, maxblock 7) and 0x00148040 (em410x:
# Manchester RF/64, maxblock 2).
_T55_MOD = {0: "DIRECT (ASK/NRZ)", 1: "PSK1", 2: "PSK2", 3: "PSK3",
            4: "FSK1", 5: "FSK2", 6: "FSK1a", 7: "FSK2a",
            8: "Manchester", 16: "Biphase", 24: "Biphase-a (CDP)"}
_T55_BITRATE = [8, 16, 32, 40, 50, 64, 100, 128]  # 3-bit non-extended dbr index

# Detected config from `lf t55xx detect`, used as the default RF for `read`.
_T55_DETECTED = {"rf": None, "mod": "manchester"}


def _t55_parse_block0(b0):
    """Decode a T5577 block-0 config word into its fields."""
    extend = (b0 >> 17) & 0x01                 # X-mode / extended bit-rate
    if extend:
        dbr = (b0 >> 18) & 0x3F                 # extended rate table differs
        rf = None
    else:
        dbr = (b0 >> 18) & 0x07
        rf = _T55_BITRATE[dbr]
    modulation = (b0 >> 12) & 0x1F
    return {
        "block0": b0, "extend": bool(extend), "rf": rf, "dbr": dbr,
        "modulation": modulation,
        "mod_name": _T55_MOD.get(modulation, f"0x{modulation:02X} (unknown)"),
        "maxblock": (b0 >> 5) & 0x07,
        "pwd": bool((b0 >> 4) & 1),
        "st": bool((b0 >> 3) & 1),
        "inverted": bool((b0 >> 1) & 1),
    }


def _t55_decode_bits(cmd, block, rf, pwd, page1, modulation):
    """Return the raw demodulated bit STRING for a block before any 32-bit framing
    (modulation 0 = Manchester via SAADC amplitude host decode; 1 = biphase via the
    firmware diphase_feed demod), or "" on failure."""
    if modulation == 1:
        n, items = cmd.lf_t55xx_read(block, rf, pwd, page1, modulation=1)
        return "".join("1" if b else "0" for b in items) if items else ""
    n, samples = cmd.lf_t55xx_read(block, rf, pwd, page1, adc=True)
    if n == 0:
        return ""
    return _t55_amplitude_bits(samples, rf) or ""


def _t55_lock_config(bits, rf, want_mods):
    """Slide a 32-bit window over the stream and return (block0, fields, inverted)
    for the first window that REPEATS (== the next 32 bits) AND parses to a config
    whose modulation is in want_mods, bitrate == rf, not extended. The repeat
    requirement skips the settling lead-in, tolerates block rotation, and rejects
    streaming tags (FDX-B) that never present a repeating 32-bit config block.
    Mirrors PM3's stride-locked framing. Returns None if nothing matches."""
    if not bits:
        return None
    n = len(bits)
    for i in range(n - 64):
        for inv in (0, 1):
            seg = bits[i:i + 32]
            nxt = bits[i + 32:i + 64]
            if inv:
                seg = "".join("1" if c == "0" else "0" for c in seg)
                nxt = "".join("1" if c == "0" else "0" for c in nxt)
            if seg != nxt:
                continue
            f = _t55_parse_block0(int(seg, 2))
            if (f["modulation"] in want_mods and not f["extend"]
                    and f["rf"] == rf and f["maxblock"] >= 1):
                return int(seg, 2), f, inv
    return None


def _t55_detect_sources(cmd, rf, pwd, modcode):
    """Candidate demodulated bit strings for detecting block 0 at this rate. For
    Manchester, try the firmware EDGE decode first (block 0 is sparse, so the edge
    path is reliable and sidesteps the amplitude decoder's phase ambiguity on config
    words) plus the SAADC amplitude decode as a denser-config fallback. For biphase,
    the firmware diphase edge decode."""
    out = []
    if modcode == 0:
        n, items = cmd.lf_t55xx_read(0, rf, pwd, False, modulation=0)
        if items:
            out.append("".join("1" if b else "0" for b in items))
        n, samples = cmd.lf_t55xx_read(0, rf, pwd, False, adc=True)
        if n:
            b = _t55_amplitude_bits(samples, rf)
            if b:
                out.append(b)
    else:
        n, items = cmd.lf_t55xx_read(0, rf, pwd, False, modulation=1)
        if items:
            out.append("".join("1" if b else "0" for b in items))
    return out


def _t55_read_framed(cmd, block, rf, pwd, page1, modulation):
    """Read a block and frame it to its repeating unit -> (period, unit) or
    (None, None)."""
    bits = _t55_decode_bits(cmd, block, rf, pwd, page1, modulation)
    if not bits:
        return None, None
    return _t55_stream_block(bits)


def _t55_frame_block(bits):
    """Frame a demodulated stream to one 32-bit block: skip a long constant settling
    lead-in, then return (value, note) for the most common 32-bit window that repeats
    (== the next 32 bits) — any rotation of the true block, hence the caller's "may
    be rotated" note. Falls back to the shortest repeating period (flagging a
    collapse) when nothing repeats at 32; (None, None) if unusable."""
    n = len(bits)
    if n < 64:
        return None, None
    lead = 1
    while lead < n and bits[lead] == bits[0]:
        lead += 1
    if lead > 48:
        bits = bits[lead:]
        n = len(bits)
        if n < 64:
            return None, None
    reps = {}
    for i in range(n - 64):
        w = bits[i:i + 32]
        if w == bits[i + 32:i + 64]:
            reps[w] = reps.get(w, 0) + 1
    if reps:
        return int(max(reps, key=reps.get), 2), "32-bit block"
    period, unit = _t55_stream_block(bits)
    if period is None:
        return None, None
    return int((unit * (32 // period + 1))[:32], 2), \
        f"{period}-bit period — repetitive value or dense-word collapse"


def _t55_expect_match(bits, want):
    """True if the 32-bit `want` appears as a repeating window in any rotation or
    inverted polarity of the demodulated stream."""
    wb = format(want, "032b")
    cands = set()
    for base in (wb, "".join("1" if c == "0" else "0" for c in wb)):
        for r in range(32):
            cands.add(base[r:] + base[:r])
    n = len(bits)
    for i in range(n - 64):
        w = bits[i:i + 32]
        if w == bits[i + 32:i + 64] and w in cands:
            return True
    return False


@hw_slot.command("list")
class HWSlotList(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get information about slots"
        parser.add_argument(
            "--short",
            action="store_true",
            help="Hide slot nicknames and Mifare Classic emulator settings",
        )
        return parser

    def get_slot_name(self, slot, sense):
        try:
            name = self.cmd.get_slot_tag_nick(slot, sense)
            return {
                "baselen": len(name),
                "metalen": len(CC + C0),
                "name": color_string((CC, name)),
            }
        except UnexpectedResponseError:
            return {"baselen": 0, "metalen": 0, "name": ""}
        except UnicodeDecodeError:
            name = "UTF8 Err"
            return {
                "baselen": len(name),
                "metalen": len(CC + C0),
                "name": color_string((CC, name)),
            }

    def on_exec(self, args: argparse.Namespace):
        slotinfo = self.cmd.get_slot_info()
        selected = SlotNumber.from_fw(self.cmd.get_active_slot())
        current = selected
        enabled = self.cmd.get_enabled_slots()
        maxnamelength = 0

        slotnames = []
        all_nicks = self.cmd.get_all_slot_nicks()
        for slot_data in all_nicks:
            hfn = {
                "baselen": len(slot_data["hf"]),
                "metalen": len(CC + C0),
                "name": color_string((CC, slot_data["hf"])),
            }
            lfn = {
                "baselen": len(slot_data["lf"]),
                "metalen": len(CC + C0),
                "name": color_string((CC, slot_data["lf"])),
            }
            m = max(hfn["baselen"], lfn["baselen"])
            maxnamelength = m if m > maxnamelength else maxnamelength
            slotnames.append({"hf": hfn, "lf": lfn})

        for slot in SlotNumber:
            fwslot = SlotNumber.to_fw(slot)
            status = f"({color_string((CG, 'active'))})" if slot == selected else ""
            try:
                hf_tag_type = TagSpecificType(slotinfo[fwslot]["hf"])
            except ValueError:
                hf_tag_type = TagSpecificType.UNDEFINED
                hf_unknown = slotinfo[fwslot]["hf"]
            else:
                hf_unknown = None
            try:
                lf_tag_type = TagSpecificType(slotinfo[fwslot]["lf"])
            except ValueError:
                lf_tag_type = TagSpecificType.UNDEFINED
                lf_unknown = slotinfo[fwslot]["lf"]
            else:
                lf_unknown = None
            print(f' - {f"Slot {slot}:":{4+maxnamelength+1}} {status}')

            # HF
            field_length = maxnamelength + slotnames[fwslot]["hf"]["metalen"] + 1
            status = (
                f"({color_string((CR, 'disabled'))})"
                if not enabled[fwslot]["hf"]
                else ""
            )
            print(
                f"   HF: " f'{slotnames[fwslot]["hf"]["name"]:{field_length}}', end=""
            )
            print(status, end="")
            if hf_unknown is not None:
                print(color_string((CR, f"Unknown ({hf_unknown})")))
            elif hf_tag_type != TagSpecificType.UNDEFINED:
                color = CY if enabled[fwslot]["hf"] else C0
                print(color_string((color, hf_tag_type)))
            else:
                print("undef")
            if (
                (not args.short)
                and enabled[fwslot]["hf"]
                and hf_tag_type != TagSpecificType.UNDEFINED
                and hf_unknown is None
            ):
                if current != slot:
                    self.cmd.set_active_slot(slot)
                    current = slot
                anti_coll_data = self.cmd.hf14a_get_anti_coll_data()
                uid = anti_coll_data["uid"]
                atqa = anti_coll_data["atqa"]
                sak = anti_coll_data["sak"]
                ats = anti_coll_data["ats"]
                # print('    - ISO14443A emulator settings:')
                atqa_hex_le = f"(0x{int.from_bytes(atqa, byteorder='little'):04x})"
                print(f'      {"UID:":40}{color_string((CY, uid.hex().upper()))}')
                print(
                    f'      {"ATQA:":40}{color_string((CY, f"{atqa.hex().upper()} {atqa_hex_le}"))}'
                )
                print(f'      {"SAK:":40}{color_string((CY, sak.hex().upper()))}')
                if len(ats) > 0:
                    print(f'      {"ATS:":40}{color_string((CY, ats.hex().upper()))}')
                if hf_tag_type in [
                    TagSpecificType.MIFARE_Mini,
                    TagSpecificType.MIFARE_1024,
                    TagSpecificType.MIFARE_2048,
                    TagSpecificType.MIFARE_4096,
                    TagSpecificType.MIFARE_PLUS_S2K,
                    TagSpecificType.MIFARE_PLUS_S4K,
                ]:
                    config = self.cmd.mf1_get_emulator_config()
                    # print('    - Mifare Classic emulator settings:')
                    enabled_str = color_string((CG, "enabled"))
                    disabled_str = color_string((CR, "disabled"))
                    print(
                        f'      {"Gen1A magic mode:":40}'
                        f'{enabled_str if config["gen1a_mode"] else disabled_str}'
                    )
                    print(
                        f'      {"Gen2 magic mode:":40}'
                        f'{enabled_str if config["gen2_mode"] else disabled_str}'
                    )
                    print(
                        f'      {"Use anti-collision data from block 0:":40}'
                        f'{enabled_str if config["block_anti_coll_mode"] else disabled_str}'
                    )
                    try:
                        print(
                            f'      {"Write mode:":40}'
                            f'{color_string((CY, MifareClassicWriteMode(config["write_mode"])))}'
                        )
                    except ValueError:
                        print(
                            f'      {"Write mode:":40}{color_string((CR, "invalid value!"))}'
                        )
                    print(
                        f'      {"Log (mfkey32) mode:":40}'
                        f'{enabled_str if config["detection"] else disabled_str}'
                    )
                    try:
                        prng_resp = self.cmd.mf1_get_prng_type()
                        prng_type = MifareClassicPrngType(prng_resp.parsed)
                        print(
                            f'      {"PRNG type:":40}'
                            f'{color_string((CY, str(prng_type)))}'
                        )
                    except Exception:
                        pass

            # LF
            field_length = maxnamelength + slotnames[fwslot]["lf"]["metalen"] + 1
            status = (
                f"({color_string((CR, 'disabled'))})"
                if not enabled[fwslot]["lf"]
                else ""
            )
            print(
                f"   LF: " f'{slotnames[fwslot]["lf"]["name"]:{field_length}}', end=""
            )
            print(status, end="")
            if lf_unknown is not None:
                print(color_string((CR, f"Unknown ({lf_unknown})")))
            elif lf_tag_type != TagSpecificType.UNDEFINED:
                color = CY if enabled[fwslot]["lf"] else C0
                print(color_string((color, lf_tag_type)))
            else:
                print("undef")
            if (
                (not args.short)
                and enabled[fwslot]["lf"]
                and lf_tag_type != TagSpecificType.UNDEFINED
                and lf_unknown is None
            ):
                if current != slot:
                    self.cmd.set_active_slot(slot)
                    current = slot
                if lf_tag_type == TagSpecificType.EM410X:
                    id = self.cmd.em410x_get_emu_id()
                    print(f'      {"ID:":40}{color_string((CY, id.hex().upper()))}')
                if lf_tag_type == TagSpecificType.HIDProx:
                    (format, fc, cn1, cn2, il, oem) = self.cmd.hidprox_get_emu_id()
                    cn = (cn1 << 32) + cn2
                    print(
                        f"      {'Format:':40}{color_string((CY, HIDFormat(format)))}"
                    )
                    if fc > 0:
                        print(f"      {'FC:':40}{color_string((CG, fc))}")
                    if il > 0:
                        print(f"      {'IL:':40}{color_string((CG, il))}")
                    if oem > 0:
                        print(f"      {'OEM:':40}{color_string((CG, oem))}")
                    print(f"      {'CN:':40}{color_string((CG, cn))}")
                if lf_tag_type == TagSpecificType.ioProx:
                    ver, fc, cn, raw8, *futureuse = self.cmd.ioprox_get_emu_id()
                    print(f"      {'Version:':40}{color_string((CG, ver))}")
                    print(f"      {'Facility:':40}{color_string((CG, f'{fc} [0x{fc:02X}]'))}")
                    print(f"      {'ID:':40}{color_string((CY, cn))}")
                    print(f"      {'Raw:':40}{color_string((CY, raw8.hex().upper()))}")
                if lf_tag_type == TagSpecificType.Viking:
                    id = self.cmd.viking_get_emu_id()
                    print(f"      {'ID:':40}{color_string((CY, id.hex().upper()))}")
                if lf_tag_type == TagSpecificType.Jablotron:
                    id = self.cmd.jablotron_get_emu_id()
                    card_id = jablotron_card_id(id)
                    print(f"      {'ID:':40}{color_string((CY, id.hex().upper()))}")
                    print(f"      {'Card:':40}{color_string((CG, str(card_id)))}")
                if lf_tag_type == TagSpecificType.PAC:
                    id = self.cmd.pac_get_emu_id()
                    id_ascii = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in id)
                    raw = pac_encode_raw(id)
                    print(f"      {'CN:':40}{color_string((CY, id_ascii))}")
                    print(f"      {'Raw:':40}{color_string((CY, raw.hex().upper()))}")
                if lf_tag_type == TagSpecificType.IDTECK:
                    frame = self.cmd.idteck_get_emu_id()
                    info = _idteck_frame_info(frame)
                    card_id_str = f"{info['card_id']} (0x{info['card_id']:06X})"
                    print(f"      {'Frame:':40}{color_string((CY, frame.hex().upper()))}")
                    print(f"      {'Card ID:':40}{color_string((CG, card_id_str))}")
                if lf_tag_type == TagSpecificType.Indala:
                    frame = self.cmd.indala_get_emu_id()
                    fc, cn = indala_decode_raw(frame)
                    print(f"      {'Frame:':40}{color_string((CY, frame.hex().upper()))}")
                    print(f"      {'FC:':40}{color_string((CG, fc))}")
                    print(f"      {'CN:':40}{color_string((CG, cn))}")
        if current != selected:
            self.cmd.set_active_slot(selected)


@hw_slot.command("prng")
class HWSlotPrng(SlotIndexArgsAndGoUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Get or set the PRNG type for the MF1 emulator of a slot. "
            "PRNG controls the nonce used during MIFARE Classic authentication: "
            "0=Static (fixed), 1=Weak (LFSR/predictable), 2=Hard (unpredictable). "
            "Omit --type to read the current setting."
        )
        self.add_slot_args(parser)
        parser.add_argument(
            "-t",
            "--type",
            type=int,
            choices=[0, 1, 2],
            metavar="<0|1|2>",
            help="PRNG type: 0=Static, 1=Weak, 2=Hard",
            default=None,
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.type is None:
            # Read current PRNG type
            resp = self.cmd.mf1_get_prng_type()
            try:
                prng_type = MifareClassicPrngType(resp.parsed)
                print(f" - Slot {self.slot_num} PRNG type: {color_string((CY, str(prng_type)))} ({resp.parsed})")
            except ValueError:
                print(f" - Slot {self.slot_num} PRNG type: {color_string((CR, f'unknown ({resp.parsed})'))} ")
        else:
            self.cmd.mf1_set_prng_type(args.type)
            prng_type = MifareClassicPrngType(args.type)
            print(f" - Slot {self.slot_num} PRNG type set to: {color_string((CG, str(prng_type)))} ({args.type})")


@hw_slot.command("change")
class HWSlotSet(SlotIndexArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set emulation tag slot activated"
        return self.add_slot_args(parser, mandatory=True)

    def on_exec(self, args: argparse.Namespace):
        slot_index = args.slot
        self.cmd.set_active_slot(slot_index)
        print(f" - Set slot {slot_index} activated success.")


@hw_slot.command("type")
class HWSlotType(TagTypeArgsUnit, SlotIndexArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set emulation tag type"
        self.add_slot_args(parser)
        self.add_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        tag_type = TagSpecificType[args.type]
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        self.cmd.set_slot_tag_type(slot_num, tag_type)
        self.cmd.set_slot_data_default(slot_num, tag_type)
        print(f" - Set slot {slot_num} tag type success.")


@hw_slot.command("delete")
class HWDeleteSlotSense(SlotIndexArgsUnit, SenseTypeArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Delete sense type data for a specific slot"
        self.add_slot_args(parser)
        self.add_sense_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        if args.lf:
            sense_type = TagSenseType.LF
        else:
            sense_type = TagSenseType.HF
        self.cmd.delete_slot_sense_type(slot_num, sense_type)
        print(f" - Delete slot {slot_num} {sense_type.name} tag type success.")


@hw_slot.command("init")
class HWSlotInit(TagTypeArgsUnit, SlotIndexArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set emulation tag data to default"
        self.add_slot_args(parser)
        self.add_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        tag_type = TagSpecificType[args.type]
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        self.cmd.set_slot_data_default(slot_num, tag_type)
        print(" - Set slot tag data init success.")


@hw_slot.command("enable")
class HWSlotEnable(SlotIndexArgsUnit, SenseTypeArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Enable tag slot"
        self.add_slot_args(parser)
        self.add_sense_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        if args.lf:
            sense_type = TagSenseType.LF
        else:
            sense_type = TagSenseType.HF
        self.cmd.set_slot_enable(slot_num, sense_type, True)
        print(f" - Enable slot {slot_num} {sense_type.name} success.")


@hw_slot.command("disable")
class HWSlotDisable(SlotIndexArgsUnit, SenseTypeArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Disable tag slot"
        self.add_slot_args(parser)
        self.add_sense_type_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        slot_num = args.slot
        if args.lf:
            sense_type = TagSenseType.LF
        else:
            sense_type = TagSenseType.HF
        self.cmd.set_slot_enable(slot_num, sense_type, False)
        print(f" - Disable slot {slot_num} {sense_type.name} success.")


@hw_slot.command("nick")
class HWSlotNick(SlotIndexArgsUnit, SenseTypeArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get/Set/Delete tag nick name for slot"
        self.add_slot_args(parser)
        self.add_sense_type_args(parser)
        action_group = parser.add_mutually_exclusive_group()
        action_group.add_argument(
            "-n", "--name", type=str, required=False, help="Set tag nick name for slot"
        )
        action_group.add_argument(
            "-d", "--delete", action="store_true", help="Delete tag nick name for slot"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.slot is not None:
            slot_num = args.slot
        else:
            slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
        if args.lf:
            sense_type = TagSenseType.LF
        else:
            sense_type = TagSenseType.HF
        if args.name is not None:
            name: str = args.name
            self.cmd.set_slot_tag_nick(slot_num, sense_type, name)
            print(f" - Set tag nick name for slot {slot_num} {sense_type.name}: {name}")
        elif args.delete:
            self.cmd.delete_slot_tag_nick(slot_num, sense_type)
            print(f" - Delete tag nick name for slot {slot_num} {sense_type.name}")
        else:
            res = self.cmd.get_slot_tag_nick(slot_num, sense_type)
            print(
                f" - Get tag nick name for slot {slot_num} {sense_type.name}" f": {res}"
            )


@hw_slot.command("store")
class HWSlotUpdate(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Store slots config & data to device flash"
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.cmd.slot_data_config_save()
        print(" - Store slots config and data from device memory to flash success.")


@hw_slot.command("openall")
class HWSlotOpenAll(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Open all slot and set to default data"
        return parser

    def on_exec(self, args: argparse.Namespace):
        # what type you need set to default?
        hf_type = TagSpecificType.MIFARE_1024
        lf_type = TagSpecificType.EM410X

        # set all slot
        for slot in SlotNumber:
            print(f" Slot {slot} setting...")
            # first to set tag type
            self.cmd.set_slot_tag_type(slot, hf_type)
            self.cmd.set_slot_tag_type(slot, lf_type)
            # to init default data
            self.cmd.set_slot_data_default(slot, hf_type)
            self.cmd.set_slot_data_default(slot, lf_type)
            # finally, we can enable this slot.
            self.cmd.set_slot_enable(slot, TagSenseType.HF, True)
            self.cmd.set_slot_enable(slot, TagSenseType.LF, True)
            print(f" Slot {slot} setting done.")

        # update config and save to flash
        self.cmd.slot_data_config_save()
        print(" - Succeeded opening all slots and setting data to default.")


@hw.command("dfu")
class HWDFU(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Restart application to bootloader/DFU mode"
        return parser

    def on_exec(self, args: argparse.Namespace):
        print("Application restarting...")
        self.cmd.enter_bootloader()
        # In theory, after the above command is executed, the dfu mode will enter, and then the USB will restart,
        # To judge whether to enter the USB successfully, we only need to judge whether the USB becomes the VID and PID
        # of the DFU device.
        # At the same time, we remember to confirm the information of the device,
        # it is the same device when it is consistent.
        print(" - Enter success @.@~")
        # let time for comm thread to send dfu cmd and close port
        time.sleep(0.1)

@hw.command("flash")
class HWFlash(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Flash a DFU firmware package (.zip) to the device over Secure DFU. "
            "Enters bootloader mode automatically, then uploads with no external "
            "tools required (no nrfutil)."
        )
        parser.add_argument("file", type=str, help="Path to the DFU package .zip")
        parser.add_argument("--no-enter", action="store_true",
                            help="Skip enter-bootloader; device is already in DFU mode")
        parser.add_argument("-p", "--port", type=str, default=None,
                            help="Override the upload transport (default: the same transport the "
                                 "client is connected on). A serial port path, or "
                                 "'ble' / 'ble:AA:BB:CC:DD:EE:FF' to force BLE DFU (needs bleak)")
        parser.add_argument("--wait", type=float, default=30.0,
                            help="Seconds to wait for the DFU device to appear (default: 30)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        # Unpack first so a bad package fails before we touch the device.
        try:
            images = chameleon_dfu.unpack_dfu_zip(args.file)
        except FileNotFoundError:
            print(color_string((CR, f"File not found: {args.file}")))
            return
        except chameleon_dfu.DFUError as e:
            print(color_string((CR, f"Invalid DFU package: {e}")))
            return

        # Pick the upload transport. An explicit --port overrides; otherwise
        # inherit whatever the client is already connected on (USB serial or
        # BLE). DFU entry rides that same link; the device then re-advertises
        # USB DFU (1915:521f) and/or the BLE DFU service (0xFE59).
        override = args.port
        ble_address = None
        serial_port = None
        if override is not None and override.lower().startswith("ble"):
            use_ble = True
            ble_address = override.split(":", 1)[1] if ":" in override else None
        elif override is not None:
            use_ble = False
            serial_port = override
        else:
            ttype = getattr(self.device_com, "transport_type", None)
            use_ble = getattr(ttype, "name", "") == "BLE"

        # Enter bootloader unless the device is already in DFU or told to skip.
        if not args.no_enter:
            already_dfu = (not use_ble) and chameleon_dfu.find_dfu_port() is not None
            if not already_dfu:
                if not self.device_com.isOpen():
                    print("Please connect to chameleon device first (use 'hw connect'), "
                          "or pass --no-enter if it is already in DFU mode.")
                    return
                print("Application restarting into DFU mode...")
                self.cmd.enter_bootloader()
                time.sleep(0.1)

        # Release the app link before the upload (frees the serial port / BLE
        # central so the DFU transport can take it).
        if self.device_com.isOpen():
            self.device_com.close()

        # Build the upload transport.
        try:
            if use_ble:
                print("Scanning for DFU device (BLE, service 0xFE59)...")
                transport = chameleon_dfu.ble_transport(address=ble_address,
                                                        scan_timeout=args.wait)
                where = f"BLE {ble_address}" if ble_address else "BLE"
            else:
                port = serial_port
                if port is None:
                    print("Waiting for DFU device...")
                    port = chameleon_dfu.wait_for_dfu_port(timeout=args.wait)
                    if port is None:
                        print(color_string((CR, "DFU device (1915:521f) not found. "
                                                "Put the device in DFU mode and retry.")))
                        return
                transport = chameleon_dfu.serial_transport(port)
                where = port
        except chameleon_dfu.DFUError as e:
            print(color_string((CR, f"Could not open DFU transport: {e}")))
            return

        kinds = ", ".join(i["type"] for i in images)
        print(f"Flashing {os.path.basename(args.file)} ({kinds}) via {where}")

        def progress(pct):
            print(f"\r - Uploading: {pct:3d}%", end="", flush=True)

        try:
            chameleon_dfu.flash_package(images, transport, progress=progress)
        except chameleon_dfu.DFUError as e:
            print()
            print(color_string((CR, f"Flash failed: {e}")))
            return
        finally:
            transport.close()
        print()
        print(color_string((CG, " - Firmware flashed. Device will reboot.")))
        time.sleep(0.5)
        
@hw_settings.command("animation")
class HWSettingsAnimation(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get or change current animation mode value"
        mode_names = [m.name for m in list(AnimationMode)]
        help_str = "Mode: " + ", ".join(mode_names)
        parser.add_argument(
            "-m",
            "--mode",
            type=str,
            required=False,
            help=help_str,
            metavar="MODE",
            choices=mode_names,
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.mode is not None:
            mode = AnimationMode[args.mode]
            self.cmd.set_animation_mode(mode)
            print("Animation mode change success.")
            print(color_string((CY, "Do not forget to store your settings in flash!")))
        else:
            print(AnimationMode(self.cmd.get_animation_mode()))


@hw_settings.command("sleeptimeout")
class HWSettingsSleepTimeout(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get or set the wake timeout after a button press (5-60 seconds)"
        parser.add_argument(
            "-s",
            "--seconds",
            type=int,
            required=False,
            help="Wake timeout in seconds (5-60)",
            metavar="SECONDS",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.seconds is not None:
            seconds = args.seconds
            if seconds < 5:
                print(color_string((CR, "Error: value is too low. Please enter a value between 5 and 60 seconds.")))
                return
            if seconds > 60:
                print(color_string((CR, "Error: value is too high. Please enter a value between 5 and 60 seconds.")))
                return
            if seconds >= 30:
                print(color_string((CY, "Warning: a long wake timeout will drain the battery faster.")))
            self.cmd.set_sleep_timeout(seconds)
            print(f"Wake timeout set to {seconds} seconds.")
            print(color_string((CY, "Do not forget to store your settings in flash!")))
        else:
            current = self.cmd.get_sleep_timeout()
            print(f"Current wake timeout: {current} seconds")


@hw_settings.command("bleclearbonds")
class HWSettingsBleClearBonds(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Clear all BLE bindings. Warning: effect is immediate!"
        parser.add_argument(
            "--force", default=False, action="store_true", help="Just to be sure"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not args.force:
            print(
                "If you are you really sure, read the command documentation to see how to proceed."
            )
            return
        self.cmd.delete_all_ble_bonds()
        print(" - Successfully clear all bonds")


@hw_settings.command("store")
class HWSettingsStore(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Store current settings to flash"
        return parser

    def on_exec(self, args: argparse.Namespace):
        print("Storing settings...")
        if self.cmd.save_settings():
            print(" - Store success @.@~")
        else:
            print(" - Store failed")


@hw_settings.command("reset")
class HWSettingsReset(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Reset settings to default values"
        parser.add_argument(
            "--force", default=False, action="store_true", help="Just to be sure"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not args.force:
            print(
                "If you are you really sure, read the command documentation to see how to proceed."
            )
            return
        print("Initializing settings...")
        if self.cmd.reset_settings():
            print(" - Reset success @.@~")
        else:
            print(" - Reset failed")


@hw.command("reset")
class HWReset(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Reboot the device. Plain restart only — slots and settings are untouched."
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        print("Device restarting...")
        if self.cmd.reset_device():
            print(" - Reset successful! Please reconnect.")
        else:
            print(" - Reset failed!")
        # let time for comm thread to close port
        time.sleep(0.1)


@hw.command("factory_reset")
class HWFactoryReset(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Wipe all slot data and custom settings and return to factory settings"
        )
        parser.add_argument(
            "--force", default=False, action="store_true", help="Just to be sure"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not args.force:
            print(
                "If you are you really sure, read the command documentation to see how to proceed."
            )
            return
        if self.cmd.wipe_fds():
            print(" - Reset successful! Please reconnect.")
            # let time for comm thread to close port
            time.sleep(0.1)
        else:
            print(" - Reset failed!")


@hw.command("battery")
class HWBatteryInfo(DeviceRequiredUnit):
    # How much remaining battery is considered low?
    BATTERY_LOW_LEVEL = 30

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get battery information, voltage and level"
        return parser

    def on_exec(self, args: argparse.Namespace):
        voltage, percentage = self.cmd.get_battery_info()
        print(" - Battery information:")
        print(f"   voltage    -> {voltage} mV")
        print(f"   percentage -> {percentage}%")
        if percentage < HWBatteryInfo.BATTERY_LOW_LEVEL:
            print(color_string((CR, "[!] Low battery, please charge.")))


@hw_settings.command("btnpress")
class HWButtonSettingsGet(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get or set button press function of Button A and Button B"
        button_group = parser.add_mutually_exclusive_group()
        button_group.add_argument("-a", "-A", action="store_true", help="Button A")
        button_group.add_argument("-b", "-B", action="store_true", help="Button B")
        duration_group = parser.add_mutually_exclusive_group()
        duration_group.add_argument(
            "-s", "--short", action="store_true", help="Short-press (default)"
        )
        duration_group.add_argument(
            "-l", "--long", action="store_true", help="Long-press"
        )
        function_names = [f.name for f in list(ButtonPressFunction)]
        function_descs = [f"{f.name} ({f})" for f in list(ButtonPressFunction)]
        help_str = "Function: " + ", ".join(function_descs)
        parser.add_argument(
            "-f",
            "--function",
            type=str,
            required=False,
            help=help_str,
            metavar="FUNCTION",
            choices=function_names,
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.function is not None:
            function = ButtonPressFunction[args.function]
            if not args.a and not args.b:
                print(
                    color_string(
                        (CR, "You must specify which button you want to change")
                    )
                )
                return
            if args.a:
                button = ButtonType.A
            else:
                button = ButtonType.B
            if args.long:
                self.cmd.set_long_button_press_config(button, function)
            else:
                self.cmd.set_button_press_config(button, function)
            print(
                f" - Successfully set function '{function}'"
                f" to Button {button.name} {'long-press' if args.long else 'short-press'}"
            )
            print(color_string((CY, "Do not forget to store your settings in flash!")))
        else:
            if args.a:
                button_list = [ButtonType.A]
            elif args.b:
                button_list = [ButtonType.B]
            else:
                button_list = list(ButtonType)
            for button in button_list:
                if not args.long:
                    resp = self.cmd.get_button_press_config(button)
                    button_fn = ButtonPressFunction(resp)
                    print(f"{color_string((CG, f'{button.name} short'))}: {button_fn}")
                if not args.short:
                    resp_long = self.cmd.get_long_button_press_config(button)
                    button_long_fn = ButtonPressFunction(resp_long)
                    print(
                        f"{color_string((CG, f'{button.name} long'))}: {button_long_fn}"
                    )
                print("")


@hw_settings.command("blekey")
class HWSettingsBLEKey(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get or set the ble connect key"
        parser.add_argument(
            "-k", "--key", required=False, help="Ble connect key for your device"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        key = self.cmd.get_ble_pairing_key()
        print(f" - The current key of the device(ascii): {color_string((CG, key))}")

        if args.key is not None:
            if len(args.key) != 6:
                print(
                    f" - {color_string((CR, 'The ble connect key length must be 6'))}"
                )
                return
            if re.match(r"[0-9]{6}", args.key):
                self.cmd.set_ble_connect_key(args.key)
                print(
                    f" - Successfully set ble connect key to : {color_string((CG, args.key))}"
                )
                print(
                    color_string((CY, "Do not forget to store your settings in flash!"))
                )
            else:
                print(
                    f" - {color_string((CR, 'Only 6 ASCII characters from 0 to 9 are supported.'))}"
                )


@hw_settings.command("blepair")
class HWBlePair(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Show or configure BLE pairing"
        set_group = parser.add_mutually_exclusive_group()
        set_group.add_argument(
            "-e", "--enable", action="store_true", help="Enable BLE pairing"
        )
        set_group.add_argument(
            "-d", "--disable", action="store_true", help="Disable BLE pairing"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        is_pairing_enable = self.cmd.get_ble_pairing_enable()
        enabled_str = color_string((CG, "Enabled"))
        disabled_str = color_string((CR, "Disabled"))

        if not args.enable and not args.disable:
            if is_pairing_enable:
                print(f" - BLE pairing: {enabled_str}")
            else:
                print(f" - BLE pairing: {disabled_str}")
        elif args.enable:
            if is_pairing_enable:
                print(color_string((CY, "BLE pairing is already enabled.")))
                return
            self.cmd.set_ble_pairing_enable(True)
            print(f" - Successfully change ble pairing to {enabled_str}.")
            print(color_string((CY, "Do not forget to store your settings in flash!")))
        elif args.disable:
            if not is_pairing_enable:
                print(color_string((CY, "BLE pairing is already disabled.")))
                return
            self.cmd.set_ble_pairing_enable(False)
            print(f" - Successfully change ble pairing to {disabled_str}.")
            print(color_string((CY, "Do not forget to store your settings in flash!")))


@hw_settings.command("blename")
class HWSettingsBLEName(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Get or set the BLE advertised name (max 20 chars). Pass an empty string to reset to the firmware default."
        parser.add_argument(
            "-n", "--name", required=False, help="BLE advertised name for your device (max 20 chars), or \"\" to reset to default"
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        current = self.cmd.get_ble_name()
        current_display = current if current else color_string((CY, "(default)"))
        print(f" - The current BLE name of the device: {color_string((CG, current_display))}")

        if args.name is not None:
            if len(args.name) > 20:
                print(
                    f" - {color_string((CR, 'The BLE name must be at most 20 characters'))}"
                )
                return
            self.cmd.set_ble_name(args.name)
            new_display = args.name if args.name else color_string((CY, "(default)"))
            print(
                f" - Successfully set BLE name to: {color_string((CG, new_display))}"
            )
            print(
                color_string((CY, "Do not forget to store your settings in flash!"))
            )
            print(
                color_string((CY, "You may need to reconnect/rescan for the new name to show up."))
            )


@hw.command("raw")
class HWRaw(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Send raw command"
        cmd_names = sorted([c.name for c in list(Command)])
        help_str = "Command: " + ", ".join(cmd_names)
        command_group = parser.add_mutually_exclusive_group(required=True)
        command_group.add_argument(
            "-c",
            "--command",
            type=str,
            metavar="COMMAND",
            help=help_str,
            choices=cmd_names,
        )
        command_group.add_argument(
            "-n",
            "--num_command",
            type=int,
            metavar="<dec>",
            help="Numeric command ID: <dec>",
        )
        parser.add_argument(
            "-d", "--data", type=str, help="Data to send", default="", metavar="<hex>"
        )
        parser.add_argument(
            "-t",
            "--timeout",
            type=int,
            help="Timeout in seconds",
            default=3,
            metavar="<dec>",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.command is not None:
            command = Command[args.command]
        else:
            # We accept not-yet-known command ids as "hw raw" is meant for debugging
            command = args.num_command
        response = self.cmd.device.send_cmd_sync(
            command, data=bytes.fromhex(args.data), status=0x0, timeout=args.timeout
        )
        print(" - Received:")
        try:
            command = Command(response.cmd)
            print(f"   Command: {response.cmd} {command.name}")
        except ValueError:
            print(f"   Command: {response.cmd} (unknown)")

        status_string = f"   Status:  {response.status:#02x}"
        try:
            status = Status(response.status)
            status_string += f" {status.name}"
            status_string += f": {str(status)}"
        except ValueError:
            pass
        print(status_string)
        if response.data:
            print(f"   Data (HEX): {response.data.hex()}")
        else:
            print(f"   Data (HEX): (none)")


@hf_14a.command("raw")
class HF14ARaw(ReaderRequiredUnit):

    def bool_to_bit(self, value):
        return 1 if value else 0

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = "Send raw command"
        parser.add_argument(
            "-a",
            "--activate-rf",
            help="Active signal field ON without select",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-s",
            "--select-tag",
            help="Active signal field ON with select",
            action="store_true",
            default=False,
        )
        # TODO: parser.add_argument('-3', '--type3-select-tag',
        #           help="Active signal field ON with ISO14443-3 select (no RATS)", action='store_true', default=False,)
        parser.add_argument(
            "-d", "--data", type=str, metavar="<hex>", help="Data to be sent"
        )
        parser.add_argument(
            "-b",
            "--bits",
            type=int,
            metavar="<dec>",
            help="Number of bits to send. Useful for send partial byte",
        )
        parser.add_argument(
            "-c",
            "--crc",
            help="Calculate and append CRC",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-r",
            "--no-response",
            help="Do not read response",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-cc",
            "--crc-clear",
            help="Verify and clear CRC of received data",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-k",
            "--keep-rf",
            help="Keep signal field ON after receive",
            action="store_true",
            default=False,
        )
        parser.add_argument(
            "-t",
            "--timeout",
            type=int,
            metavar="<dec>",
            help="Timeout in ms",
            default=100,
        )
        parser.epilog = """
examples/notes:
  hf 14a raw -b 7 -d 40 -k
  hf 14a raw -d 43 -k
  hf 14a raw -d 3000 -c
  hf 14a raw -sc -d 6000
"""
        return parser

    def on_exec(self, args: argparse.Namespace):
        options = {
            "activate_rf_field": self.bool_to_bit(args.activate_rf),
            "wait_response": self.bool_to_bit(not args.no_response),
            "append_crc": self.bool_to_bit(args.crc),
            "auto_select": self.bool_to_bit(args.select_tag),
            "keep_rf_field": self.bool_to_bit(args.keep_rf),
            "check_response_crc": self.bool_to_bit(args.crc_clear),
            # 'auto_type3_select': self.bool_to_bit(args.type3-select-tag),
        }
        data: str = args.data
        if data is not None:
            data = data.replace(" ", "")
            if re.match(r"^[0-9a-fA-F]+$", data):
                if len(data) % 2 != 0:
                    print(
                        f" [!] {color_string((CR, 'The length of the data must be an integer multiple of 2.'))}"
                    )
                    return
                else:
                    data_bytes = bytes.fromhex(data)
            else:
                print(f" [!] {color_string((CR, 'The data must be a HEX string'))}")
                return
        else:
            data_bytes = []
        if args.bits is not None and args.crc:
            print(
                f" [!] {color_string((CR, '--bits and --crc are mutually exclusive'))}"
            )
            return

        # Exec 14a raw cmd.
        resp = self.cmd.hf14a_raw(options, args.timeout, data_bytes, args.bits)
        if len(resp) > 0:
            print(
                # print head
                " - "
                +
                # print data
                " ".join([hex(byte).replace("0x", "").rjust(2, "0") for byte in resp])
            )
        else:
            print(f" [*] {color_string((CY, 'No response'))}")


@hf_14a.command('sniff')
class HF14ASniff(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Capture ISO14443A reader frames while CU acts as a tag. "
            "Place CU near a reader — all commands the reader sends are logged. "
            "Useful for understanding what a reader expects before configuring emulation."
        )
        parser.add_argument(
            '--timeout', type=int, default=5000, metavar='MS',
            help='Listen duration in milliseconds (default: 5000, max: 30000, firmware blocks for full duration)'
        )
        parser.add_argument(
            '--tap', action='store_true',
            help='Passive tap: CU stays silent while a REAL card answers the reader. '
                 'Captures reader->card on NFCT and card->reader via the RC522. '
                 'Place CU, card, and reader in the same field.'
        )
        parser.add_argument('-o', '--trace', type=str, default=None,
                            help='Write capture as a Proxmark3 .trace file')
        return parser

    def on_exec(self, args: argparse.Namespace):
        timeout = max(1, min(30000, args.timeout))
        if args.tap:
            print(f" Passive tap for {timeout}ms — CU silent, real card answers.")
            print(" Place the card between the reader and the CU, all in the field.")
        else:
            print(f" Listening for reader frames for {timeout}ms...")
            print(" Place CU near a reader now.")
        print()

        try:
            resp = self.cmd.hf14a_sniff(timeout_ms=timeout, tap=args.tap)
        except Exception as e:
            if 'CMDInvalid' in type(e).__name__ or '2020' in str(e):
                print(f"{CR}Command not supported — reflash firmware to enable hf 14a sniff{C0}")
            else:
                print(f"{CR}{e}{C0}")
            return

        if resp.status not in (Status.HF_TAG_OK, Status.SUCCESS):
            cb_count = 0
            if resp.data and len(resp.data) >= 2:
                cb_count = (resp.data[0] << 8) | resp.data[1]
            if cb_count > 0:
                print(f"{CY} Callback fired {cb_count}x but no valid frames buffered{C0}")
            else:
                print(" No frames captured — no reader detected")
            return

        # Parse packed frame buffer: [2 bytes bits BE][N bytes data] ...
        # Bit 15 of szBits: 0 = reader→card, 1 = card→reader (new firmware).
        # Old firmware always sends bit15=0; parser is backward compatible.
        buf = bytes(resp.data)
        frames = []  # (szBits, data, is_tx, parity)
        i = 0
        while i + 2 <= len(buf):
            hdr = (buf[i] << 8) | buf[i+1]
            i += 2
            is_tx = bool(hdr & 0x8000)
            szBits = hdr & 0x7FFF
            if szBits == 0:
                break
            szBytes = (szBits + 7) // 8
            if i + szBytes > len(buf):
                break
            raw = buf[i:i+szBytes]
            i += szBytes

            # parity array: parity for each byte of data array
            parity_bits = []

            # ISO14443-A frames include one parity bit per byte.
            # Short frames (< 8 bits, e.g. REQA=7 bits) have no parity.
            # All other frames: szBits = data_bytes * 9, strip every 9th bit.
            if szBits >= 8 and szBits % 9 == 0:
                n_bytes = szBits // 9
                all_bits = []
                for byte in raw:
                    for b in range(8):
                        all_bits.append((byte >> b) & 1)
                stripped = []
                for nb in range(n_bytes):
                    val = 0
                    for b in range(8):
                        val |= all_bits[nb * 9 + b] << b
                    stripped.append(val)
                    parity_bits.append(all_bits[nb * 9 + 8])
                data = bytes(stripped)
                szBits = n_bytes * 8
            else:
                data = raw

            frames.append((szBits, data, is_tx, parity_bits))

        if not frames:
            print(f"{CR}No frames decoded{C0}")
            return

        if getattr(args, 'trace', None):
            blob = pm3_trace.frames_to_pm3_trace(frames)
            with open(args.trace, 'wb') as f:
                f.write(blob)
            print(f" Saved Proxmark3 trace: {CG}{args.trace}{C0} "
                  f"({len(blob)} bytes, {len(frames)} frame(s))")
        rx_count = sum(1 for _, _, tx, _ in frames if not tx)
        tx_count = sum(1 for _, _, tx, _ in frames if tx)

        if tx_count > 0:
            print(f" Captured : {CG}{len(frames)}{C0} frame(s)  "
                  f"({CY}{rx_count}{C0} reader→card  {CG}{tx_count}{C0} card→reader)")
        else:
            print(f" Captured : {CG}{len(frames)}{C0} frame(s)  "
                  f"{CY}(reader→card only — reflash for both directions){C0}")
        print()
        print(f"  {'#':>3}  {'dir':<3}  {'bits':>4}  {'hex data':<42}  decoded")
        print(f"  {'---':>3}  {'---':<3}  {'----':>4}  {'-'*42}  {'-'*35}")
        # Context for MIFARE Classic authentication decoding (NT / NR||AR)
        expect_nt = False
        expect_nr_ar = False
        last_auth_keytype = None
        last_auth_block = None
        auth_nt_slot = -1
        expect_nr_ar = False
        at_slot = -1
        nt_clean = None
        prev_cmd = None
        iso_dep = False

        for n, (szBits, data, is_tx, parity_bits) in enumerate(frames):
            if (len(data) == len(parity_bits)):
                hex_str = ' '.join(f"{b:02x}{'!' if odd_parity_byte(b)!= p else ' '}" for (b,p) in zip(data,parity_bits))
            else:
                hex_str = ' '.join(f"{b:02x}" for b in data)

            # is_tx==True means CU transmitted (card -> reader).
            # is_tx==False means reader -> card.
            decoded_ctx = None
            col_ctx = None

            # Reader -> card: AUTH command (0x60/0x61 + block + CRC-A)
            if (not is_tx) and szBits == 32 and len(data) == 4 and data[0] in (0x60, 0x61):
                last_auth_keytype = 'A' if data[0] == 0x60 else 'B'
                last_auth_block = data[1]
                auth_nt_slot = n + 1     # NT must be the very next frame, nothing later
                expect_nr_ar = False
                nt_clean = None
                decoded_ctx = f"MIFARE Classic AUTH Key{last_auth_keytype} block=0x{last_auth_block:02X} ({last_auth_block})"
                col_ctx = CG

            # Card -> reader: NT — ONLY the frame immediately after AUTH. A clean
            # nonce is 4 bytes; the RC522 often mangles it (40 bits etc.), so flag
            # that rather than latching onto a later SAK and calling it NT.
            elif is_tx and n == auth_nt_slot:
                if szBits == 32 and len(data) == 4:
                    nt_clean = data.hex()
                    decoded_ctx = f"AUTH: NT (card nonce) = {nt_clean}"
                    col_ctx = CG
                else:
                    decoded_ctx = f"AUTH: NT (card nonce) GARBLED — {szBits}b, need clean 32b"
                    col_ctx = CR
                expect_nr_ar = True

            # Reader -> card: NR||AR (64-bit, encrypted) after the NT slot
            elif (not is_tx) and expect_nr_ar and szBits == 64 and len(data) == 8:
                nr = data[:4].hex()
                ar = data[4:].hex()
                note = "" if nt_clean else "  (NT garbled -> not crackable)"
                decoded_ctx = f"AUTH: NR||AR (enc)  NR={nr}  AR={ar}{note}"
                col_ctx = CG if nt_clean else CY
                expect_nr_ar = False
                at_slot = n + 1     # {at} is the very next frame (card->reader, 32b)

            # Card -> reader: AT — the frame immediately after NR||AR. mfkey64
            # needs this (clean 4 bytes) plus a clean NT to recover the key.
            elif is_tx and n == at_slot:
                if szBits == 32 and len(data) == 4:
                    at_hex = data.hex()
                    ready = " -> mfkey64-ready" if nt_clean else " (but NT garbled)"
                    decoded_ctx = f"AUTH: AT (enc card response) = {at_hex}{ready}"
                    col_ctx = CG if nt_clean else CY
                else:
                    decoded_ctx = f"AUTH: AT (enc card response) GARBLED — {szBits}b, need clean 32b"
                    col_ctx = CR

            # Generic decoder -- direction- and context-gated
            decoded, col, cmd_tag = _decode_14a_frame_col(
                data, szBits, is_tx, prev_cmd, iso_dep)
            if not is_tx:
                prev_cmd = cmd_tag
                if cmd_tag == 'rats':
                    iso_dep = True
                elif cmd_tag in ('halt', 'deselect'):
                    iso_dep = False
            else:
                prev_cmd = None      # a response consumes its command context
            if decoded_ctx is not None:
                decoded, col = decoded_ctx, col_ctx

            dir_str = f'{CG}<<<{C0}' if is_tx else f'{CY}>>>{C0}'
            print(f"  {CY}{n+1:>3}{C0}  {dir_str}  {szBits:>4}  {hex_str:<42}  {col}{decoded}{C0}")

        # Summary block (pass only reader→card frames for protocol decode)
        print()
        _print_14a_sniff_summary([(szBits, data, is_tx) for (szBits, data, is_tx,parity) in frames])  # full frames needed for nonce extraction


@hf_14a.command("auth-trace")
class HF14AAuthTrace(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = (
            "Run a full reader-side ISO14443A + MIFARE Classic Crypto1 auth "
            "against a real card and print every wire frame: REQA → ATQA → "
            "anticoll/SELECT → SAK → (RATS/ATS) → AUTH(0x60/0x61) → NT → "
            "NR||AR (enc) → AT (enc), with host-side Crypto1 decryption of "
            "the auth sub-frames for verification."
        )
        parser.add_argument(
            "--blk", "--block", type=int, required=True, metavar="<dec>",
            help="Target block number"
        )
        keytype_group = parser.add_mutually_exclusive_group()
        keytype_group.add_argument("-a", "-A", action="store_true", help="Use Key A (default)")
        keytype_group.add_argument("-b", "-B", action="store_true", help="Use Key B")
        parser.add_argument(
            "-k", "--key", type=str, required=True, metavar="<hex>",
            help="6-byte sector key (12 hex chars)"
        )
        parser.add_argument(
            "-t", "--timeout", type=int, default=5000, metavar="<ms>",
            help="Tag-presence polling timeout in ms (1-30000, default 5000)"
        )
        parser.epilog = """
examples:
  hf 14a auth-trace --blk 0 -k FFFFFFFFFFFF
  hf 14a auth-trace --blk 4 -b -k A0A1A2A3A4A5
  hf 14a auth-trace --blk 0 -k FFFFFFFFFFFF -t 10000   # wait up to 10s for tag
"""
        return parser

    def on_exec(self, args: argparse.Namespace):
        # Validate key
        key_hex = args.key.replace(" ", "")
        if not re.match(r"^[0-9a-fA-F]{12}$", key_hex):
            print(f" [!] {color_string((CR, 'Key must be exactly 12 hex characters'))}")
            return
        key_bytes = bytes.fromhex(key_hex)
        key_type = 0x61 if args.b else 0x60
        block = args.blk
        timeout_ms = max(1, min(30000, int(args.timeout)))

        print(f" Running auth trace: block={block} keyType={'B' if args.b else 'A'} key={key_hex.upper()}")
        print(f" Waiting up to {timeout_ms} ms for a MIFARE Classic card... "
              f"({CY}place CU on a card now{C0})")
        print()

        try:
            resp = self.cmd.hf14a_auth_trace(block, key_type, key_bytes, timeout_ms=timeout_ms)
        except Exception as e:
            if 'CMDInvalid' in type(e).__name__ or '2017' in str(e):
                print(f"{CR}Command not supported — reflash firmware to enable hf 14a auth-trace{C0}")
            else:
                print(f"{CR}{e}{C0}")
            return

        # Status legend:
        #   HF_TAG_OK   — auth succeeded, full trace
        #   HF_TAG_NO   — no card / scan failed
        #   MF_ERR_AUTH — auth failed (wrong key / wrong block), partial trace returned
        #   HF_ERR_STAT — no NT received, partial trace returned
        if resp.status == Status.HF_TAG_NO:
            print(f"{CR} No 14443A tag in field — auth aborted{C0}")
            return

        if not resp.data:
            print(f"{CR} No frames returned (status={Status(resp.status).name}){C0}")
            return

        # Parse packed frame buffer — same format as hf 14a sniff.
        # [bits_be16][data...]; bit15 of bits = direction (1 = card→reader).
        buf = bytes(resp.data)
        frames = []  # (szBits, data, is_tx)
        i = 0
        while i + 2 <= len(buf):
            hdr = (buf[i] << 8) | buf[i + 1]
            i += 2
            is_tx = bool(hdr & 0x8000)
            szBits = hdr & 0x7FFF
            if szBits == 0:
                break
            szBytes = (szBits + 7) // 8
            if i + szBytes > len(buf):
                break
            raw = buf[i:i + szBytes]
            i += szBytes
            # Auth-trace stores parity-stripped data (firmware byte/bits
            # transfer primitives strip parity automatically), so szBits is
            # always a multiple of 8 — no unwrap needed.
            frames.append((szBits, raw, is_tx))

        if not frames:
            print(f"{CR}No frames decoded{C0}")
            return

        # Header
        rx_count = sum(1 for _, _, tx in frames if not tx)
        tx_count = sum(1 for _, _, tx in frames if tx)
        status_label = {
            Status.HF_TAG_OK:    f"{CG}auth OK{C0}",
            Status.MF_ERR_AUTH:  f"{CR}auth FAILED{C0}",
            Status.HF_ERR_STAT:  f"{CR}no NT received{C0}",
        }.get(Status(resp.status), f"{CY}status={Status(resp.status).name}{C0}")
        print(f" Captured : {CG}{len(frames)}{C0} frame(s)  "
              f"({CY}{rx_count}{C0} reader→card  {CG}{tx_count}{C0} card→reader)  "
              f"{status_label}")
        print()
        print(f"  {'#':>3}  {'dir':<3}  {'bits':>4}  {'hex data':<42}  decoded")
        print(f"  {'---':>3}  {'---':<3}  {'----':>4}  {'-' * 42}  {'-' * 35}")

        # Auth-state tracker — annotate AUTH cmd, NT, NR||AR, AT specifically.
        auth_state = 'idle'    # idle → cmd_seen → nt_seen → nr_ar_seen → done
        last_auth_keytype = None
        last_auth_block = None
        nt_int = None
        nr_ar_enc = None
        at_enc = None
        uid_bytes = b''
        prev_cmd = None
        iso_dep = False

        for n, (szBits, data, is_tx) in enumerate(frames):
            hex_str = ' '.join(f'{b:02x}' for b in data)
            decoded_ctx = None
            col_ctx = None

            # Capture UID from the first anticoll RX (CL1 response): 5 bytes.
            # If first byte is 0x88 it's a cascading 7-byte UID — second segment
            # gives bytes 3..6. For 4-byte UID, all four bytes are here.
            if is_tx and szBits == 40 and len(data) == 5 and not uid_bytes:
                if data[0] == 0x88:
                    uid_bytes = data[1:4]  # CT|UID0|UID1|UID2|BCC
                else:
                    uid_bytes = data[0:4]
            elif is_tx and szBits == 40 and len(data) == 5 and len(uid_bytes) == 3:
                uid_bytes = uid_bytes + data[0:4]  # 7-byte UID complete

            # AUTH cmd: 0x60/0x61 + block + 2 CRC bytes, reader→card, 32 bits
            if (not is_tx) and szBits == 32 and len(data) == 4 and data[0] in (0x60, 0x61):
                last_auth_keytype = 'A' if data[0] == 0x60 else 'B'
                last_auth_block = data[1]
                auth_state = 'cmd_seen'
                decoded_ctx = f"AUTH Key{last_auth_keytype} block=0x{last_auth_block:02X} ({last_auth_block}) +CRC"
                col_ctx = CG

            # NT: 4 bytes, card→reader, immediately after AUTH cmd
            elif is_tx and auth_state == 'cmd_seen' and szBits == 32 and len(data) == 4:
                nt_int = int.from_bytes(data, 'big')
                auth_state = 'nt_seen'
                decoded_ctx = f"NT (card nonce, plaintext) = {data.hex().upper()}"
                col_ctx = CG

            # NR||AR encrypted: 8 bytes, reader→card, after NT
            elif (not is_tx) and auth_state == 'nt_seen' and szBits == 64 and len(data) == 8:
                nr_ar_enc = bytes(data)
                auth_state = 'nr_ar_seen'
                decoded_ctx = f"NR||AR (enc)  NR={data[:4].hex().upper()}  AR={data[4:].hex().upper()}"
                col_ctx = CG

            # AT encrypted: 4 bytes, card→reader, after NR||AR
            elif is_tx and auth_state == 'nr_ar_seen' and szBits == 32 and len(data) == 4:
                at_enc = bytes(data)
                auth_state = 'done'
                decoded_ctx = f"AT (enc) = {data.hex().upper()}"
                col_ctx = CG

            decoded, col, cmd_tag = _decode_14a_frame_col(
                data, szBits, is_tx, prev_cmd, iso_dep)
            if not is_tx:
                prev_cmd = cmd_tag
                if cmd_tag == 'rats':
                    iso_dep = True
                elif cmd_tag in ('halt', 'deselect'):
                    iso_dep = False
            else:
                prev_cmd = None      # a response consumes its command context
            if decoded_ctx is not None:
                decoded, col = decoded_ctx, col_ctx

            dir_str = f'{CG}<<<{C0}' if is_tx else f'{CY}>>>{C0}'
            print(f"  {CY}{n + 1:>3}{C0}  {dir_str}  {szBits:>4}  {hex_str:<42}  {col}{decoded}{C0}")

        # Crypto1 verification block — if we have NT + NR||AR, decrypt AR/AT
        # and confirm they match prng_successor(NT, 32) / prng_successor(NT, 64).
        print()
        if nt_int is not None and nr_ar_enc is not None and len(uid_bytes) >= 4:
            uid32 = int.from_bytes(uid_bytes[-4:], 'big')  # last 4 bytes for cascade≥2
            print(f" {CC}Crypto1 analysis:{C0}")
            print(f"   UID (low 4 bytes) : {uid_bytes[-4:].hex().upper()}")
            print(f"   NT (plaintext)    : {nt_int:08X}")
            print(f"   NR (fixed in fw)  : 12345678  (encrypted on wire: {nr_ar_enc[:4].hex().upper()})")
            ar_expected = Crypto1.prng_next(nt_int, 64)
            at_expected = Crypto1.prng_next(nt_int, 96)
            if at_enc is not None:
                # Re-run Crypto1 forward to recover ks2 (AR keystream) and ks3 (AT keystream).
                state = Crypto1()
                state.key = key_hex
                state.lfsr48_u32(uid32 ^ nt_int, False)                            # ks0
                state.lfsr48_u32(int.from_bytes(nr_ar_enc[:4], 'big'), True)       # ks1
                ks_ar = state.lfsr48_u32(0, False)                                  # ks2 (AR keystream)
                ks_at = state.lfsr48_u32(0, False)                                  # ks3 (AT keystream)
                ar_int = int.from_bytes(nr_ar_enc[4:], 'big')
                ar_decoded = ar_int ^ ks_ar
                ar_ok = (ar_decoded == ar_expected)
                ar_colour = CG if ar_ok else CR
                ar_mark = '✓' if ar_ok else '✗'
                print(f"   AR expected       : {ar_expected:08X}  = prng_successor(NT, 64)")
                print(f"   AR (encrypted)    : {nr_ar_enc[4:].hex().upper()}")
                print(f"   AR decrypted      : {ar_colour}{ar_decoded:08X}{C0}  {ar_colour}{ar_mark} "
                      f"{'MATCH' if ar_ok else 'MISMATCH — wrong key or replay'}{C0}")
                at_int = int.from_bytes(at_enc, 'big')
                at_decoded = at_int ^ ks_at
                ok = (at_decoded == at_expected)
                colour = CG if ok else CR
                mark = '✓' if ok else '✗'
                print(f"   AT expected       : {at_expected:08X}  = prng_successor(NT, 96)")
                print(f"   AT (encrypted)    : {at_enc.hex().upper()}")
                print(f"   AT decrypted      : {colour}{at_decoded:08X}{C0}  {colour}{mark} "
                      f"{'MATCH — auth verified' if ok else 'MISMATCH — wrong key or replay'}{C0}")
                # Cross-check against mfkey32 prediction too.
                nr_enc_int = int.from_bytes(nr_ar_enc[:4], 'big')
                ar_enc_int = int.from_bytes(nr_ar_enc[4:], 'big')
                key_match = Crypto1.mfkey32_is_reader_has_key(uid32, nt_int, nr_enc_int, ar_enc_int, key_hex)
                if key_match:
                    print(f"   mfkey32 forward   : {CG}key {key_hex.upper()} verified against NT/NR/AR{C0}")
            else:
                print(f"   {CR}AT not received — auth was rejected by the card{C0}")
        elif nt_int is not None:
            print(f" {CY}Auth aborted before NR||AR — NT={nt_int:08X}, no further analysis{C0}")


def _decode_sw(sw1: int, sw2: int) -> str:
    """Decode an ISO 7816-4 status word pair."""
    exact = {
        0x9000: 'OK',
        0x6100: 'Response bytes available',
        0x6283: 'File deactivated',
        0x6300: 'Auth failed',
        0x6400: 'No changes',
        0x6581: 'Memory failure',
        0x6700: 'Wrong length',
        0x6881: 'Logical channel not supported',
        0x6882: 'Secure messaging not supported',
        0x6900: 'Command not allowed',
        0x6981: 'Command incompatible with file structure',
        0x6982: 'Security status not satisfied',
        0x6983: 'Auth method blocked',
        0x6984: 'Referenced data invalidated',
        0x6985: 'Conditions of use not satisfied',
        0x6986: 'Command not allowed — no EF selected',
        0x6A00: 'Wrong parameters P1-P2',
        0x6A80: 'Incorrect data in command',
        0x6A81: 'Function not supported',
        0x6A82: 'File not found',
        0x6A83: 'Record not found',
        0x6A84: 'Not enough memory',
        0x6A85: 'Lc inconsistent with TLV',
        0x6A86: 'Incorrect parameters P1-P2',
        0x6A87: 'Lc inconsistent with P1-P2',
        0x6A88: 'Referenced data not found',
        0x6B00: 'Wrong parameters P1-P2',
        0x6D00: 'Instruction not supported',
        0x6E00: 'Class not supported',
        0x6F00: 'Unknown error',
    }
    key = (sw1 << 8) | sw2
    if key in exact:
        return exact[key]
    if sw1 == 0x61:
        return f'Response bytes available: {sw2}'
    if sw1 == 0x62:
        return f'Warning — no info change: {sw2:02X}'
    if sw1 == 0x63:
        return f'Warning — state changed: {sw2:02X}'
    if sw1 == 0x6C:
        return f'Wrong Le — use {sw2}'
    if sw1 == 0x90:
        return 'OK'
    if sw1 == 0x91:
        return 'Proprietary OK'
    return ''


_CD = "\033[90m"   # dim grey: raw/garbled frames that fail validation


def _sak_desc(sak: int):
    try:
        sak_type = type_id_SAK_dict.get(sak, "")
    except Exception:
        sak_type = ""
    if sak_type:
        return f"SAK (Select Acknowledge) = 0x{sak:02X}  [{sak_type}]"
    return f"SAK (Select Acknowledge) = 0x{sak:02X}"


def _decode_14a_frame_col(data: bytes, szBits: int, is_tx: bool = False,
                          prev_cmd=None, iso_dep: bool = False):
    """Return (description, colour, cmd_tag) for a 14A frame.

    Direction- and context-gated so demod garbage is not dressed up as protocol:
      * is_tx False (reader->card) is decoded as a COMMAND, is_tx True
        (card->reader) as a RESPONSE.
      * a response is only NAMED when the preceding reader command makes it
        plausible -- ATQA after REQA/WUPA, SAK after SELECT, UID after ANTICOLL
        -- and it passes its integrity check (BCC / length).
      * APDUs are only decoded inside an established ISO-DEP (RATS/ATS) channel.
    Anything that fails is shown raw, not mislabelled.

    cmd_tag (3rd value) is this frame's reader-command class ('reqa','anticoll1',
    'select1','auth','rats','halt','deselect',...) or None, so the caller can
    feed it as prev_cmd to the next frame and track ISO-DEP state.
    """
    if not data:
        return '', C0, None
    b0 = data[0]

    def raw(reason=''):
        body = f'raw {data.hex()}'
        return (f'{body}  ({reason})' if reason else body), _CD, None

    # ===================== READER -> CARD : commands =====================
    if not is_tx:
        if szBits == 7:
            if b0 == 0x26:
                return 'REQA', CG, 'reqa'
            if b0 == 0x52:
                return 'WUPA', CG, 'wupa'
            return f'short(0x{b0:02x})', CC, None
        if b0 in (0x93, 0x95, 0x97):
            lvl = {0x93: '1', 0x95: '2', 0x97: '3'}[b0]
            if len(data) > 1 and data[1] == 0x70:
                uid = ' '.join(f'{b:02x}' for b in data[2:6]) if len(data) >= 6 else ''
                return f'SELECT CL{lvl}  UID={uid}', CB, f'select{lvl}'
            nvb = f'NVB={data[1]:02x}' if len(data) > 1 else ''
            return f'ANTICOLL CL{lvl}  {nvb}', CB, f'anticoll{lvl}'
        if b0 == 0x50:
            return 'HALT', CC, 'halt'
        if b0 == 0xc2:
            return 'S-DESELECT', CC, 'deselect'
        if b0 == 0xd0:
            return (f'PPS  PPS1={data[1]:02x}' if len(data) > 1 else 'PPS'), CC, None
        if b0 == 0xe0:
            fsdi = (data[1] >> 4) if len(data) > 1 else 0
            cid = (data[1] & 0xf) if len(data) > 1 else 0
            return f'RATS  FSDI={fsdi} CID={cid}', CC, 'rats'
        if b0 == 0x60:
            return (f'AUTH KeyA  block={data[1]}' if len(data) > 1 else 'AUTH KeyA'), CR, 'auth'
        if b0 == 0x61:
            return (f'AUTH KeyB  block={data[1]}' if len(data) > 1 else 'AUTH KeyB'), CR, 'auth'
        if b0 == 0x30:
            return (f'READ  block={data[1]}' if len(data) > 1 else 'READ'), CC, 'read'
        if b0 == 0xa0:
            return (f'WRITE block={data[1]}' if len(data) > 1 else 'WRITE'), CY, 'write'
        if b0 == 0x40:
            return 'MAGIC WUPC1', CY, None
        if b0 == 0x43:
            return 'MAGIC WUPC2', CY, None
        if b0 == 0x41:
            return 'MAGIC WIPE', CR, None
        # ISO 7816-4 APDU -- only inside an established ISO-DEP channel
        if iso_dep and len(data) >= 4 and b0 in (0x00, 0x80, 0x90, 0xa0):
            cla, ins = data[0], data[1]
            p1 = data[2] if len(data) > 2 else 0
            p2 = data[3] if len(data) > 3 else 0
            if cla == 0x00 and ins == 0xa4:
                if len(data) > 5:
                    aid = ' '.join(f'{b:02x}' for b in data[5:5 + data[4]])
                    name = _known_aid(bytes(data[5:5 + data[4]]))
                    label = f'SELECT AID  {aid.upper()}' + (f'  ({name})' if name else '')
                    return label, CY, None
                return 'SELECT', CY, None
            if cla == 0x00 and ins == 0xb0:
                return f'READ BINARY  off={p1 << 8 | p2} len={data[4] if len(data) > 4 else 0}', CC, None
            if cla == 0x00 and ins == 0xb2:
                return f'READ RECORD  SFI={p2 >> 3} rec={p1}', CC, None
            if cla == 0x80 and ins == 0xca:
                name = _known_bertag((p1 << 8) | p2)
                return f'GET DATA  {p1:02x}{p2:02x}' + (f'  ({name})' if name else ''), CC, None
            if cla == 0x80 and ins == 0xa8:
                return 'GPO  (Get Processing Options)', CY, None
            if cla == 0x80 and ins == 0xae:
                actype = {0x00: 'AAC', 0x40: 'TC', 0x80: 'ARQC'}.get(p1 & 0xc0, f'AC/{p1:02x}')
                return f'GENERATE AC  requesting {actype}', CR, None
            if cla == 0x00 and ins == 0x20:
                return 'VERIFY PIN', CY, None
            if cla == 0x00 and ins == 0x88:
                return 'INTERNAL AUTH', CR, None
            if cla == 0x00 and ins == 0x82:
                return 'EXTERNAL AUTH', CR, None
            if cla == 0x00 and ins == 0x70:
                return 'MANAGE CHANNEL', CC, None
            return f'APDU  CLA={cla:02x} INS={ins:02x} P1={p1:02x} P2={p2:02x}', CY, None
        if szBits >= 64:
            return '(encrypted / data)', CC, None
        return f'unknown cmd (0x{b0:02x})', CC, None

    # ===================== CARD -> READER : responses =====================
    # ATQA -- 2 bytes, only right after REQA/WUPA
    if (szBits == 16 and len(data) == 2 and prev_cmd in ('reqa', 'wupa')
            and (data[0] & 0x20) == 0        # byte0 bit5 is RFU (0)
            and (data[0] & 0x1f) != 0        # byte0 must carry a bit-frame SDD bit
            and (data[1] & 0xf0) == 0):       # byte1 high nibble is RFU (0)
        atqa = data[0] | (data[1] << 8)
        return f"ATQA (Answer To Request, Type A) = 0x{atqa:04X}", CG, None
    # UID/anticoll response -- 5 bytes with VALID BCC, only after ANTICOLL
    if szBits == 40 and len(data) == 5 and prev_cmd in ('anticoll1', 'anticoll2', 'anticoll3'):
        u0, u1, u2, u3, bcc = data
        if (u0 ^ u1 ^ u2 ^ u3) == bcc:
            return f"ANTICOLL response: UID={bytes(data[:4]).hex()}  BCC=0x{bcc:02X} (OK)", CG, None
        return raw('BCC fail')
    # SAK -- 1 byte (or 3 on the wire incl. CRC-A), only after a SELECT
    if prev_cmd in ('select1', 'select2', 'select3') and \
            ((szBits == 8 and len(data) == 1) or (szBits == 24 and len(data) == 3)):
        return _sak_desc(data[0]), CG, None
    # ISO-DEP response -- ISO 7816 status word at the tail
    if iso_dep and len(data) >= 2:
        for off in (-2, -4):
            if len(data) >= abs(off):
                lbl = _decode_sw(data[off], data[off + 1])
                if lbl:
                    return f'SW {data[off]:02X} {data[off + 1]:02X}  {lbl}', CY, None
    # large blob (the caller's auth tracker names the specific NT/NR||AR/AT)
    if szBits >= 64:
        return '(encrypted / data)', CC, None
    # nothing matched a plausible response -> show raw, do not invent a label
    return raw()

    # Short frames (7-bit)
    if szBits == 7:
        if b0 == 0x26:
            return 'REQA', CG
        if b0 == 0x52:
            return 'WUPA', CG
        return f'short(0x{b0:02x})', CC

    # Sub-byte noise frames (< 7 bits) — field activation artefacts
    if szBits < 7:
        return f'field noise ({szBits} bit)', CC

    # Anti-collision / Select
    if b0 == 0x93:
        if len(data) > 1 and data[1] == 0x70:
            uid = ' '.join(f'{b:02x}' for b in data[2:6]) if len(data) >= 6 else ''
            return f'SELECT CL1  UID={uid}', CB
        nvb = f'NVB={data[1]:02x}' if len(data) > 1 else ''
        return f'ANTICOLL CL1  {nvb}', CB
    if b0 == 0x95:
        if len(data) > 1 and data[1] == 0x70:
            uid = ' '.join(f'{b:02x}' for b in data[2:6]) if len(data) >= 6 else ''
            return f'SELECT CL2  UID={uid}', CB
        nvb = f'NVB={data[1]:02x}' if len(data) > 1 else ''
        return f'ANTICOLL CL2  {nvb}', CB
    if b0 == 0x97:
        if len(data) > 1 and data[1] == 0x70:
            uid = ' '.join(f'{b:02x}' for b in data[2:6]) if len(data) >= 6 else ''
            return f'SELECT CL3  UID={uid}', CB
        nvb = f'NVB={data[1]:02x}' if len(data) > 1 else ''
        return f'ANTICOLL CL3  {nvb}', CB

    # HALT (0x50 0x00 + CRC — b1 may vary after parity strip)
    if b0 == 0x50:
        return 'HALT', CC

    # S-DESELECT (ISO14443-4 block)
    if b0 == 0xc2:
        return 'S-DESELECT', CC

    # PPS
    if b0 == 0xd0:
        return f'PPS  PPS1={data[1]:02x}' if len(data) > 1 else 'PPS', CC

    # RATS
    if b0 == 0xe0:
        fsdi = (data[1] >> 4) if len(data) > 1 else 0
        cid = (data[1] & 0xf) if len(data) > 1 else 0
        return f'RATS  FSDI={fsdi} CID={cid}', CC

    # MIFARE Classic commands
    if b0 == 0x60:
        return (f'AUTH KeyA  block=0x{data[1]:02X} ({data[1]})' if len(data) > 1 else 'AUTH KeyA'), CR
    if b0 == 0x61:
        return (f'AUTH KeyB  block=0x{data[1]:02X} ({data[1]})' if len(data) > 1 else 'AUTH KeyB'), CR
    # Encrypted nonce / auth response (follows AUTH, first byte varies)
    if szBits == 72:
        return '(encrypted nonce — auth challenge/response)', CC

    if b0 == 0x30:
        return f'READ  block={data[1]}' if len(data) > 1 else 'READ', CC
    if b0 == 0xa0:
        return f'WRITE block={data[1]}' if len(data) > 1 else 'WRITE', CY
    if b0 == 0x40:
        return 'MAGIC WUPC1', CY
    if b0 == 0x43:
        return 'MAGIC WUPC2', CY
    if b0 == 0x41:
        return 'MAGIC WIPE', CR

    # ISO 7816-4 APDUs
    if len(data) >= 2 and b0 in (0x00, 0x80, 0x90, 0xa0):
        cla, ins = data[0], data[1]
        p1 = data[2] if len(data) > 2 else 0
        p2 = data[3] if len(data) > 3 else 0
        # SELECT FILE / AID
        if cla == 0x00 and ins == 0xa4:
            if len(data) > 5:
                aid = ' '.join(f'{b:02x}' for b in data[5:5+data[4]])
                # Identify known AIDs
                aid_raw = bytes(data[5:5+data[4]])
                name = _known_aid(aid_raw)
                label = f'SELECT AID  {aid.upper()}'
                if name:
                    label += f'  ({name})'
                return label, CY
            return 'SELECT', CY
        # READ BINARY
        if cla == 0x00 and ins == 0xb0:
            return f'READ BINARY  off={p1 << 8 | p2} len={data[4] if len(data) > 4 else 0}', CC
        # READ RECORD
        if cla == 0x00 and ins == 0xb2:
            sfi = p2 >> 3
            return f'READ RECORD  SFI={sfi} rec={p1}', CC
        # GET DATA
        if cla == 0x80 and ins == 0xca:
            tag = (p1 << 8) | p2
            name = _known_bertag(tag)
            return f'GET DATA  {p1:02x}{p2:02x}' + (f'  ({name})' if name else ''), CC
        # GET PROCESSING OPTIONS
        if cla == 0x80 and ins == 0xa8:
            return 'GPO  (Get Processing Options)', CY
        # GENERATE AC
        if cla == 0x80 and ins == 0xae:
            actype = {0x00: 'AAC', 0x40: 'TC', 0x80: 'ARQC'}.get(p1 & 0xc0, f'AC/{p1:02x}')
            return f'GENERATE AC  requesting {actype}', CR
        # VERIFY
        if cla == 0x00 and ins == 0x20:
            return 'VERIFY PIN', CY
        # INTERNAL AUTHENTICATE
        if cla == 0x00 and ins == 0x88:
            return 'INTERNAL AUTH', CR
        # EXTERNAL AUTHENTICATE
        if cla == 0x00 and ins == 0x82:
            return 'EXTERNAL AUTH', CR
        # MANAGE CHANNEL
        if cla == 0x00 and ins == 0x70:
            return 'MANAGE CHANNEL', CC
        return f'APDU  CLA={cla:02x} INS={ins:02x} P1={p1:02x} P2={p2:02x}', CY

    # ISO 7816-4 status word — scan last 2 bytes (and last 4 if CRC present)
    sw_label = ''
    for sw_offset in (-2, -4):
        if len(data) >= abs(sw_offset):
            s1, s2 = data[sw_offset], data[sw_offset + 1]
            lbl = _decode_sw(s1, s2)
            if lbl:
                sw_label = f'SW {s1:02X} {s2:02X}  {lbl}'
                break
    if sw_label:
        return sw_label, CY

    # Unknown — show first byte
    return f'unknown (0x{b0:02x})', CC

def _known_aid(aid: bytes) -> str:
    table = {
        bytes.fromhex('a0000000031010'): 'Visa Credit/Debit',
        bytes.fromhex('a0000000032010'): 'Visa Electron',
        bytes.fromhex('a0000000033010'): 'Visa Classic',
        bytes.fromhex('a0000000038010'): 'Visa Plus',
        bytes.fromhex('a0000000041010'): 'Mastercard',
        bytes.fromhex('a0000000043060'): 'Maestro',
        bytes.fromhex('a000000025010801'): 'AmEx',
        bytes.fromhex('a0000000181002'): 'Mastercard Debit',
        bytes.fromhex('d2760000850101'): 'NDEF (NFC Forum)',
        bytes.fromhex('d27600002545'): 'NDEF Type 4',
        bytes.fromhex('315041592e5359532e4444463031'): 'PPSE (2PAY.SYS.DDF01)',
    }
    return table.get(aid, '')


def _known_bertag(tag: int) -> str:
    table = {
        0x9f36: 'ATC',
        0x9f13: 'Last Online ATC',
        0x9f17: 'PIN Try Counter',
        0x9f4f: 'Log Format',
        0x9f4e: 'Merchant Name',
    }
    return table.get(tag, '')


def _extract_sniff_nonces(frames):
    """
    Extract MIFARE Classic auth nonces from a complete frame list (reader + card).

    Walks frames looking for the 3-pass auth pattern:
      1. reader→card  AUTH (0x60/0x61 + block)         -- not is_tx
      2. card→reader  nt  (4 bytes, tag nonce)         -- is_tx
      3. reader→card  {nr}{ar}  (8 bytes)              -- not is_tx

    The current UID is tracked from SELECT (NVB=0x70) reader→card frames.

    Returns a list of dicts: { uid, block, key_type, nt, nr, ar }
    Paired nonces for the same (uid, block, key_type) appear consecutively.
    """
    nonces = []
    uid_hex = None

    for i, frame in enumerate(frames):
        szBits, data, is_tx = frame[0], frame[1], frame[2]  # tolerate an optional 4th (parity) element
        if not data:
            continue

        # Track UID from completed SELECT (NVB=0x70), reader→card
        if (not is_tx
                and data[0] in (0x93, 0x95, 0x97)
                and len(data) >= 6
                and data[1] == 0x70):
            # bytes [2:6] = UID0..UID3; skip cascade byte 0x88 for multi-level UIDs
            if not (data[0] == 0x93 and data[2] == 0x88):
                uid_hex = ''.join(f'{b:02X}' for b in data[2:6])

        # Fallback: extract UID from anticollision response (card→reader, 40 bits).
        # This fires when no SELECT frame is present (common in authtrace captures
        # where hf14a_auth_trace_run synthesises the anticollision exchange).
        if (is_tx
                and szBits == 40
                and len(data) == 5
                and uid_hex is None):
            # 5 bytes = UID[0..3] + BCC; verify BCC
            bcc = data[0] ^ data[1] ^ data[2] ^ data[3]
            if bcc == data[4]:
                uid_hex = ''.join(f'{b:02X}' for b in data[0:4])

        # AUTH command: reader→card, 0x60 (KeyA) or 0x61 (KeyB)
        if not is_tx and data[0] in (0x60, 0x61) and len(data) >= 2:
            key_type = 'A' if data[0] == 0x60 else 'B'
            block = data[1]

            # frame i+1: card→reader, exactly 4 bytes = nt (tag nonce)
            if i + 1 >= len(frames):
                continue
            d1, tx1 = frames[i + 1][1], frames[i + 1][2]
            if not tx1 or len(d1) != 4:
                continue
            nt_hex = ''.join(f'{b:02X}' for b in d1)

            # frame i+2: reader→card, exactly 8 bytes = {nr} || {ar}
            if i + 2 >= len(frames):
                continue
            d2, tx2 = frames[i + 2][1], frames[i + 2][2]
            if tx2 or len(d2) != 8:
                continue
            nr_hex = ''.join(f'{b:02X}' for b in d2[:4])
            ar_hex = ''.join(f'{b:02X}' for b in d2[4:])

            # frame i+3: card→reader, exactly 4 bytes = {at} (tag answer), optional
            at_hex = None
            if i + 3 < len(frames):
                d3, tx3 = frames[i + 3][1], frames[i + 3][2]
                if tx3 and len(d3) == 4:
                    at_hex = ''.join(f'{b:02X}' for b in d3)

            nonces.append({
                'uid':      uid_hex or '00000000',
                'block':    block,
                'key_type': key_type,
                'nt':       nt_hex,
                'nr':       nr_hex,
                'ar':       ar_hex,
                'at':       at_hex,
            })

    return nonces


def _print_14a_sniff_summary(frames):
    """Print a decoded summary of the sniff session."""
    uid_cl1 = None
    uid_cl2 = None
    uid_cl3 = None
    aids = []
    auth_blocks = []   # (key_type, block)
    auth_seen = False
    arqc_seen = False
    tc_seen = False
    halted = False
    rats_seen = False
    atc_tag = None
    amount = None

    for szBits, data, is_tx in frames:
        if not data or is_tx:   # protocol decode uses reader→card frames only
            continue
        b0 = data[0]

        # Extract UID from anticoll frames (NVB != 70 = anticoll, NVB = 70 = select)
        # Anticoll frame with NVB=41 means we're requesting UID bytes
        # The *response* from the tag contains the UID — but we only see reader frames
        # So extract from SELECT (NVB=70) which contains the full UID
        if b0 in (0x93, 0x95, 0x97) and len(data) >= 5 and data[1] == 0x70:
            uid_bytes = bytes(data[2:6])
            if b0 == 0x93:
                if data[2] == 0x88:
                    uid_cl1 = None  # cascade tag, UID continues in CL2
                else:
                    uid_cl1 = uid_bytes
            elif b0 == 0x95:
                uid_cl2 = uid_bytes
            elif b0 == 0x97:
                uid_cl3 = uid_bytes

        # Extract partial UID from anticoll frames — the tag sends back UID bytes
        # We capture the reader's anticoll command which may contain partial UID
        # NVB high nibble = number of full bytes sent, low nibble = bits
        # NVB=41 means reader sent 4 bits, so tag should respond with rest
        # NVB=e1 (225) is unusual — may be tag response captured by NFCT

        # RATS
        if b0 == 0xe0:
            rats_seen = True

        # SELECT AID
        if b0 == 0x00 and len(data) > 5 and data[1] == 0xa4:
            aid = bytes(data[5:5+data[4]])
            name = _known_aid(aid)
            entry = aid.hex().upper()
            if name:
                entry += f'  ({name})'
            if entry not in aids:
                aids.append(entry)

        # MIFARE Classic auth
        if b0 in (0x60, 0x61) and len(data) > 1:
            auth_seen = True
            key_type = 'KeyA' if b0 == 0x60 else 'KeyB'
            block = data[1]
            if (key_type, block) not in auth_blocks:
                auth_blocks.append((key_type, block))

        # GENERATE AC — check AC type
        if b0 == 0x80 and len(data) > 2 and data[1] == 0xae:
            if (data[2] & 0xc0) == 0x80:
                arqc_seen = True
            if (data[2] & 0xc0) == 0x40:
                tc_seen = True

        # GET DATA — ATC
        if b0 == 0x80 and len(data) > 2 and data[1] == 0xca:
            tag = (data[2] << 8) | data[3]
            atc_tag = _known_bertag(tag) or f'{data[2]:02x}{data[3]:02x}'

        # GPO — extract amount if PDOL present
        if b0 == 0x80 and len(data) > 4 and data[1] == 0xa8:
            # Amount is usually first 6 bytes of PDOL data at offset 4+
            if len(data) >= 11:
                amt_bytes = data[5:11]
                amt = int.from_bytes(amt_bytes, 'big')
                if amt > 0:
                    amount = amt

        # HALT / DESELECT
        if b0 == 0x50 or b0 == 0xc2:
            halted = True

    # Build UID from cascade levels
    uid_bytes = None
    if uid_cl1 and uid_cl2:
        uid_bytes = uid_cl1 + uid_cl2
        if uid_cl3:
            uid_bytes = uid_bytes + uid_cl3
    elif uid_cl1:
        uid_bytes = uid_cl1

    # Do NOT attempt to extract UID from anticoll frames (81-bit NVB=e1):
    # those frames are the CU's own emulated tag responding, so the UID
    # would always be the active slot's UID — not useful information.
    # Only report UID when we see a completed SELECT (NVB=70).

    print(f" {'─'*55}")
    if uid_bytes:
        uid_str = ' '.join(f'{b:02X}' for b in uid_bytes)
        cascade = f'  ({len(uid_bytes)}-byte UID)' if uid_bytes else ''
        print(f" {CC}UID      :{C0} {CG}{uid_str}{cascade}{C0}")
    if rats_seen:
        print(f" {CC}Protocol :{C0} ISO14443-4 (RATS seen)")
    for aid in aids:
        print(f" {CC}AID      :{C0} {CY}{aid}{C0}")
    if amount is not None:
        major = amount // 100
        minor = amount % 100
        print(f" {CC}Amount   :{C0} {CG}{major}.{minor:02d}{C0}  (raw={amount})")
    if auth_blocks:
        for key_type, block in auth_blocks:
            print(f" {CC}Auth     :{C0} {CR}MIFARE Classic {key_type} block={block}{C0}")
    elif auth_seen:
        print(f" {CC}Auth     :{C0} {CR}MIFARE Classic auth detected{C0}")
    if arqc_seen:
        print(f" {CC}Auth type:{C0} {CR}ARQC — online authorisation requested{C0}")
    if tc_seen:
        print(f" {CC}Auth type:{C0} {CG}TC — approved offline{C0}")
    if atc_tag:
        print(f" {CC}ATC      :{C0} tag {atc_tag}  (transaction counter)")
    if halted:
        print(f" {CC}End      :{C0} HALT / DESELECT")
    if not uid_bytes and not aids and not auth_seen and not rats_seen:
        print(f" {CC}Note     :{C0} anti-collision incomplete — no SELECT seen (reader could not complete exchange)")

    # ── Nonce cracking ─────────────────────────────────────────────────────
    for line in _nonce_cracking_lines(frames):
        print(line)


def _nonce_cracking_lines(frames) -> list:
    """Nonce extraction + mfkey64/mfkey32v2 cracking attempt, as display
    lines rather than direct prints, so both _print_14a_sniff_summary and
    authtrace_pretty_dump can use it -- the latter builds a string (for -f
    file output) rather than printing directly. auth_seen is recomputed
    here (cheap single-pass scan) rather than threaded in as a parameter,
    so this stays a self-contained, single-argument function.

    Three cases, in order of how little is needed to crack:
      A. Any clean nonce has {at} (the encrypted auth ack) -> mfkey64,
         deterministic from a single auth exchange.
      B. No {at}, but 2+ clean nonces for the same block/key -> mfkey32v2
         across every pair combination; a real key is the candidate common
         to all of them.
      C. Exactly one clean nonce, no {at} -> not yet crackable; show both
         ready-to-fill commands so it's clear what to capture next.
    """
    lines = []
    auth_seen = any(
        (not is_tx) and sz_bits == 32 and len(data) == 4 and data[0] in (0x60, 0x61)
        for sz_bits, data, is_tx in (f[:3] for f in frames)
    )

    nonces = _extract_sniff_nonces(frames)
    if nonces:
        from collections import defaultdict
        groups = defaultdict(list)
        for n in nonces:
            groups[(n['uid'], n['block'], n['key_type'])].append(n)

        lines.append("")
        lines.append(f" {'-'*55}")
        total = sum(len(v) for v in groups.values())
        lines.append(f" {CC}Nonces   :{C0} {total} auth exchange(s) captured")

        for (uid, block, kt), ns in groups.items():
            lines.append(f"   Block {block} Key {kt}  uid={uid}")
            for idx, n in enumerate(ns):
                lines.append(f"     [{idx}] nt={n['nt']}  nr={n['nr']}  ar={n['ar']} at={n['at']}")

            import itertools
            # Case A: any completed auth carries the tag answer {at} (the 4-byte
            # card->reader frame right after {nr}{ar}). mfkey64 is deterministic
            # given the *same* auth's {at} — never the next auth's nt. Only an
            # actual recovered key stops here -- a missing/blocked binary or
            # "no key found" still falls through to offer mfkey32v2 below,
            # rather than leaving a dead end when mfkey64 isn't runnable.
            had_at = False
            found_key = False
            for n in ns:
                if n.get('at'):
                    had_at = True
                    cmd64 = f"mfkey64 {uid} {n['nt']} {n['nr']} {n['ar']} {n['at']}"
                    lines.append(f"     {CC}mfkey64:{C0} {cmd64}")
                    key = _run_mfkey64(uid, n['nt'], n['nr'], n['ar'], n['at'])
                    if key not in (_TOOL_MISSING, _TOOL_BLOCKED, _TOOL_NO_KEY):
                        lines.append(f"     {CG}Key: [{key.upper()}]{C0}")
                        found_key = True
                    elif key == _TOOL_MISSING:
                        lines.append(f"     {CY}mfkey64 binary not found in bin/ — "
                              f"copy the command above and run it manually{C0}")
                    elif key == _TOOL_BLOCKED:
                        lines.append(f"     {CY}mfkey64 could not be executed "
                              f"(antivirus / permissions) — "
                              f"run the command above manually{C0}")
                    else:
                        lines.append(f"     {CR}mfkey64 found no key{C0}")
                    break

            if not found_key:
                if len(ns) >= 2:
                    # Case B: two or more clean nonces for the same block/key,
                    # and mfkey64 either wasn't available or didn't pan out --
                    # offer mfkey32v2 too, over every nonce pair; a real key
                    # shows up as the single candidate common to the pairs.
                    possible_keys = set()
                    for n0, n1 in itertools.combinations(ns, 2):
                        cmd32 = (f"mfkey32v2 {uid} {n0['nt']} {n0['nr']} {n0['ar']}"
                                 f" {n1['nt']} {n1['nr']} {n1['ar']}")
                        lines.append(f"     {CC}mfkey32v2:{C0} {cmd32}")
                        key = _run_mfkey32v2_sniff(n0, n1)
                        if key not in (_TOOL_MISSING, _TOOL_BLOCKED, _TOOL_NO_KEY):
                            possible_keys.add(key.upper())
                        elif key == _TOOL_MISSING:
                            lines.append(f"     {CY}mfkey32v2 binary not found in bin/ — "
                                  f"run the commands above manually{C0}")
                        elif key == _TOOL_BLOCKED:
                            lines.append(f"     {CY}mfkey32v2 could not be executed "
                                  f"(antivirus / permissions) — "
                                  f"run the commands above manually{C0}")
                    if len(possible_keys) == 0:
                        lines.append(f"     {CR}mfkey32v2 found no key — "
                              f"capture more nonce exchanges and retry{C0}")
                    elif len(possible_keys) == 1:
                        lines.append(f"     {CG}Key: [{next(iter(possible_keys))}]{C0}")
                    else:
                        lines.append(f"     {CG}Key candidates: [{', '.join(sorted(possible_keys))}]{C0}")
                else:
                    # One clean nonce triple and no key yet: not crackable from
                    # this alone. Show whichever paths are still open -- the
                    # mfkey64 template only if {at} was never captured
                    # (otherwise the real command and its outcome are already
                    # shown above); mfkey32v2's template always, since a 2nd
                    # nonce isn't in hand yet.
                    n = ns[0]
                    lines.append(f"     {CY}One clean nonce (nt/nr/ar) captured — not yet crackable.{C0}")
                    if not had_at:
                        lines.append(f"     {CC}mfkey64  (add this auth's {{at}}):{C0} "
                              f"mfkey64 {uid} {n['nt']} {n['nr']} {n['ar']} <at>")
                    lines.append(f"     {CC}mfkey32v2 (add a 2nd clean nonce):{C0} "
                          f"mfkey32v2 {uid} {n['nt']} {n['nr']} {n['ar']} <nt2> <nr2> <ar2>")

    elif auth_seen:
        # Reader-side auth was captured but no clean nonce survived — the
        # card-side NT came back garbled. Say so, so it's clear the reader path
        # works and only the RC522 NT capture is the blocker.
        n_auth = sum(1 for _szb, _d, _tx in (f[:3] for f in frames)
                     if (not _tx) and _szb == 32 and len(_d) == 4 and _d[0] in (0x60, 0x61))
        lines.append("")
        lines.append(f" {'-'*55}")
        lines.append(f" {CC}Nonces   :{C0} {CY}{n_auth} AUTH captured, but every card nonce (NT) "
              f"came back garbled{C0}")
        lines.append(f"   Reader side is clean (AUTH + NR||AR present); the RC522 is mangling")
        lines.append(f"   the 4-byte NT. One clean 32-bit NT in the frame right after an AUTH")
        lines.append(f"   is all that's needed to crack.")

    return lines


# Sample period of the last `lf sniff` capture, in microseconds. 8 for a
# normal (field-managed, 125kHz) capture; 6 for a --passive (TIMER3,
# 166.67kHz) capture. Set by cli_lf.py's LFSniff on every successful sniff.
_last_capture_rate_us = 8


def _get_capture():
    """Return last capture buffer or print error."""
    import chameleon_cli_unit as _m
    if not _m._last_capture:
        return None
    return _m._last_capture


def _get_capture_rate_us():
    """Return the sample period (µs) of the last capture."""
    import chameleon_cli_unit as _m
    return getattr(_m, '_last_capture_rate_us', 8)


@data.command('pm3import')
class DataPm3Import(BaseCLIUnit):
    """Import a Proxmark3 .trace file and decode it with CU's own 14A
    annotator (ANTICOLL/SELECT/AUTH/HALT, NT/NR||AR/AT nonce tracking,
    parity-flagged hex) -- the reverse of `standalone get-result --pm3`.

    Works offline: no device connection needed, and the file doesn't have
    to have come from CU originally -- any genuine PM3 trace (`trace save`)
    parses the same way, since this reads the real tracelog_hdr_t layout.
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Import and decode a Proxmark3 .trace file (offline, no device needed)'
        parser.add_argument('file', type=str, metavar='<path>',
                            help='Proxmark3 .trace file (from `trace save` or CU\'s --pm3 export)')
        parser.add_argument('--json', action='store_true',
                            help='emit the parsed frames as JSON instead of a pretty dump')
        return parser

    def on_exec(self, args: argparse.Namespace):
        import pm3_trace
        try:
            frames = pm3_trace.pm3_trace_file_to_frames(args.file)
        except OSError as e:
            print(color_string((CR, f"Could not read {args.file}: {e}")))
            return

        if not frames:
            print(color_string((CR, f"No frames parsed from {args.file} -- "
                                     "not a recognizable PM3 .trace, or empty")))
            return

        if args.json:
            import json as jsonlib
            recs = [
                {"bits": sz, "data": data.hex(), "is_tx": is_tx,
                 "parity": parity}
                for sz, data, is_tx, parity in frames
            ]
            print(jsonlib.dumps(recs, indent=2))
            return

        sessions = [{
            "session_num": 0,
            "status_name": "imported",
            "frames": frames,
        }]
        print(f" Imported : {color_string((CG, args.file))}  ({len(frames)} frame(s))")
        print(authtrace_pretty_dump(sessions))


@data.command('hexsamples')
class DataHexsamples(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Dump last LF sniff capture as hex bytes (PM3 style)'
        parser.add_argument('-n', '--num', type=int, default=512, metavar='N',
                            help='Number of bytes to display (default: 512)')
        return parser

    def on_exec(self, args: argparse.Namespace):
        buf = _get_capture()
        if buf is None:
            print(f"{CR}No capture in buffer — run lf sniff first{C0}")
            return
        n = min(args.num, len(buf))
        print(f" Buffer: {CG}{len(buf)}{C0} bytes total, showing {n}")
        print()
        for row in range(0, n, 16):
            chunk = buf[row:row+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        bar = ''
        for b in chunk:
            if b < 0x10:
                bar += '_'
            elif b < 0x40:
                bar += '.'
            elif b < 0x80:
                bar += '-'
            elif b < 0xa0:
                bar += '+'
            elif b < 0xc0:
                bar += 'o'
            elif b < 0xe0:
                bar += 'O'
            else:
                bar += '#'
        print(f" {row // 16:02d} | {hex_part:<47s} | {bar}")
        print()
        print(" _ gap  . ringing  - low  + mid  o carrier  O high  # clipped")


@data.command('plot')
class DataPlot(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Graphical waveform plot of last LF sniff capture (PyQt5 or matplotlib)'
        parser.add_argument('--start', type=int, default=0, metavar='N',
                            help='Start sample (default: 0)')
        parser.add_argument('--len', type=int, default=4000, metavar='N',
                            help='Number of samples to plot (default: all)')
        parser.add_argument('--ascii', action='store_true',
                            help='Force ASCII plot even if GUI is available')
        return parser

    def on_exec(self, args: argparse.Namespace):
        buf = _get_capture()
        if buf is None:
            print(f"{CR}No capture in buffer — run lf sniff first{C0}")
            return

        start = max(0, args.start)
        end = min(len(buf), start + args.len)
        view = list(buf[start:end])
        n = len(view)

        rate_us = _get_capture_rate_us()
        xs = [((start + i) * rate_us) for i in range(n)]

        mean = sum(view) // n
        threshold = mean // 2

        if not args.ascii:
            # Try PyQt5 first, then matplotlib
            try:
                from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget
                from PyQt5.QtCore import Qt
                import pyqtgraph as pg
                _plot_pyqtgraph(xs, view, mean, threshold, start, end)
                return
            except ImportError:
                pass
            try:
                import matplotlib
                matplotlib.use('Qt5Agg')
                import matplotlib.pyplot as plt
                _plot_matplotlib(xs, view, mean, threshold, start, end)
                return
            except ImportError:
                pass
            try:
                import matplotlib.pyplot as plt
                _plot_matplotlib(xs, view, mean, threshold, start, end)
                return
            except ImportError:
                print(" No GUI library found (install PyQt5+pyqtgraph or matplotlib)")
                print(" Falling back to ASCII plot...")

        # ASCII fallback
        w = 64
        bsize = max(1, n // w)
        buckets = []
        for i in range(0, n, bsize):
            chunk = view[i:i+bsize]
            buckets.append(sum(chunk) // len(chunk))
        buckets = buckets[:w]
        mn, mx = min(view), max(view)
        print(f" Samples {start}–{end}  range 0x{mn:02x}–0x{mx:02x}  mean 0x{mean:02x}")
        print()
        levels = [0xe0, 0xc0, 0xa0, 0x80, 0x60, 0x40, 0x20, 0x00]
        labels = ['0xff', '0xc0', '0xa0', '0x80', '0x60', '0x40', '0x20', '0x00']
        for thresh, lbl in zip(levels, labels):
            row = ''.join('#' if v >= thresh else ' ' for v in buckets)
            print(f" {lbl} |{row}|")
        print(f"        +{'-'*len(buckets)}+")


def _plot_matplotlib(xs, ys, mean, threshold, start, end):
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches

    fig, ax = plt.subplots(figsize=(14, 5))
    fig.patch.set_facecolor('#1a1a2e')
    ax.set_facecolor('#0d1117')

    # Main waveform
    ax.plot(xs, ys, color='#00e5ff', linewidth=0.8, label='LF field')

    # Mean and gap threshold lines
    ax.axhline(mean,      color='#ffb020', linewidth=0.8, linestyle='--', label=f'mean 0x{mean:02x}')
    ax.axhline(threshold, color='#ff3d57', linewidth=0.8, linestyle=':',  label=f'gap threshold 0x{threshold:02x}')

    # Shade gap regions
    in_gap = False
    gap_start = 0
    for i, v in enumerate(ys):
        if not in_gap and v < threshold:
            in_gap = True
            gap_start = xs[i]
        elif in_gap and v >= threshold:
            ax.axvspan(gap_start, xs[i], alpha=0.25, color='#ff3d57', linewidth=0)
            in_gap = False
    if in_gap:
        ax.axvspan(gap_start, xs[-1], alpha=0.25, color='#ff3d57', linewidth=0)

    ax.set_xlabel('Time (µs)', color='#8899b4')
    ax.set_ylabel('ADC value', color='#8899b4')
    ax.set_title(f'LF Sniff — samples {start}–{end}  ({(end-start)*8}µs)',
                 color='#dde8f5', fontsize=11)
    ax.set_ylim(0, 270)
    ax.set_xlim(xs[0], xs[-1])
    ax.tick_params(colors='#8899b4')
    for spine in ax.spines.values():
        spine.set_edgecolor('#21262d')
    ax.legend(facecolor='#161b22', edgecolor='#30363d', labelcolor='#c9d1d9',
              fontsize=8, loc='upper right')
    ax.grid(True, color='#21262d', linewidth=0.5)

    gap_patch = mpatches.Patch(color='#ff3d57', alpha=0.4, label='field gap')
    handles, labels = ax.get_legend_handles_labels()
    ax.legend(handles + [gap_patch], labels + ['field gap'],
              facecolor='#161b22', edgecolor='#30363d',
              labelcolor='#c9d1d9', fontsize=8, loc='upper right')

    plt.tight_layout()
    plt.show()


def _plot_pyqtgraph(xs, ys, mean, threshold, start, end):
    import sys
    from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel
    from PyQt5.QtCore import Qt
    from PyQt5.QtGui import QFont
    import pyqtgraph as pg

    pg.setConfigOption('background', '#0d1117')
    pg.setConfigOption('foreground', '#8899b4')

    app = QApplication.instance() or QApplication(sys.argv)

    win = pg.GraphicsLayoutWidget(title='ChameleonUltra — LF Sniff')
    win.resize(1200, 400)
    win.setWindowTitle(f'LF Sniff — samples {start}–{end}  ({(end-start)*8}µs)')

    plot = win.addPlot()
    plot.setLabel('bottom', 'Time (µs)')
    plot.setLabel('left', 'ADC value')
    plot.showGrid(x=True, y=True, alpha=0.2)
    plot.setYRange(0, 270)

    # Waveform
    plot.plot(xs, ys, pen=pg.mkPen('#00e5ff', width=1))

    # Mean line
    plot.addLine(y=mean,      pen=pg.mkPen('#ffb020', width=1, style=pg.QtCore.Qt.DashLine))
    # Gap threshold line
    plot.addLine(y=threshold, pen=pg.mkPen('#ff3d57', width=1, style=pg.QtCore.Qt.DotLine))

    # Shade gaps
    for i in range(len(ys)-1):
        if ys[i] < threshold:
            r = pg.LinearRegionItem([xs[i], xs[i+1]],
                                    brush=pg.mkBrush(255, 61, 87, 40),
                                    pen=pg.mkPen(None), movable=False)
            plot.addItem(r)

    # Legend / info panel
    legend_text = (
        '<span style="color:#8899b4; font-size:11px;">'
        '<span style="color:#00e5ff;">━</span> LF field (ADC)&nbsp;&nbsp;'
        '<span style="color:#ffb020;">- -</span> Mean&nbsp;&nbsp;'
        '<span style="color:#ff3d57;">···</span> Gap threshold (mean÷2)&nbsp;&nbsp;'
        '<span style="background:#ff3d57; opacity:0.3;">&nbsp;&nbsp;&nbsp;</span>'
        ' Field gap (below threshold)&nbsp;&nbsp;'
        '<span style="color:#8899b4;">Ringing = exponential rise on field restore</span>'
        '</span>'
    )
    legend = pg.LabelItem(legend_text, justify='left')
    win.addItem(legend, row=1, col=0)

    win.show()
    app.exec_()


@data.command('manrawdecode')
class DataManrawdecode(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Manchester decode the last LF sniff capture'
        parser.add_argument('--clock', type=int, default=64, metavar='N',
                            help='Clock divisor in Tc (default: 64 = RF/64)')
        parser.add_argument('--invert', action='store_true',
                            help='Invert logic (high=0, low=1)')
        return parser

    def on_exec(self, args: argparse.Namespace):
        buf = _get_capture()
        if buf is None:
            print(f"{CR}No capture in buffer — run lf sniff first{C0}")
            return

        # Binarise: above mean = 1 (carrier), below = 0 (gap)
        mean = sum(buf) // len(buf)
        threshold = mean // 2
        bits_raw = [1 if b > threshold else 0 for b in buf]
        if args.invert:
            bits_raw = [1 - b for b in bits_raw]

        # Find transitions and measure run lengths
        runs = []
        cur = bits_raw[0]
        count = 1
        for b in bits_raw[1:]:
            if b == cur:
                count += 1
            else:
                runs.append((cur, count))
                cur = b
                count = 1
        runs.append((cur, count))

        # Clock period in samples (1 sample = 8µs)
        half_clk = args.clock // 2  # samples per half-bit

        # Decode Manchester: half-bit transitions
        # Low->High = 0, High->Low = 1 (standard Manchester)
        decoded_bits = []
        tol = max(2, half_clk // 3)

        i = 0
        while i < len(runs):
            val, cnt = runs[i]
            # Short run = half period, long run = full period
            half = abs(cnt - half_clk) <= tol
            full = abs(cnt - args.clock) <= tol
            if half:
                # need next run to complete bit
                if i + 1 < len(runs):
                    nval, ncnt = runs[i+1]
                    nhalf = abs(ncnt - half_clk) <= tol
                    if nhalf:
                        # two halves: transition val->nval
                        if val == 0 and nval == 1:
                            decoded_bits.append(0)
                        elif val == 1 and nval == 0:
                            decoded_bits.append(1)
                        i += 2
                        continue
            elif full:
                # biphase / stay same level for full period = repeated bit
                decoded_bits.append(val)
            i += 1

        if not decoded_bits:
            print(f"{CR}No bits decoded — check clock rate or signal quality{C0}")
            print(f" Mean threshold: 0x{threshold:02x}  Clock: RF/{args.clock}")
            return

        bits_str = ''.join(str(b) for b in decoded_bits)
        hex_str = hex(int(bits_str, 2))[2:] if decoded_bits else ''

        rate_us = _get_capture_rate_us()
        print(f" Clock    : RF/{args.clock}  ({args.clock} Tc = {args.clock*rate_us}µs/bit)")
        print(f" Threshold: 0x{threshold:02x}  Inverted: {args.invert}")
        print(f" Bits     : {CG}{len(decoded_bits)}{C0}")
        print()
        # Print in rows of 64
        for i in range(0, len(bits_str), 64):
            print(f"  {bits_str[i:i+64]}")
        if hex_str:
            print()
            print(f" Hex: {CG}{hex_str[:64]}{C0}{'...' if len(hex_str) > 64 else ''}")


@data.command('modulation')
class DataModulation(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Detect clock rate and modulation type in last LF capture'
        return parser

    def on_exec(self, args: argparse.Namespace):
        buf = _get_capture()
        if buf is None:
            print(f"{CR}No capture in buffer — run lf sniff first{C0}")
            return

        n = len(buf)
        mean = sum(buf) // n
        mn = min(buf)
        mx = max(buf)
        threshold = mean // 2

        rate_us = _get_capture_rate_us()
        print(f" Samples  : {CG}{n}{C0}  ({n*rate_us}µs)")
        print(f" Range    : 0x{mn:02x} – 0x{mx:02x}  mean: 0x{mean:02x}")
        print()

        # Check if there is any modulation at all
        dynamic_range = mx - mn
        if dynamic_range < 0x20:
            print(f" Modulation: {CR}none — flat carrier (no signal){C0}")
            return

        # Binarise
        bits = [1 if b > threshold else 0 for b in buf]

        # Measure run lengths (periods between transitions)
        runs = []
        cur = bits[0]
        count = 1
        for b in bits[1:]:
            if b == cur:
                count += 1
            else:
                runs.append(count)
                cur = b
                count = 1

        runs.append(count)

        if len(runs) < 4:
            print(f" Modulation: {CR}insufficient transitions{C0}")
            return

        runs_sorted = sorted(runs)
        # Remove outliers (top/bottom 10%)
        trim = max(1, len(runs) // 10)

        # Estimate clock: most common run length = half-period
        from collections import Counter
        run_counts = Counter(runs)
        most_common_run = run_counts.most_common(1)[0][0]

        # Map to nearest standard RF divider
        half_samples = most_common_run
        full_period_us = half_samples * 2 * rate_us

        rf_dividers = [8, 16, 32, 40, 50, 64, 100, 128]
        tc_us = rate_us  # 1 Tc = 1 sample period
        best_div = min(rf_dividers, key=lambda d: abs(d*tc_us - full_period_us))

        print(f" Half-period : ~{most_common_run} samples = {most_common_run*rate_us}µs")
        print(f" Full period : ~{full_period_us}µs")
        print(f" Nearest RF  : {CG}RF/{best_div}{C0}  ({best_div*tc_us}µs/bit)")
        print()

        # Modulation type heuristic
        # Manchester: runs cluster around 1 value (half period) and 2x that (full period)
        # ASK/NRZ: long runs of same value
        # FSK: two distinct run lengths alternating

        unique_runs = set(runs)
        long_runs = [r for r in runs if r > most_common_run * 3]

        # Manchester has runs clustering at N and 2N (half and full period)
        # Check if second most common run is ~2x the most common
        tol = max(2, most_common_run // 3)
        top2 = run_counts.most_common(2)
        is_manchester = (len(top2) >= 2 and
                         abs(top2[1][0] - most_common_run * 2) <= tol)

        if len(long_runs) > len(runs) * 0.3:
            mod = "ASK / NRZ (long steady periods)"
            col = CG
        elif is_manchester:
            mod = f"Manchester (RF/{best_div})"
            col = CG
        elif len(unique_runs) <= 4:
            mod = f"Biphase (RF/{best_div})"
            col = CG
        else:
            mod = "FSK or mixed (multiple run lengths)"
            col = CG

        print(f" Modulation : {col}{mod}{C0}")

        # Gap detection
        gap_threshold = mean // 2
        gaps = [i for i, b in enumerate(buf[200:]) if b < gap_threshold]

        if gaps:
            print(f" RTF gaps   : {CG}{len(gaps)}{C0} samples below 0x{gap_threshold:02x}"
                  f" ^`^t gap commands present")
        else:
            print(f" RTF gaps   : {CR}none ^`^t no gap commands detected{C0}")


# ============================================================================
# EMV contactless payment card commands  (emv subgroup)
# ============================================================================

def _emv_decode_apdu(data: bytes) -> str:
    """Return a brief human-readable description of a command APDU."""
    if len(data) < 4:
        return ''
    cla, ins, p1, p2 = data[0], data[1], data[2], data[3]
    lc = data[4] if len(data) > 4 else 0
    body = data[5:5 + lc] if len(data) > 5 else b''
    if cla == 0x00 and ins == 0xA4 and p1 == 0x04 and body:
        known = {
            bytes.fromhex('325041592e5359532e4444463031'): 'PPSE (2PAY.SYS.DDF01)',
            bytes.fromhex('a0000000031010'): 'Visa Credit/Debit',
            bytes.fromhex('a0000000041010'): 'Mastercard Debit',
            bytes.fromhex('a000000025010402'): 'Amex',
        }
        return 'SELECT AID  ' + known.get(body.lower(), body.hex().upper())
    if cla == 0x80 and ins == 0xA8:
        return 'GET PROCESSING OPTIONS (GPO)'
    if cla == 0x00 and ins == 0xB2:
        return f'READ RECORD  SFI={(p2 >> 3) & 0x1F}  rec={p1}'
    return f'CLA={cla:02x} INS={ins:02x} P1={p1:02x} P2={p2:02x}'


@emv.command('scan')
class EMVScan(DeviceRequiredUnit):
    """
    Full EMV contactless card scan — equivalent to PM3 'emv scan -at'.

    Scans an ISO14443-4 card, performs the full EMV transaction sequence
    (SELECT PPSE, SELECT AID, GPO, READ RECORDs) and saves results to a
    JSON file compatible with PM3's emv scan output format.

    Place the card on the CU antenna before running.

    Usage:
        emv scan                   print results to terminal
        emv scan -f /tmp/card.json save to JSON file
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'EMV contactless card scan (reader mode) — like PM3 emv scan -at'
        parser.add_argument('-f', '--file', default='', metavar='<path>',
                            help='Save results to JSON file (PM3-compatible format)')
        parser.add_argument('-s', '--slot', type=int, default=None,
                            metavar='<1-8>', help='Also load scanned card into this slot for emulation')
        return parser

    def on_exec(self, args: argparse.Namespace):
        import time
        import json as jsonlib
        cmd = self.cmd

        # Ensure reader mode
        try:
            if not cmd.is_device_reader_mode():
                cmd.set_device_reader_mode(True)
                time.sleep(0.5)
        except Exception:
            time.sleep(0.3)

        print(f' {CY}Scanning... (place card on antenna) [fw-canary:v5]{C0}')

        # Single firmware call — full EMV sequence without USB round-trips
        resp = cmd.hf14a_4_emv_scan()
        if resp.status != Status.HF_TAG_OK or not resp.data:
            print(f' {CR}No card found or scan failed (status={resp.status}){C0}')
            return

        # Parse packed response
        d = bytes(resp.data)
        off = 0

        uid_len = d[off]
        off += 1
        uid = d[off:off+uid_len]
        off += uid_len
        atqa = d[off:off+2]
        off += 2
        sak = d[off]
        off += 1
        ats_len = d[off]
        off += 1
        ats = d[off:off+ats_len]
        off += ats_len

        uid_str = ' '.join(f'{b:02X}' for b in uid)
        atqa_str = ' '.join(f'{b:02X}' for b in atqa)
        ats_str = ' '.join(f'{b:02X}' for b in ats)
        print(f' {CG}UID : {uid_str}{C0}')
        print(f' {CG}ATQA: {atqa_str}  SAK: {sak:02X}{C0}')
        print(f' {CG}ATS : {ats_str}{C0}')

        num_apdus = d[off]
        off += 1
        pairs = []
        for _ in range(num_apdus):
            cl = d[off]
            off += 1
            c = d[off:off+cl]
            off += cl
            rl = d[off] | (d[off+1] << 8)
            off += 2
            r = d[off:off+rl]
            off += rl
            pairs.append((c, r))

        if not pairs:
            print(f' {CR}No APDU responses captured{C0}')
            return
        result = {}
        result['File'] = {'Created': 'chameleon emv scan'}
        result['Card'] = {'Contactless': {
            'Communication': 'iso14443-4a',
            'UID':  uid_str, 'ATQA': atqa_str,
            'SAK':  f'{sak:02X}', 'ATS': ats_str,
        }}

        def tlv_to_dict(data):
            if not data:
                return {}
            i = 0
            tl = 2 if (data[i] & 0x1F) == 0x1F else 1
            tag_hex = data[:tl].hex().upper()
            i += tl
            if i >= len(data):
                return {}
            if data[i] & 0x80:
                nb = data[i] & 0x7F
                i += 1
                vlen = int.from_bytes(data[i:i+nb], 'big')
                i += nb
            else:
                vlen = data[i]
                i += 1
            val = data[i:i+vlen]
            return {'tag': tag_hex, 'length': f'{vlen:02X}',
                    'value': ' '.join(f'{b:02X}' for b in val)}

        def find_tag(data, tag):
            results = []
            i = 0
            while i < len(data) - 1:
                tl = 2 if (data[i] & 0x1F) == 0x1F else 1
                if i + tl > len(data):
                    break
                cur = data[i:i+tl]
                i += tl
                if i >= len(data):
                    break
                if data[i] & 0x80:
                    nb = data[i] & 0x7F
                    i += 1
                    vlen = int.from_bytes(data[i:i+nb], 'big')
                    i += nb
                else:
                    vlen = data[i]
                    i += 1
                val = data[i:i+vlen]
                i += vlen
                if int.from_bytes(cur, 'big') == tag:
                    results.append(val)
                elif cur[0] & 0x20:
                    results.extend(find_tag(val, tag))
            return results

        # PPSE
        if pairs:
            ppse_cmd, ppse_resp = pairs[0]
            ppse_body = ppse_resp[:-2] if len(ppse_resp) >= 2 else ppse_resp
            print(f'\n {CG}PPSE OK ({len(ppse_resp)}b){C0}')
            result['PPSE'] = {
                'AID': '32 50 41 59 2E 53 59 53 2E 44 44 46 30 31',
                'FCITemplate': tlv_to_dict(ppse_body),
            }

        if len(pairs) >= 2:
            sel_cmd, sel_resp = pairs[1]
            sel_body = sel_resp[:-2] if len(sel_resp) >= 2 else sel_resp
            aid_bytes = sel_cmd[5:-1] if len(sel_cmd) > 6 else b''
            aid_str = ' '.join(f'{b:02X}' for b in aid_bytes)
            print(f' {CG}SELECT AID OK ({len(sel_resp)}b){C0}')
            result['Application'] = {'AID': aid_str,
                                     'FCITemplate': tlv_to_dict(sel_body)}

        if len(pairs) >= 3:
            gpo_cmd, gpo_resp = pairs[2]
            gpo_body = gpo_resp[:-2] if len(gpo_resp) >= 2 else gpo_resp
            print(f' {CG}GPO OK ({len(gpo_resp)}b){C0}')
            result['Application']['GPO'] = tlv_to_dict(gpo_body)
            records = []
            for cb, rb in pairs[3:]:
                sfi_n = (cb[3] >> 3) & 0x1F if len(cb) >= 4 else 0
                rec_n = cb[2] if len(cb) >= 3 else 0
                r_body = rb[:-2] if len(rb) >= 2 else rb
                print(f' {CG}READ RECORD SFI={sfi_n} rec={rec_n} OK ({len(rb)}b){C0}')
                records.append({'SFI': f'{sfi_n:02X}', 'RecordNum': f'{rec_n:02X}',
                                'Offline': '01', 'Data': tlv_to_dict(r_body)})
            result['Application']['Records'] = records

        # ---- Decode and display key card fields from EMV records --------
        def _pan_luhn(pan: str) -> bool:
            digits = [int(c) for c in pan if c.isdigit()]
            digits.reverse()
            total = sum(d if i % 2 == 0 else (d * 2 - 9 if d * 2 > 9 else d * 2)
                        for i, d in enumerate(digits))
            return total % 10 == 0

        def _find_tag_all(data: bytes, *tags: int):
            """Recursively find all values for any of the given tags."""
            results = {}
            for t in tags:
                results[t] = []
            i = 0
            while i < len(data) - 1:
                tl = 2 if (data[i] & 0x1F) == 0x1F else 1
                if i + tl > len(data):
                    break
                cur_tag = int.from_bytes(data[i:i+tl], 'big')
                i += tl
                if i >= len(data):
                    break
                if data[i] & 0x80:
                    nb = data[i] & 0x7F
                    i += 1
                    vlen = int.from_bytes(data[i:i+nb], 'big')
                    i += nb
                else:
                    vlen = data[i]
                    i += 1
                val = data[i:i+vlen]
                i += vlen
                if cur_tag in results:
                    results[cur_tag].append(val)
                # recurse into constructed TLV
                if data[i - vlen - (1 if vlen < 128 else 2)] & 0x20 if False else (data[i - vlen - 1] & 0x20 if vlen < 128 else False):
                    sub = _find_tag_all(val, *tags)
                    for t in tags:
                        results[t].extend(sub[t])
            return results

        # Simpler recursive TLV walker
        def tlv_find(data: bytes, *want_tags: int) -> dict:
            found = {t: [] for t in want_tags}
            i = 0
            while i < len(data):
                if i + 1 >= len(data):
                    break
                b0 = data[i]
                tl = 2 if (b0 & 0x1F) == 0x1F else 1
                if i + tl > len(data):
                    break
                tag = int.from_bytes(data[i:i+tl], 'big')
                i += tl
                if i >= len(data):
                    break
                constructed = bool(b0 & 0x20)
                if data[i] & 0x80:
                    nb = data[i] & 0x7F
                    i += 1
                    if i + nb > len(data):
                        break
                    vlen = int.from_bytes(data[i:i+nb], 'big')
                    i += nb
                else:
                    vlen = data[i]
                    i += 1
                # For truncated TLV: read whatever bytes are available and
                # continue parsing — don't break, so we can find tags inside
                # truncated constructed TLV (e.g. 6F/A5 larger than received data)
                truncated = (i + vlen > len(data))
                val = data[i:i+vlen] if not truncated else data[i:]
                i = (i + vlen) if not truncated else len(data)
                if tag in found and not truncated:
                    found[tag].append(val)
                if constructed:
                    sub = tlv_find(val, *want_tags)
                    for t in want_tags:
                        found[t].extend(sub[t])
            return found

        # Collect all response bodies for tag search.
        # tlv_to_dict stores the VALUE (content) of the outermost tag —
        # so rec['Data']['value'] is already the unwrapped inner bytes.
        all_record_data = b''
        for rec in result.get('Application', {}).get('Records', []):
            raw_hex = rec.get('Data', {}).get('value', '')
            try:
                all_record_data += bytes.fromhex(raw_hex.replace(' ', ''))
            except Exception:
                pass
        # Also include GPO and SELECT AID FCI values for label/name tags
        extra_data = b''
        for key in ('GPO', 'FCITemplate'):
            v = result.get('Application', {}).get(key, {})
            if isinstance(v, dict):
                try:
                    extra_data += bytes.fromhex(v.get('value', '').replace(' ', ''))
                except Exception:
                    pass
        all_search_data = all_record_data + extra_data

        # EMV tag definitions:
        # 0x5A  = PAN
        # 0x5F24 = Expiry Date (YYMMDD)
        # 0x5F20 = Cardholder Name
        # 0x5F28 = Issuer Country Code
        # 0x8C / 0x8D = CDOL — skip
        # 0x9F12 = Application Preferred Name
        # 0x50   = Application Label
        tags = tlv_find(all_record_data, 0x5A, 0x57, 0x5F24, 0x5F20, 0x5F28)
        app_tags = tlv_find(all_search_data, 0x9F12, 0x50)
        tags[0x9F12] = app_tags[0x9F12]
        tags[0x50] = app_tags[0x50]

        print(f'')
        print(f' {CG}── Card Details ──────────────────────{C0}')

        # App label — show first unique label only
        seen_labels = set()
        for v in tags.get(0x50, []) + app_tags.get(0x50, []):
            try:
                lbl = v.decode('ascii', errors='replace').strip()
                if lbl and lbl not in seen_labels:
                    seen_labels.add(lbl)
                    print(f' {CG}App Label     :{C0} {CY}{lbl}{C0}')
            except Exception:
                pass

        # PAN — prefer Track2 D-separator (authoritative, no padding ambiguity)
        pan_hex = None
        for v in tags.get(0x57, []):
            t2 = v.hex().upper()
            sep = t2.find('D')
            if sep > 0:
                pan_hex = t2[:sep]
                break
        if not pan_hex:
            for v in tags.get(0x5A, []):
                raw = v.hex().upper()
                pan_hex = raw.rstrip('F') if raw.endswith('F') else raw
                break
        if pan_hex:
            pan_fmt = ' '.join(pan_hex[i:i+4] for i in range(0, len(pan_hex), 4))
            luhn_ok = _pan_luhn(pan_hex)
            luhn_str = f'{CG}✓{C0}' if luhn_ok else f'{CR}✗{C0}'
            print(f' {CG}PAN           :{C0} {CY}{pan_fmt}{C0}  Luhn: {luhn_str}')
            result.setdefault('Decoded', {})['PAN'] = pan_hex
        else:
            print(f' {CR}PAN           : not found{C0}')

        # Expiry — 5F24 is 3 bytes BCD: YYMMDD
        expiry_found = False
        for v in tags.get(0x5F24, []):
            if len(v) == 3:
                exp = v.hex().upper()
                exp_fmt = f'20{exp[0:2]}/{exp[2:4]}'
                print(f' {CG}Expiry        :{C0} {CY}{exp_fmt}{C0}')
                result.setdefault('Decoded', {})['Expiry'] = exp_fmt
                expiry_found = True
        # Fallback: extract expiry from Track2 after D separator (YYMM)
        if not expiry_found and pan_hex:
            for v in tags.get(0x57, []):
                t2 = v.hex().upper()
                sep = t2.find('D')
                if sep > 0 and len(t2) >= sep + 5:
                    yymm = t2[sep+1:sep+5]
                    if yymm.isdigit():
                        exp_fmt = f'20{yymm[0:2]}/{yymm[2:4]}'
                        print(f' {CG}Expiry        :{C0} {CY}{exp_fmt}{C0} (from Track2)')
                        result.setdefault('Decoded', {})['Expiry'] = exp_fmt
                        expiry_found = True
                        break
        if not expiry_found:
            print(f' {CR}Expiry        : not found{C0}')

        # Cardholder Name (tag 5F20: printable ASCII only)
        for v in tags[0x5F20]:
            try:
                if v and all(0x20 <= b <= 0x7E for b in v):
                    name = v.decode('ascii').strip()
                    if name:
                        print(f' {CG}Cardholder    :{C0} {CY}{name}{C0}')
                        result.setdefault('Decoded', {})['CardholderName'] = name
            except Exception:
                pass

        # Issuer Country Code (ISO 3166-1 numeric, BCD) -> add the country name
        for v in tags[0x5F28]:
            country = v.hex().upper().lstrip('0') or '0'
            try:
                # EMV 5F28 is pure ISO 3166-1 numeric. Use the ISO table only --
                # not the FDX-B code namer, which labels 900+ as manufacturer/
                # test-transponder codes that never occur on an EMV card.
                name = ISO3166_NUMERIC.get(int(country))
            except ValueError:
                name = None
            shown = f'{country} ({name})' if name else country
            print(f' {CG}Issuer Country:{C0} {CY}{shown}{C0}')
            dec = result.setdefault('Decoded', {})
            dec['IssuerCountry'] = country
            if name:
                dec['IssuerCountryName'] = name

        # Application Preferred Name (9F12) — only if different from label
        for v in tags[0x9F12]:
            try:
                name = v.decode('ascii', errors='replace').strip()
                if name and name not in seen_labels:
                    print(f' {CG}App Name      :{C0} {CY}{name}{C0}')
            except Exception:
                pass

        print(f' {CG}──────────────────────────────────────{C0}')

        json_str = jsonlib.dumps(result, indent=2)
        if args.file:
            try:
                with open(args.file, 'w') as fp:
                    fp.write(json_str)
                print(f'\n {CG}Saved to {args.file}{C0}')
            except Exception as e:
                print(f' {CR}Save failed: {e}{C0}')
        else:
            print(f'\n{json_str}')

        if args.slot is not None and pairs:
            target_slot = SlotNumber(args.slot)
            print(f'\n {CY}Loading into slot {target_slot}...{C0}')
            try:
                cmd.set_slot_tag_type(target_slot, TagSpecificType.HF14A_4)
                cmd.set_slot_data_default(target_slot, TagSpecificType.HF14A_4)
                cmd.set_slot_enable(target_slot, TagSenseType.HF, True)
                cmd.hf14a_4_set_anti_coll(uid, atqa, sak, ats)  # atqa already in wire order
                cmd.hf14a_4_clear_static_responses()
                for c, r in pairs:
                    cmd.hf14a_4_add_static_response(c, r)  # use full cmd as match key
                cmd.slot_data_config_save()
                print(f' {CG}Slot {target_slot} ready. Run: hw slot change -s {args.slot} && hw mode -e{C0}')
            except Exception as e:
                print(f' {CR}Slot load failed: {e}{C0}')


@emv.command('debug')
class EMVDebug(DeviceRequiredUnit):
    """Show T=CL emulation debug counters (I-blocks rx/tx, last PCB, last match)."""

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Show T=CL emulation debug counters'
        return parser

    def on_exec(self, args: argparse.Namespace):
        resp = self.cmd.device.send_cmd_sync(6010, b'')
        if resp.status != Status.SUCCESS or not resp.data or len(resp.data) < 4:
            print(f' {CR}Debug command failed{C0}')
            return
        d = resp.data
        print(f' {CY}T=CL debug counters:{C0}')
        print(f'   I-blocks received : {d[0]}')
        print(f'   I-blocks sent     : {d[1]}')
        print(
            f'   Last rx PCB       : {d[2]:02x}  (blk_num={(d[2] & 0x01)}, chain={(d[2] >> 5) & 1}, cid={(d[2] >> 4) & 1})')
        print(f'   Last static match : {"yes" if d[3] else "no"}')


@emv.command('load')
class EMVLoad(DeviceRequiredUnit):
    """
    Load EMV card data into an HF14A_4 slot for emulation.

    Supports two modes:
      1. Load from a JSON file (PM3 emv scan -at output)
      2. Add a single custom APDU command/response pair

    Usage:
        emv load -f /tmp/card.json -s 3    load full card from PM3 JSON
        emv load --clear                    clear static responses
        emv load --cmd 00A4... --resp 6F..  add single APDU pair
        emv load --defaults                 load Mastercard test defaults
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Load EMV APDU responses into HF14A_4 slot for autonomous emulation'
        parser.add_argument('-f', '--file', default='', metavar='<path>',
                            help='Load from PM3 emv scan JSON file')
        parser.add_argument('-s', '--slot', type=int, default=None,
                            metavar='<1-8>', help='Target slot when using --file (default: active)')
        parser.add_argument('--clear', action='store_true',
                            help='Clear all static responses from active slot')
        parser.add_argument('--cmd', default='', metavar='<hex>',
                            help='Command APDU prefix to match (hex)')
        parser.add_argument('--resp', default='', metavar='<hex>',
                            help='Response APDU to return (hex)')
        parser.add_argument('--defaults', action='store_true',
                            help='Load built-in Mastercard test responses')
        return parser

    def on_exec(self, args: argparse.Namespace):
        cmd = self.cmd

        if args.clear:
            cmd.hf14a_4_clear_static_responses()
            print(f' {CG}Static responses cleared.{C0}')
            return

        if args.cmd and args.resp:
            try:
                c = bytes.fromhex(args.cmd.replace(' ', ''))
                r = bytes.fromhex(args.resp.replace(' ', ''))
                cmd.hf14a_4_add_static_response(c, r)
                print(f' {CG}Added: {c.hex().upper()} → {r.hex().upper()}{C0}')
            except ValueError as e:
                print(f' {CR}Invalid hex: {e}{C0}')
            return

        if args.defaults:
            self._load_defaults(cmd)
            return

        if args.file:
            if args.slot is not None:
                target_slot = SlotNumber(args.slot)
            else:
                target_slot = SlotNumber.from_fw(cmd.get_active_slot())
            self._load_from_json(args.file, target_slot, cmd)
            return

        print(f' {CY}Specify --file, --cmd/--resp, --clear, or --defaults{C0}')

    def _load_defaults(self, cmd):
        """Load built-in Mastercard test APDU responses."""
        cmd.hf14a_4_clear_static_responses()
        pairs = [
            # SELECT PPSE
            (bytes.fromhex('00a404000e325041592e5359532e4444463031'),
             bytes.fromhex('6f23840e325041592e5359532e4444463031'
                           'a511bf0c0e610c4f07a000000004101087010190 00'.replace(' ', '')),
             'SELECT PPSE'),
            # SELECT Mastercard Debit AID
            (bytes.fromhex('00a4040007a0000000041010'),
             bytes.fromhex('6f1d8407a0000000041010a512500a'
                           '4d6173746572436172648701019f38009000'),
             'SELECT Mastercard AID'),
            # GPO — decline gracefully
            (bytes.fromhex('80a80000'),
             bytes.fromhex('6985'),
             'GPO (conditions not satisfied)'),
        ]
        for c, r, name in pairs:
            resp = cmd.hf14a_4_add_static_response(c, r)
            if resp.status == Status.SUCCESS:
                print(f' {CG}Loaded: {name}{C0}')
            else:
                print(f' {CR}Failed: {name}{C0}')
        print(f'\n {CY}Default responses loaded. Run: hw mode -e{C0}')

    def _tlv_encode_len(self, n: int) -> bytes:
        """Encode integer n as BER-TLV length (short or long form)."""
        if n < 0x80:
            return bytes([n])
        elif n <= 0xFF:
            return bytes([0x81, n])
        else:
            return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])

    def _load_from_json(self, filepath, target_slot, cmd):
        """Load card data from a PM3 emv scan JSON file."""
        import json as jsonlib
        import os
        if not os.path.exists(filepath):
            print(f' {CR}File not found: {filepath}{C0}')
            return
        try:
            with open(filepath) as f:
                data = jsonlib.load(f)
        except Exception as e:
            print(f' {CR}JSON parse error: {e}{C0}')
            return

        # Parse card info
        try:
            card = data['Card']['Contactless']
            uid = bytes.fromhex(card['UID'].replace(' ', ''))
            atqa = bytes.fromhex(card['ATQA'].replace(' ', ''))
            sak = int(card['SAK'], 16)
            ats_raw = bytes.fromhex(card['ATS'].replace(' ', ''))
            ats = ats_raw[:ats_raw[0]] if ats_raw else b''
        except Exception as e:
            print(f' {CR}Card info parse error: {e}{C0}')
            return

        uid_str = ' '.join(f'{b:02X}' for b in uid)
        print(f' {CG}Card from JSON:{C0}')
        print(f'   UID  : {CG}{uid_str}{C0}')
        print(f'   ATQA : {CG}{atqa.hex().upper()}{C0}  SAK: {CG}{sak:02X}{C0}')
        print(f'   ATS  : {CG}{ats.hex().upper()}{C0}')

        static_pairs = []

        def tlv_resp(tag_hex, len_hex, val_hex):
            """Reconstruct TLV response with proper BER length encoding + SW 9000."""
            tag_b = bytes.fromhex(tag_hex)
            val_b = bytes.fromhex(val_hex)
            n = int(len_hex, 16)
            len_b = self._tlv_encode_len(n)
            return tag_b + len_b + val_b + bytes([0x90, 0x00])

        try:
            v = data['PPSE']['FCITemplate']['value'].replace(' ', '')
            l = data['PPSE']['FCITemplate']['length']
            static_pairs.append((
                bytes.fromhex('00a404000e325041592e5359532e4444463031'),
                tlv_resp('6F', l, v),
                'SELECT PPSE'))
        except Exception as e:
            print(f' {CR}PPSE: {e}{C0}')

        try:
            v = data['Application']['FCITemplate']['value'].replace(' ', '')
            l = data['Application']['FCITemplate']['length']
            aid = data['Application']['AID'].replace(' ', '')
            static_pairs.append((
                bytes.fromhex('00a4040007' + aid),
                tlv_resp('6F', l, v),
                'SELECT AID'))
        except Exception as e:
            print(f' {CR}Application FCI: {e}{C0}')

        try:
            v = data['Application']['GPO']['value'].replace(' ', '')
            l = data['Application']['GPO']['length']
            tag = data['Application']['GPO'].get('tag', '77')
            static_pairs.append((
                bytes.fromhex('80a80000'),
                tlv_resp(tag, l, v),
                'GPO'))
        except Exception as e:
            print(f' {CR}GPO: {e}{C0}')

        try:
            for rec in data['Application'].get('Records', []):
                sfi_n = int(rec['SFI'], 16)
                rec_n = int(rec['RecordNum'], 16)
                v = rec['Data']['value'].replace(' ', '')
                l = rec['Data']['length']
                tag = rec['Data'].get('tag', '70')
                p2 = (sfi_n << 3) | 4
                static_pairs.append((
                    bytes([0x00, 0xB2, rec_n, p2, 0x00]),
                    tlv_resp(tag, l, v),
                    f'READ RECORD SFI={sfi_n} rec={rec_n}'))
        except Exception as e:
            print(f' {CR}Records: {e}{C0}')

        # Configure slot
        print(f'\n {CY}Configuring slot {target_slot}...{C0}')
        cmd.set_slot_tag_type(target_slot, TagSpecificType.HF14A_4)
        cmd.set_slot_data_default(target_slot, TagSpecificType.HF14A_4)
        cmd.set_slot_enable(target_slot, TagSenseType.HF, True)

        # PM3 JSON stores ATQA in display order (byte1,byte0) — swap to wire order
        atqa_wire = bytes([atqa[1], atqa[0]]) if len(atqa) == 2 else atqa
        cmd.hf14a_4_set_anti_coll(uid, atqa_wire, sak, ats)

        cmd.hf14a_4_clear_static_responses()
        for c, r, name in static_pairs:
            try:
                cmd.hf14a_4_add_static_response(c, r)
                print(f' {CG}+ {name} ({len(r)}b){C0}')
            except Exception as e:
                print(f' {CR}  Failed {name}: {e}{C0}')

        cmd.slot_data_config_save()
        print(f'\n {CG}Done! Slot {target_slot} ready with {len(static_pairs)} response(s).{C0}')
        print(f' {C0}Next: hw slot change -s {target_slot} && hw mode -e{C0}')


@emv.command('apdu')
class EMVApdu(DeviceRequiredUnit):
    """
    ISO14443-4 T=CL interactive APDU relay.

    CU emulates an ISO14443-4 card and relays APDUs to/from the terminal.
    For each APDU from the reader, you type the hex response bytes.

    Requires HF14A_4 slot configured with SAK=20 and ATS. Run hw mode -e first.

    Usage:
        emv apdu
        emv apdu --timeout 30000
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'ISO14443-4 T=CL interactive APDU relay (manual response mode)'
        parser.add_argument('--timeout', type=int, default=15000, metavar='<ms>',
                            help='Total relay timeout in ms (default: 15000)')
        return parser

    def on_exec(self, args: argparse.Namespace):
        import time
        cmd = self.cmd
        timeout_ms = max(1000, min(60000, args.timeout))

        print(f' {CY}ISO14443-4 T=CL APDU relay started{C0}')
        print(f' Waiting for a reader to connect (SAK=20 slot required)...')
        print(f' Type {CY}quit{C0} to exit, or enter hex response bytes when prompted.')

        exchange_count = 0

        while True:
            resp = None
            deadline = time.monotonic() + (timeout_ms / 1000.0)
            while time.monotonic() < deadline:
                try:
                    r = cmd.hf14a_4_apdu_recv()
                except Exception as e:
                    print(f' {CR}Error polling for APDU: {e}{C0}')
                    resp = None
                    break
                if r.status == Status.SUCCESS:
                    resp = r
                    break
                elif r.status != Status.HF_TAG_NO:
                    print(f' {CR}Firmware error: {r.status}{C0}')
                    resp = None
                    break
                time.sleep(0.02)

            if resp is None:
                print(f' {C0}No APDU received within timeout.{C0}')
                break

            apdu = bytes(resp.data)
            desc = _emv_decode_apdu(apdu)
            exchange_count += 1
            apdu_hex = ' '.join(f'{b:02x}' for b in apdu)
            print(f'\n [{exchange_count}] {CY}APDU →→  {apdu_hex}{C0}')
            if desc:
                print(f'       {C0}{desc}{C0}')

            try:
                user_input = input(f'     Response (hex) [{CG}90 00{C0}]: ').strip()
            except (EOFError, KeyboardInterrupt):
                break

            if user_input.lower() == 'quit':
                break
            if not user_input:
                user_input = '9000'

            try:
                response_bytes = bytes.fromhex(user_input.replace(' ', ''))
            except ValueError:
                print(f' {CR}Invalid hex — sending 6F00 (error){C0}')
                response_bytes = bytes.fromhex('6F00')

            try:
                cmd.hf14a_4_apdu_send(response_bytes)
                resp_hex = ' '.join(f'{b:02x}' for b in response_bytes)
                print(f'       {CG}←← Response  {resp_hex}{C0}')
            except Exception as e:
                print(f' {CR}Error sending response: {e}{C0}')
                break

        print(f'\n {C0}Relay ended. {exchange_count} APDU exchange(s) completed.{C0}')


# ---------------------------------------------------------------------------
# hf des — MIFARE DESFire commands
# ---------------------------------------------------------------------------


def _strip_parity(raw: bytes, sz_bits: int):
    """Strip ISO14443-A parity bits (one per byte) from a frame.

    Returns (stripped_bytes, data_bits).
    Short frames (<8 bits) and frames whose bit count is not a multiple of 9
    are returned as-is — they have no parity.
    """
    if sz_bits >= 8 and sz_bits % 9 == 0:
        n_bytes = sz_bits // 9
        all_bits = []
        for byte in raw:
            for b in range(8):
                all_bits.append((byte >> b) & 1)
        stripped = []
        for nb in range(n_bytes):
            val = 0
            for b in range(8):
                val |= all_bits[nb * 9 + b] << b
            stripped.append(val)
        return bytes(stripped), n_bytes * 8
    return raw, sz_bits


def parse_authtrace_frames(trace: bytes):
    """Decode inner frame stream; strip parity; return list of (szBits, data, is_tx)."""
    frames = []
    off = 0
    while off + 2 <= len(trace):
        hdr      = (trace[off] << 8) | trace[off + 1]
        is_tx    = bool(hdr & 0x8000)
        sz_bits  = hdr & 0x7FFF
        sz_bytes = (sz_bits + 7) // 8
        off += 2
        if off + sz_bytes > len(trace):
            break
        raw = trace[off:off + sz_bytes]
        data, sz_bits = _strip_parity(raw, sz_bits)
        frames.append((sz_bits, bytes(data), is_tx))
        off += sz_bytes
    return frames


# ---------------------------------------------------------------------------
# nfc_canary helpers. Layouts mirror firmware/.../standalone_modes/nfc_canary_core.h
# ---------------------------------------------------------------------------
CANARY_LEVELS = ('field', 'poll', 'select', 'engage')
CANARY_CFG_VERSION = 1
CANARY_REC_SIZE = 16
CANARY_FLAG_NAMES = {0x01: 'forced', 0x02: 'disarm'}


def canary_cfg_parse(blob: bytes) -> dict:
    """Decode the 4-byte config blob; empty/None -> firmware defaults."""
    if not blob:
        return {'min_level': 0, 'cooldown_s': 10, 'flags': 3}
    if len(blob) != 4 or blob[0] != CANARY_CFG_VERSION:
        raise ValueError(f"unexpected blob {bytes(blob).hex()}")
    if blob[1] > 3 or blob[2] == 0 or blob[3] & ~0x03:
        raise ValueError(f"out-of-range blob {bytes(blob).hex()}")
    return {'min_level': blob[1], 'cooldown_s': blob[2], 'flags': blob[3]}


def canary_cfg_pack(cfg: dict) -> bytes:
    return bytes([CANARY_CFG_VERSION, cfg['min_level'], cfg['cooldown_s'], cfg['flags']])


def canary_log_parse(raw: bytes) -> list:
    """Decode the 16-byte window records the firmware keeps (oldest first)."""
    out = []
    for off in range(0, len(raw) - len(raw) % CANARY_REC_SIZE, CANARY_REC_SIZE):
        r = raw[off:off + CANARY_REC_SIZE]
        if r[0] != 1:       # NC_REC_TYPE_WINDOW
            continue
        flags = r[14]
        out.append({
            'level': CANARY_LEVELS[r[1]] if r[1] < len(CANARY_LEVELS) else f'?{r[1]}',
            'cmd': r[2],
            'cmd_name': canary_cmd_name(CANARY_LEVELS[r[1]] if r[1] < len(CANARY_LEVELS) else '?', r[2]),
            'epoch': r[3],
            'start_s': int.from_bytes(r[4:8], 'little'),
            'dur_s': int.from_bytes(r[8:10], 'little'),
            'field_ons': int.from_bytes(r[10:12], 'little'),
            'frames': int.from_bytes(r[12:14], 'little'),
            'flags': [n for b, n in CANARY_FLAG_NAMES.items() if flags & b],
        })
    return out


def canary_log_table(records: list) -> str:
    if not records:
        return "  (empty)"
    lines = [f"  {'arm':>3}  {'start':>7}  {'dur':>5}  {'level':<7} {'cmd':<4} "
             f"{'fields':>6}  {'frames':>6}  {'last command':<26}  notes"]
    for r in records:
        cmd = f"{r['cmd']:02x}" if r['level'] != 'field' else '--'
        lines.append(f"  {r['epoch']:>3}  {r['start_s']:>6}s  {r['dur_s']:>4}s  "
                     f"{r['level']:<7} {cmd:<4} {r['field_ons']:>6}  {r['frames']:>6}  "
                     f"{r['cmd_name']:<26}  {','.join(r['flags'])}")
    lines.append("  (start is seconds since that arm; arm = arm counter)")
    lines.append("  (last command = first byte of the final frame at the deepest level)")
    return "\n".join(lines)


def canary_event_decode(payload: bytes) -> dict:
    """Decode the 10-byte BLE notification payload (cmd 7010)."""
    if len(payload) != 10:
        raise ValueError(f"expected 10 bytes, got {len(payload)}")
    t = {1: 'alert', 2: 'end', 3: 'test'}.get(payload[0], f'?{payload[0]}')
    return {
        'type': t,
        'level': CANARY_LEVELS[payload[1]] if payload[1] < 4 else f'?{payload[1]}',
        'cmd': payload[2],
        'cmd_name': canary_cmd_name(CANARY_LEVELS[payload[1]] if payload[1] < 4 else '?', payload[2]),
        'seq': payload[3],
        'dur_s': int.from_bytes(payload[4:6], 'little'),
        'field_ons': payload[6],
        'flags': [n for b, n in CANARY_FLAG_NAMES.items() if payload[7] & b],
        'frames': int.from_bytes(payload[8:10], 'little'),
    }


def parse_authtrace_buffer(raw: bytes):
    """Walk the session stream; return list of session dicts."""
    sessions = []
    off = 0
    while off + 4 <= len(raw):
        session_num = raw[off]
        status      = raw[off + 1]
        trace_len   = raw[off + 2] | (raw[off + 3] << 8)
        off += 4
        if off + trace_len > len(raw):
            break
        trace_bytes = raw[off:off + trace_len]
        off += trace_len
        sessions.append({
            "session_num": session_num,
            "status_code": status,
            "status_name": AUTHTRACE_STATUS_NAMES.get(status, f"0x{status:02x}"),
            "trace_len":   trace_len,
            "frames":      parse_authtrace_frames(trace_bytes),
        })
    return sessions


def authtrace_summarise(sessions):
    out = []
    for s in sessions:
        frames = s["frames"]
        tx  = sum(1 for f in frames if f[2]) # tolerate an optional 4th (parity) element
        rx  = len(frames) - tx
        nonces = _extract_sniff_nonces(frames)
        nonce_info = f"  {CG}{len(nonces)} nonce pair(s){C0}" if nonces else ""
        out.append(
            f"  #{s['session_num']:<3} {s['status_name']:<10} "
            f"{len(frames):>2} frames  ({rx} reader\u2192card, "
            f"{tx} card\u2192reader){nonce_info}"
        )
    return "\n".join(out)


def authtrace_pretty_dump(sessions):
    """Full decoded per-frame dump matching hf 14a sniff/trace output style."""
    out = []
    for s in sessions:
        frames = s["frames"]
        tx_count = sum(1 for f in frames if f[2])  # tolerate an optional 4th (parity) element
        rx_count = len(frames) - tx_count
        out.append(
            f"\n{CG}=== session #{s['session_num']}  "
            f"status={s['status_name']}  "
            f"{len(frames)} frames  "
            f"({rx_count} reader\u2192card  {tx_count} card\u2192reader) ==={C0}"
        )
        out.append(
            f"  {'#':>3}  {'dir':<3}  {'bits':>4}  {'hex data':<42}  decoded"
        )
        out.append(
            f"  {'---':>3}  {'---':<3}  {'----':>4}  {'-'*42}  {'-'*35}"
        )
        # Exact next-frame-index slots, not sticky booleans: a slot only
        # applies to the ONE frame right after the event that armed it. If
        # that frame is missing or garbled, the slot is simply never hit
        # again -- unlike a boolean flag, it can't stay "stuck" open and
        # mislabel some unrelated later frame (e.g. a fresh SELECT cycle's
        # response, with no new AUTH in between) as a leftover NT/NR||AR/AT.
        last_keytype  = None
        last_block    = None
        nt_slot       = -1
        nr_ar_slot    = -1
        at_slot       = -1
        for n, frame in enumerate(frames):
            # Backward compatible: existing callers pass 3-tuples (no parity
            # captured/relevant); imported PM3 traces carry real parity as an
            # optional 4th element, shown as '!' after a byte on mismatch --
            # same convention as the live --dump parity-flagged hex column.
            if len(frame) == 4:
                sz_bits, data, is_tx, parity_bits = frame
            else:
                sz_bits, data, is_tx = frame
                parity_bits = []
            if parity_bits and len(parity_bits) == len(data):
                hex_str = ' '.join(
                    f"{b:02x}{'!' if odd_parity_byte(b) != p else ' '}"
                    for b, p in zip(data, parity_bits)
                )
            else:
                hex_str = ' '.join(f'{b:02x}' for b in data)
            decoded_ctx = None
            col_ctx     = None

            if not is_tx and sz_bits == 32 and len(data) == 4 and data[0] in (0x60, 0x61):
                last_keytype = 'A' if data[0] == 0x60 else 'B'
                last_block   = data[1]
                nt_slot      = n + 1
                nr_ar_slot   = -1
                at_slot      = -1
                decoded_ctx  = f"MIFARE AUTH Key{last_keytype} block=0x{last_block:02X} ({last_block})"
                col_ctx      = CG
            elif is_tx and n == nt_slot and sz_bits == 32 and len(data) == 4:
                decoded_ctx  = f"NT (card nonce) = {data.hex().upper()}"
                col_ctx      = CG
                nr_ar_slot   = n + 1
            elif not is_tx and n == nr_ar_slot and sz_bits == 64 and len(data) == 8:
                nr = data[:4].hex().upper()
                ar = data[4:].hex().upper()
                decoded_ctx  = f"NR={nr}  AR={ar}  (mfkey32 input)"
                col_ctx      = CG
                at_slot      = n + 1

            elif is_tx and n == at_slot and sz_bits == 32 and len(data) == 4:
                decoded_ctx  = f"AT (auth ack, encrypted) = {data.hex().upper()}"
                col_ctx      = CG

            if decoded_ctx is None:
                decoded, col, _ = _decode_14a_frame_col(data, sz_bits, is_tx=is_tx)
            else:
                decoded, col = decoded_ctx, col_ctx

            dir_str = f'{CG}<<<{C0}' if is_tx else f'{CY}>>>{C0}'
            out.append(
                f"  {CY}{n+1:>3}{C0}  {dir_str}  {sz_bits:>4}  "
                f"{hex_str:<42}  {col}{decoded}{C0}"
            )

        # Nonce summary + mfkey64/mfkey32v2 cracking attempt -- shared with
        # _print_14a_sniff_summary so --dump gets the same raw nt/nr/ar/at
        # values and crack attempts the default (non-dump) summary already
        # had, rather than a second, weaker reimplementation.
        out.extend(_nonce_cracking_lines(frames))
    return "\n".join(out)


def parse_relay_result_buffer(raw: bytes) -> list:
    """Parse a relay FDS result buffer into a list of session dicts.

    Variable-length session records (16-byte header + trace):
      [0]      role  (0=CARD, 1=READER)
      [1]      status (0=OK, 1=TIMEOUT, 2=DISCONNECT)
      [2]      uid_len
      [3..6]   uid (4 bytes)
      [7..8]   atqa
      [9]      sak
      [10..11] frame_count u16 LE
      [12..13] trace_len u16 LE
      [14..15] reserved
      [16..]   trace frames (AuthTrace wire format: u16 hdr + raw bytes)
    """
    import struct
    HEADER = 16
    STATUS = {0: 'OK', 1: 'TIMEOUT', 2: 'DISCONNECT'}
    sessions = []
    off = 0
    idx = 0
    while off + HEADER <= len(raw):
        h = raw[off:off + HEADER]
        role        = h[0]
        status      = h[1]
        uid_len     = h[2]
        uid         = raw[off+3:off+3+min(uid_len,4)].hex().upper() if uid_len else '-'
        atqa        = raw[off+7:off+9].hex().upper()
        sak         = f'{h[9]:02X}'
        frame_count = struct.unpack_from('<H', h, 10)[0]
        trace_len   = struct.unpack_from('<H', h, 12)[0]
        protocol    = h[14]  # 0=HF, 1=LF

        trace_off   = off + HEADER
        trace_end   = trace_off + trace_len
        if trace_end > len(raw):
            break  # truncated

        trace_bytes = raw[trace_off:trace_end]
        frames      = parse_relay_frames(trace_bytes)

        sessions.append({
            'session_num':  idx,
            'role':         'CARD' if role == 0 else 'READER',
            'protocol':     'LF' if protocol == 1 else 'HF',
            'uid_len':      uid_len,
            'uid':          uid,
            'atqa':         atqa if protocol == 0 else '-',
            'sak':          sak  if protocol == 0 else '-',
            'frame_count':  frame_count,
            'trace_len':    trace_len,
            'status':       status,
            'status_name':  STATUS.get(status, f'UNKNOWN({status})'),
            'frames':       frames,
        })
        off = trace_end
        idx += 1
    return sessions


def parse_relay_frames(trace: bytes) -> list:
    """Decode a raw trace buffer into frame dicts (same format as AuthTrace)."""
    frames = []
    off = 0
    while off + 2 <= len(trace):
        hdr       = (trace[off] << 8) | trace[off + 1]
        tag_to_rd = bool(hdr & 0x8000)
        bits      = hdr & 0x7FFF
        byte_cnt  = (bits + 7) // 8
        off += 2
        if off + byte_cnt > len(trace):
            break
        raw = trace[off:off + byte_cnt]
        decoded, col, _ = _decode_14a_frame_col(raw, bits, is_tx=tag_to_rd)
        frames.append({
            'dir':     'tag→reader' if tag_to_rd else 'reader→tag',
            'bits':    bits,
            'hex':     raw.hex().upper(),
            'decoded': decoded,
            'col':     col,
        })
        off += byte_cnt
    return frames


def relay_result_summary(sessions) -> str:
    """Human-readable session table for --dump."""
    if not sessions:
        return color_string((CY, '  (no sessions)'))
    lines = []
    for s in sessions:
        role_col = CG if s['role'] == 'CARD' else CC
        st_col   = CG if s['status'] == 0 else CY
        lines.append(
            f"  {CY}#{s['session_num']}{C0}  "
            f"{role_col}{s['role']:<6}{C0}  "
            f"{CC}{s.get('protocol','HF')}{C0}  "
            f"UID={s['uid']}  "
            + (f"ATQA={s['atqa']} SAK={s['sak']}  " if s.get('protocol','HF') == 'HF' else "")
            + f"frames={s['frame_count']}  "
            f"{st_col}{s['status_name']}{C0}"
        )
        frames = s.get('frames', [])
        if frames:
            lines.append(f"    {'#':>3}  {'dir':<12} {'bits':>4}  {'hex':<44}  decoded")
            lines.append(f"    {'---':>3}  {'---':<12} {'----':>4}  {'---':<44}  -------")
            for i, f in enumerate(frames):
                arrow = f"{CG}←{C0}" if f['dir'] == 'tag→reader' else f"{CC}→{C0}"
                decoded_str = color_string((f['col'], f['decoded'])) if f.get('decoded') else ''
                lines.append(
                    f"    {i+1:>3}  {arrow} {f['dir']:<11} {f['bits']:>4}  "
                    f"{f['hex']:<44}  {decoded_str}"
                )
    return '\n'.join(lines)


# --- Commands ----------------------------------------------------------------

@standalone.command('status')
class StandaloneStatus(DeviceRequiredUnit):
    """
    Show the current standalone state, mode, and flags.

    Usage:
        standalone status
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Show standalone subsystem state'
        return parser

    def on_exec(self, args):
        state, mode, flags, fds = self.cmd.standalone_get_mode()
        state_col = CG if state != StandaloneState.DISARMED else CY
        print(f" state: {color_string((state_col, state.name))}")
        print(f"  mode: {color_string((CC, mode.name))}")
        flag_str = ", ".join(f.name for f in StandaloneFlag
                             if f != StandaloneFlag.NONE and (flags & f)) \
                   or "(none)"
        print(f" flags: {flag_str}")
        if fds is not None:
            used  = fds['words_used']
            pages = fds['pages_available']
            dirty = fds['dirty_records']
            valid = fds['valid_records']
            gc_hint = f"  {CY}(GC recommended){C0}" if dirty > 4 else ""
            print(f" flash: {used} words used  {pages} pages free  "
                  f"valid={valid} dirty={dirty}{gc_hint}")
        if mode == StandaloneMode.RELAY:
            try:
                d = self.cmd.relay_get_diag()
                if not d:
                    pass
                else:
                    reports = d['adv_reports']
                    hits    = d['relay_hits']
                    state   = d.get('ble_state', 0)
                    role    = d.get('ble_role', 0)
                    state_names = {0:'IDLE',1:'STARTING',2:'CONNECTING',
                                   3:'DISCOVERING',4:'NEGOTIATING',5:'READY',
                                   6:'ACTIVE',7:'ERROR'}
                    role_names  = {0:'RELAY_CARD (faces reader)',
                                   1:'RELAY_READER (faces real card)'}
                    sub        = d.get('sub_state', 0)
                    card_found  = d.get('card_found', 0)
                    identity_rx = d.get('identity_rx', 0)
                    uid_len     = d.get('uid_len', 0)
                    uid_bytes   = d.get('uid', [])
                    uid_str = ''.join(f'{b:02X}' for b in uid_bytes[:uid_len]) if uid_len else '-'
                    sub_names = {0:'INIT',1:'LINKING',2:'CARD_AWAIT_IDENTITY',
                                 3:'CARD_READY',4:'CARD_AWAIT_RESPONSE',5:'READER_SCAN',
                                 6:'READER_READY',7:'READER_RELAY',8:'ERROR'}
                    state_str = state_names.get(state, f'UNKNOWN({state})')
                    role_str  = role_names.get(role, f'UNKNOWN({role})')
                    sub_str   = sub_names.get(sub, f'UNKNOWN({sub})')
                    print(f"   ble: {reports} scan reports  {hits} relay hits")
                    print(f"        state={CG if state==5 else CY}{state_str}{C0}  "
                          f"role={CC}{role_str}{C0}")
                    print(f"        sub={CG if sub in (3,6) else CY}{sub_str}{C0}")
                    relay_armed = (state != StandaloneState.DISARMED)
                    if relay_armed and reports == 0:
                        print(f"        {CR}WARNING: scanning not working{C0}")
                    elif relay_armed and hits == 0:
                        print(f"        {CY}no relay HELLO seen yet{C0}")
                    elif relay_armed and state < 5:
                        print(f"        {CY}HELLO seen but not connected — check both CUs armed{C0}")
                    else:
                        if role == 0:   # RELAY_CARD
                            if identity_rx:
                                print(f"        {CG}card identity received  UID={uid_str}{C0}")
                            else:
                                print(f"        {CY}waiting for card identity from RELAY_READER{C0}")
                        else:           # RELAY_READER
                            if card_found:
                                print(f"        {CG}real card found  UID={uid_str}{C0}")
                            else:
                                print(f"        {CY}scanning for real card — place card near CU{C0}")
            except Exception:
                pass


@standalone.command('set-mode')
class StandaloneSetMode(DeviceRequiredUnit):
    """
    Select the active standalone mode.

    Examples:
        standalone set-mode authtrace
        standalone set-mode slot-cycle
        standalone set-mode autoclone --opt-in
        standalone set-mode disabled       (returns to normal button config)
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Set standalone mode'
        parser.add_argument('mode', help='mode name (authtrace, emul-trace, relay, slot-cycle, '
                                         'autoclone, read-replay, dict-check, '
                                         'hf14a-tap-sniff, disabled)')
        parser.add_argument('--opt-in', action='store_true',
                            help='set HOST_OPTED_IN flag (required for '
                                 'autoclone and read-replay)')
        parser.add_argument('--quiet-buzzer', action='store_true')
        parser.add_argument('--quiet-led',    action='store_true')
        return parser

    def on_exec(self, args):
        try:
            mode = StandaloneMode.from_name(args.mode)
        except ValueError as e:
            print(color_string((CR, str(e))))
            # from_name()'s "valid: ..." list is every known name, not what
            # this specific firmware was built with. Add that separately so
            # a typo doesn't look like every mode is available here.
            avail = self.cmd.standalone_get_available()
            if avail:
                built = [m.name.lower().replace('_', '-') for m in StandaloneMode
                         if m != StandaloneMode.DISABLED and m < len(avail) and avail[m]]
                print(color_string((CY,
                    "built into this firmware: " + (", ".join(built) or "(none)"))))
            return

        flags = StandaloneFlag.NONE
        if args.opt_in:        flags |= StandaloneFlag.HOST_OPTED_IN
        if args.quiet_buzzer:  flags |= StandaloneFlag.BUZZER_QUIET
        if args.quiet_led:     flags |= StandaloneFlag.LED_QUIET

        result = self.cmd.standalone_set_mode(mode, flags)
        if not isinstance(result, tuple):
            if result.status == Status.NOT_IMPLEMENTED:
                print(color_string((CR,
                    f"refused: mode '{mode.name}' is not available on this device/firmware build")))
            elif result.status == Status.PAR_ERR:
                print(color_string((CR,
                    f"refused: mode '{mode.name}' requires --opt-in")))
            else:
                print(color_string((CR,
                    f"set-mode failed: status={result.status}")))
            return

        state, mode_now, flags_now = result
        print(color_string((CG,
            f"ok: state={state.name} mode={mode_now.name} "
            f"flags={int(flags_now):#04x}")))


@standalone.command('trigger')
class StandaloneTrigger(DeviceRequiredUnit):
    """
    Fire the active mode's primary action (equivalent to pressing both
    buttons briefly on the device).

    For authtrace, this runs one scan session against whatever tag is in
    the field right now.
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Trigger active standalone mode'
        return parser

    def on_exec(self, args):
        resp = self.cmd.standalone_trigger()
        if resp.status == Status.SUCCESS:
            print(color_string((CG, "triggered")))
        elif resp.status == Status.HF_TAG_NO:
            print(color_string((CY, "no tag in field")))
        elif resp.status == Status.DEVICE_MODE_ERROR:
            print(color_string((CR, "mode not armed or invalid state")))
        elif resp.status == Status.PAR_ERR:
            print(color_string((CR, "refused (likely missing opt-in)")))
        else:
            print(color_string((CR, f"trigger failed: status={resp.status}")))


@standalone.command('disarm')
class StandaloneDisarm(DeviceRequiredUnit):
    """
    Disarm the active standalone mode via USB, triggering on_exit.

    Equivalent to the both-button long chord on the device. Saves result
    data to FDS so it can be retrieved with get-result.
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Disarm standalone mode and save results'
        return parser

    def on_exec(self, args):
        try:
            resp = self.cmd.standalone_disarm()
            if resp.status == Status.SUCCESS:
                print(color_string((CG, "disarmed — results saving")))
            else:
                print(color_string((CY, f"already disarmed or error: status={resp.status}")))
        except Exception as e:
            # The disarm may have been accepted but the ack came back slow — a
            # mode's on_exit can do a multi-second blocking FDS save. Confirm the
            # actual device state before reporting failure.
            try:
                from chameleon_enum import StandaloneState
                if self.cmd.standalone_get_mode()[0] == StandaloneState.DISARMED:
                    print(color_string((CG, "disarmed (ack was slow — confirmed via state)")))
                    return
            except Exception:
                pass
            print(color_string((CR, f"disarm failed: {e}")))
            print(color_string((CY, "Use the both-button chord on the device to disarm manually.")))


# read_replay / autoclone / dict_check result decoders.
# Record layouts mirror firmware/application/src/standalone_modes/mode_*.c

def parse_read_replay_buffer(raw: bytes):
    # 13B: uid_len, uid[7], atqa[2], sak, sectors_read, sectors_total
    recs = []
    for o in range(0, len(raw) - (len(raw) % 13), 13):
        r = raw[o:o + 13]
        uid_len = min(r[0], 7)
        recs.append({
            "uid":           r[1:1 + uid_len].hex(),
            "atqa":          r[8:10].hex(),
            "sak":           r[10],
            "sectors_read":  r[11],
            "sectors_total": r[12],
        })
    return recs


def read_replay_table(recs):
    if not recs:
        return "  (no clones recorded)"
    return "\n".join(
        f"  [{i}] uid {r['uid']}  atqa {r['atqa']}  sak {r['sak']:02x}  "
        f"sectors {r['sectors_read']}/{r['sectors_total']}"
        for i, r in enumerate(recs))


_AUTOCLONE_RESULT = {0: "ok", 1: "no source", 2: "no target", 3: "write fail"}


def parse_autoclone_buffer(raw: bytes):
    # 11B: result, uid_len, uid[7], blocks_written (+1 pad)
    recs = []
    for o in range(0, len(raw) - (len(raw) % 11), 11):
        r = raw[o:o + 11]
        uid_len = min(r[1], 7)
        recs.append({
            "result":         r[0],
            "result_name":    _AUTOCLONE_RESULT.get(r[0], f"?{r[0]}"),
            "uid":            r[2:2 + uid_len].hex(),
            "blocks_written": r[9],
        })
    return recs


def autoclone_table(recs):
    if not recs:
        return "  (no clone attempts recorded)"
    return "\n".join(
        f"  [{i}] {r['result_name']:<10}  uid {r['uid'] or '-'}  blocks {r['blocks_written']}"
        for i, r in enumerate(recs))


def parse_dict_check_buffer(raw: bytes):
    # 15B: sector, found_a, keyA[6], found_b, keyB[6]
    recs = []
    for o in range(0, len(raw) - (len(raw) % 15), 15):
        r = raw[o:o + 15]
        recs.append({
            "sector":  r[0],
            "found_a": bool(r[1]),
            "key_a":   r[2:8].hex(),
            "found_b": bool(r[8]),
            "key_b":   r[9:15].hex(),
        })
    return recs


def dict_check_table(recs):
    if not recs:
        return "  (no sectors checked)"
    lines = []
    for r in recs:
        a = r['key_a'] if r['found_a'] else "--"
        b = r['key_b'] if r['found_b'] else "--"
        lines.append(f"  sector {r['sector']:2d}  A {a:<12}  B {b:<12}")
    return "\n".join(lines)


def _standalone_result_args_parser(description: str) -> ArgumentParserNoExit:
    """Shared arg set for both the current-mode and per-mode get-result
    commands, so the two stay identical rather than drifting apart."""
    parser = ArgumentParserNoExit()
    parser.description = description
    parser.add_argument('-f', '--file', default=None, metavar='<path>',
                        help='write output to file instead of stdout')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--raw',  action='store_true',
                       help='dump raw bytes (no parsing)')
    group.add_argument('--json', action='store_true',
                       help='emit parsed sessions as JSON')
    group.add_argument('--dump', action='store_true',
                       help='dump every frame in each session')
    group.add_argument('--pm3', default=None, metavar='<prefix>',
                       help='write each session as a Proxmark3 .trace (<prefix>-NN.trace)')
    return parser


def _standalone_render_result(args, mode, raw: bytes):
    """Parse and print already-drained result bytes for `mode`. Shared by
    the current-mode 'standalone get-result' and every per-mode
    'standalone <mode> get-result' -- this is the entire body of the old
    single on_exec(), unchanged, just taking mode/raw as parameters
    instead of resolving them itself."""
    import json as jsonlib
    from pathlib import Path

    if not raw:
        print(color_string((CY, "no result data")))
        return

    if args.pm3:
        if mode != StandaloneMode.HF14A_TAP_SNIFF:
            print(color_string((CY, f"--pm3 applies to hf14a_tap_sniff (mode={mode.name})")))
            return
        import pm3_trace
        written = pm3_trace.export_tap_sniff_sessions_to_pm3(raw, args.pm3)
        if not written:
            print(color_string((CY, "no sessions to export")))
        else:
            for fn, nframes, status in written:
                print(color_string((CG, f"  {fn}  ({nframes} frame(s), status 0x{status:02x})")))
        return

    if args.raw or (args.file and not (args.json or args.dump)):
        if args.file:
            Path(args.file).write_bytes(raw)
            print(color_string((CG, f"{len(raw)} bytes -> {args.file}")))
        else:
            print(color_string((CY, f"{len(raw)} raw bytes:")))
            for off in range(0, len(raw), 16):
                chunk = raw[off:off + 16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"  {off:04x}  {hex_part:<47}  {ascii_part}")
        return

    if mode == StandaloneMode.NFC_CANARY:
        records = canary_log_parse(raw)
        if args.json:
            import json as _json
            out = _json.dumps(records, indent=2)
            if args.file:
                Path(args.file).write_text(out)
                print(color_string((CG, f"-> {args.file}")))
            else:
                print(out)
        else:
            print(color_string((CG, f"{len(records)} nfc-canary window(s)")))
            print(canary_log_table(records))
        return

    for _m, _parse, _table, _hdr in (
        (StandaloneMode.READ_REPLAY, parse_read_replay_buffer, read_replay_table, "clone(s)"),
        (StandaloneMode.AUTOCLONE,   parse_autoclone_buffer,   autoclone_table,   "attempt(s)"),
    ):
        if mode == _m:
            recs = _parse(raw)
            if args.json:
                out = jsonlib.dumps(recs, indent=2)
                if args.file:
                    Path(args.file).write_text(out)
                    print(color_string((CG, f"-> {args.file}")))
                else:
                    print(out)
            else:
                print(color_string((CG, f"{len(recs)} {mode.name.lower().replace('_', '-')} {_hdr}")))
                print(_table(recs))
            return

    if mode == StandaloneMode.DICT_CHECK:
        recs = parse_dict_check_buffer(raw)
        if args.json:
            out = jsonlib.dumps(recs, indent=2)
            if args.file:
                Path(args.file).write_text(out)
                print(color_string((CG, f"-> {args.file}")))
            else:
                print(out)
        else:
            found = sum(1 for r in recs if r['found_a'] or r['found_b'])
            print(color_string((CG, f"dict-check: {found}/{len(recs)} sector(s) with a known key")))
            print(dict_check_table(recs))
        return

    if mode not in (StandaloneMode.AUTHTRACE, StandaloneMode.EMUL_TRACE,
                    StandaloneMode.RELAY, StandaloneMode.HF14A_TAP_SNIFF):
        print(color_string((CY,
            f"got {len(raw)} bytes; mode={mode.name} has no parser. "
            f"use --raw -f <path> to dump.")))
        return

    if mode == StandaloneMode.RELAY:
        sessions = parse_relay_result_buffer(raw)
        print(color_string((CG, f"{len(sessions)} relay session(s)")))
        if args.json:
            import json as _json
            # Strip display-only fields (col, decoded) from JSON output
            def _clean(s):
                c = dict(s)
                c['frames'] = [
                    {k: v for k, v in f.items() if k not in ('col', 'decoded')}
                    for f in c.get('frames', [])
                ]
                return c
            out = _json.dumps([_clean(s) for s in sessions], indent=2)
            if args.file:
                Path(args.file).write_text(out)
                print(color_string((CG, f"-> {args.file}")))
            else:
                print(out)
        else:
            print(relay_result_summary(sessions))
        return

    sessions = parse_authtrace_buffer(raw)
    mode_label = mode.name.lower().replace('_', '-')
    print(color_string((CG, f"{len(sessions)} {mode_label} session(s)")))

    if args.json:
        # Convert frames tuples to JSON-serializable dicts
        json_sessions = []
        for s in sessions:
            json_sessions.append({
                "session_num": s["session_num"],
                "status_name": s["status_name"],
                "status_code": s["status_code"],
                "frames": [
                    {"bits": bits, "data": data.hex(), "is_tx": is_tx}
                    for bits, data, is_tx in s["frames"]
                ],
            })
        out = jsonlib.dumps(json_sessions, indent=2)
        if args.file:
            Path(args.file).write_text(out)
            print(color_string((CG, f"-> {args.file}")))
        else:
            print(out)
        return

    if args.dump:
        out = authtrace_pretty_dump(sessions)
        if args.file:
            Path(args.file).write_text(out + "\n")
            print(color_string((CG, f"-> {args.file}")))
        else:
            print(out)
        return

    # default summary
    print(authtrace_summarise(sessions))


@standalone.command('get-result')
class StandaloneGetResult(DeviceRequiredUnit):
    """
    Pull the active mode's result buffer.

    For authtrace, decodes session-tagged wire traces. Default output is
    a one-line summary per session; --dump prints every captured frame
    in Proxmark3 style; --json emits structured data; --raw dumps the
    binary blob (use with -f to save for external decoders).

    To read a specific mode's data regardless of what's currently active,
    use `standalone <mode> get-result` instead (e.g.
    `standalone autoclone get-result`).
    """

    def args_parser(self) -> ArgumentParserNoExit:
        return _standalone_result_args_parser('Read standalone result buffer')

    def on_exec(self, args):
        _state, mode, _flags, _fds = self.cmd.standalone_get_mode()
        raw = self.cmd.standalone_drain_result()
        _standalone_render_result(args, mode, raw)


def _make_mode_get_result_cls(mode: StandaloneMode):
    """Build a get-result command class fixed to one mode, for the
    `standalone <mode> get-result` subgroups below. Shares argument
    parsing and rendering with the current-mode command above -- only
    which mode's buffer gets drained differs."""
    mode_label = mode.name.lower().replace('_', '-')

    class _ModeGetResult(DeviceRequiredUnit):
        __doc__ = (f"Pull the {mode_label} mode's result buffer, regardless of "
                   f"whether it's currently active.")

        def args_parser(self) -> ArgumentParserNoExit:
            return _standalone_result_args_parser(f'Read {mode_label} result buffer')

        def on_exec(self, args):
            raw = self.cmd.standalone_drain_result_for(mode)
            _standalone_render_result(args, mode, raw)

    return _ModeGetResult


def _make_mode_clear_result_cls(mode: StandaloneMode):
    """Build a clear-result command class fixed to one mode, mirroring
    _make_mode_get_result_cls above."""
    mode_label = mode.name.lower().replace('_', '-')

    class _ModeClearResult(DeviceRequiredUnit):
        __doc__ = (f"Discard the {mode_label} mode's result buffer, regardless "
                   f"of whether it's currently active.")

        def args_parser(self) -> ArgumentParserNoExit:
            parser = ArgumentParserNoExit()
            parser.description = f'Clear {mode_label} result buffer'
            return parser

        def on_exec(self, args):
            resp = self.cmd.standalone_clear_result_for(mode)
            if resp.status == Status.SUCCESS:
                print(color_string((CG, "cleared")))
            else:
                print(color_string((CR, f"clear failed: status={resp.status}")))

    return _ModeClearResult


# standalone <mode> get-result / clear-result for every mode: a dedicated
# subgroup per mode, each with the same two commands as above but fixed
# to that mode regardless of what's currently armed. e.g.
# `standalone autoclone get-result`, `standalone autoclone clear-result`.
for _mode in StandaloneMode:
    if _mode == StandaloneMode.DISABLED:
        continue
    _mode_grp = standalone.subgroup(
        _mode.name.lower().replace('_', '-'),
        f"Result data for the {_mode.name.lower().replace('_', '-')} mode")
    _mode_grp.command('get-result')(_make_mode_get_result_cls(_mode))
    _mode_grp.command('clear-result')(_make_mode_clear_result_cls(_mode))


@standalone.command('modes')
class StandaloneModes(DeviceRequiredUnit):
    """
    List standalone modes and whether each is built into this firmware.

    Every mode is excluded by default at build time to keep the image
    small (see CONTRIBUTING STANDALONE.md); this shows what the connected
    device was actually built with, queried from the device itself rather
    than assumed.

    Usage:
        standalone modes
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'List standalone modes and build-time availability'
        return parser

    def on_exec(self, args):
        avail = self.cmd.standalone_get_available()
        if not avail:
            print(color_string((CR,
                "failed to read mode availability from device "
                "(older firmware without this command?)")))
            return

        print(f"  {'mode':<16}  available")
        print(f"  {'-'*16}  ---------")
        for m in StandaloneMode:
            if m == StandaloneMode.DISABLED:
                continue
            name = m.name.lower().replace('_', '-')
            if m < len(avail) and avail[m]:
                print(f"  {CG}{name:<16}{C0}  yes")
            else:
                print(f"  {name:<16}  no")


@standalone.command('ls')
class StandaloneLs(DeviceRequiredUnit):
    """
    List every standalone mode: built into this firmware, and stored data.

    A mode can have stored result data even when it's not currently built
    in -- e.g. after rebuilding with different STANDALONE_* flags -- this
    shows that rather than hiding it, flagged yellow since it's stale.

    Usage:
        standalone ls
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'List standalone modes: built-in status and stored result data'
        return parser

    def on_exec(self, args):
        sizes = self.cmd.standalone_get_sizes()
        if not sizes:
            print(color_string((CR, "failed to read sizes from device")))
            return
        avail = self.cmd.standalone_get_available()  # [] on firmware predating this command

        if avail:
            print(f"  {'mode':<16}  {'built':>5}  {'stored':>8}  {'est. sessions':>14}")
            print(f"  {'-'*16}  {'-'*5}  {'-'*8}  {'-'*14}")
        else:
            print(f"  {'mode':<16}  {'stored':>8}  {'est. sessions':>14}")
            print(f"  {'-'*16}  {'-'*8}  {'-'*14}")

        for m in StandaloneMode:
            if m == StandaloneMode.DISABLED:
                continue
            name = m.name.lower().replace('_', '-')
            sz = sizes[m] if m < len(sizes) else 0
            stored_s = f"{sz:>7}B" if sz > 0 else "      -"
            # Rough session estimate: minimum session = 4 hdr + 20 trace = 24 bytes
            est = f"~{max(1, sz // 64)}" if sz > 0 else "-"

            if avail:
                built = m < len(avail) and avail[m]
                color = CY if (sz > 0 and not built) else (CG if sz > 0 else C0)
                print(f"  {color}{name:<16}{C0}  {'yes' if built else 'no':>5}  {stored_s}  {est:>14}")
            else:
                color = CG if sz > 0 else C0
                print(f"  {color}{name:<16}{C0}  {stored_s}  {est:>14}")


@standalone.command('clear-result')
class StandaloneClearResult(DeviceRequiredUnit):
    """Discard the active mode's result buffer."""

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Clear standalone result buffer'
        return parser

    def on_exec(self, args):
        resp = self.cmd.standalone_clear_result()
        if resp.status == Status.SUCCESS:
            print(color_string((CG, "cleared")))
        else:
            print(color_string((CR, f"clear failed: status={resp.status}")))


@standalone.command('config')
class StandaloneConfig(DeviceRequiredUnit):
    """
    View or set the per-mode config blob.

    AuthTrace config format (16 bytes):
        u8  version=1
        u8  type        (0x60=KEY_A, 0x61=KEY_B)
        u8  block       (target block number)
        u8  reserved0
        u16 timeout_ms  (100..30000)
        u8  key[6]      (candidate sector key)
        u8  reserved1[4]

    HF14A tap-sniff config format (8 bytes):
        u8  version=1
        u8  reserved0
        u16 timeout_ms  (100..30000, per-capture listen duration)
        u8  reserved1[4]

    Examples:
        standalone config authtrace                       (read current)
        standalone config authtrace --block 4 --key-type A
        standalone config authtrace --key FFFFFFFFFFFF --timeout 5000
        standalone config hf14a-tap-sniff                  (read current)
        standalone config hf14a-tap-sniff --timeout 8000
        standalone config read-replay --read-blocks on
        standalone config autoclone --also-slot on
        standalone config dict-check --sectors 16
    """

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Read or write mode-specific config'
        parser.add_argument('mode', help='target mode name')
        parser.add_argument('--block',    type=int, default=None,
                            help='[authtrace] target block (0-255)')
        parser.add_argument('--key-type', choices=['A', 'B'], default=None,
                            help='[authtrace] MIFARE key type')
        parser.add_argument('--key',      default=None,
                            help='[authtrace] 12-hex-char sector key '
                                 '(e.g. FFFFFFFFFFFF)')
        parser.add_argument('--timeout',  type=int, default=None,
                            help='[authtrace] tag-poll timeout in ms (100-30000); '
                                 '[hf14a-tap-sniff] capture duration in ms (100-30000); '
                                 '[relay] WTX ms (500-10000)')
        parser.add_argument('--min-level', choices=list(CANARY_LEVELS), default=None,
                            help='[nfc-canary] ignore windows that never get this deep')
        parser.add_argument('--cooldown', type=int, default=None,
                            help='[nfc-canary] quiet seconds before a window closes (1-255)')
        parser.add_argument('--ble', choices=['off', 'alert', 'end', 'both'], default=None,
                            help='[nfc-canary] which BLE notifications to send')
        parser.add_argument('--read-blocks', choices=['on', 'off'], default=None,
                            help='[read-replay] also read MFC data blocks with the default key')
        parser.add_argument('--also-slot', choices=['on', 'off'], default=None,
                            help='[autoclone] also clone the source into the active slot')
        parser.add_argument('--sectors', type=int, default=None,
                            help='[dict-check] number of sectors to test (1-16)')
        return parser

    def on_exec(self, args):
        try:
            mode = StandaloneMode.from_name(args.mode)
        except ValueError as e:
            print(color_string((CR, str(e))))
            return

        any_setter = any(v is not None for v in
                         (args.block, args.key_type, args.key, args.timeout))

        if mode == StandaloneMode.NFC_CANARY:
            if any_setter:
                print(color_string((CR,
                    "nfc-canary config does not use --block/--key-type/--key/--timeout")))
                return
            blob = self.cmd.standalone_get_config(mode)
            try:
                cfg = canary_cfg_parse(blob)
            except ValueError as e:
                print(color_string((CR, f"stored nfc-canary config is invalid: {e}")))
                return
            if any(v is not None for v in (args.min_level, args.cooldown, args.ble)):
                if args.min_level is not None:
                    cfg['min_level'] = CANARY_LEVELS.index(args.min_level)
                if args.cooldown is not None:
                    if not (1 <= args.cooldown <= 255):
                        print(color_string((CR, "cooldown must be 1..255 seconds")))
                        return
                    cfg['cooldown_s'] = args.cooldown
                if args.ble is not None:
                    cfg['flags'] = {'off': 0, 'alert': 1, 'end': 2, 'both': 3}[args.ble]
                resp = self.cmd.standalone_set_config(mode, canary_cfg_pack(cfg))
                if resp.status != Status.SUCCESS:
                    print(color_string((CR, f"set-config failed: status={resp.status}")))
                    return
            print(color_string((CG, "nfc-canary config:")))
            print(f"  min-level  {CANARY_LEVELS[cfg['min_level']]}")
            print(f"  cooldown   {cfg['cooldown_s']} s")
            print(f"  ble        {['off', 'alert', 'end', 'both'][cfg['flags']]}")
            return

        if mode == StandaloneMode.RELAY:
            if any(v is not None for v in (args.block, args.key_type, args.key)):
                print(color_string((CR,
                    "relay config does not use --block/--key-type/--key")))
                return
            if args.timeout is not None:
                # --timeout reused as WTX ms for relay mode
                wtx_ms = int(args.timeout)
                if wtx_ms < 500 or wtx_ms > 10000:
                    print(color_string((CR,
                        "relay --wtx must be 500-10000 ms")))
                    return
                cfg_hex = '{:02X}{:02X}{:02X}{:02X}'.format(
                    wtx_ms & 0xFF, (wtx_ms >> 8) & 0xFF,
                    (wtx_ms >> 16) & 0xFF, (wtx_ms >> 24) & 0xFF)
                resp = self.cmd.standalone_set_config(
                    StandaloneMode.RELAY.value, cfg_hex)
                if resp.status == Status.SUCCESS:
                    print(color_string((CG,
                        f"relay WTX set to {wtx_ms} ms")))
                return
            # No setter args — read and display current config
            raw = self.cmd.standalone_get_config(StandaloneMode.RELAY.value)
            if raw and len(raw) >= 4:
                wtx_ms = raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24)
            else:
                wtx_ms = 2000  # firmware default
            print(color_string((CG, f"relay config:")))
            print(f"  wtx  {wtx_ms} ms  (time to request from reader via WTX "
                  f"while BLE round-trip completes)"
                  + (color_string((CY, "  [default]")) if not raw or len(raw) < 4 else ""))
            print(f"  link auto-pair nearest available CU in relay mode")
            print(f"  role lower MAC = RELAY_CARD (reader side), "
                  f"higher MAC = RELAY_READER (card side)")
            print(color_string((CY, "Ultra only. Arm both units with both-button chord.")))
            return

        if mode == StandaloneMode.EMUL_TRACE:
            print(color_string((CY,
                "emul_trace has no config — it uses the active emulation slot as-is.\n"
                "Set up your slot normally, then arm the mode.")))
            return

        if mode == StandaloneMode.HF14A_TAP_SNIFF:
            if any(v is not None for v in (args.block, args.key_type, args.key)):
                print(color_string((CR,
                    "hf14a-tap-sniff config does not use --block/--key-type/--key")))
                return
            if args.timeout is not None:
                timeout_ms = int(args.timeout)
                if not (100 <= timeout_ms <= 30000):
                    print(color_string((CR, "timeout must be 100..30000 ms")))
                    return
                cfg = struct.pack('<BBH', 1, 0, timeout_ms) + b'\x00' * 4
                resp = self.cmd.standalone_set_config(mode, cfg)
                if resp.status == Status.SUCCESS:
                    print(color_string((CG,
                        f"hf14a-tap-sniff timeout set to {timeout_ms} ms")))
                else:
                    print(color_string((CR,
                        f"set-config failed: status={resp.status}")))
                return
            # No setter args — read and display current config
            blob = self.cmd.standalone_get_config(mode)
            if blob and len(blob) >= 4:
                ver, _r0, timeout_ms = struct.unpack('<BBH', blob[:4])
                print(color_string((CG, "hf14a-tap-sniff config:")))
                print(f"  version:  {ver}")
                print(f"  timeout:  {timeout_ms} ms")
            else:
                print(color_string((CY,
                    "no persisted config — default timeout 5000 ms")))
            return

        if mode == StandaloneMode.READ_REPLAY:
            if any(v is not None for v in (args.block, args.key_type, args.key, args.timeout)):
                print(color_string((CR,
                    "read-replay config uses only --read-blocks")))
                return
            if args.read_blocks is not None:
                rb = 1 if args.read_blocks == 'on' else 0
                cfg = struct.pack('<BB', 1, rb) + b'\x00' * 2
                resp = self.cmd.standalone_set_config(mode, cfg)
                if resp.status == Status.SUCCESS:
                    print(color_string((CG, f"read-replay read-blocks set to {args.read_blocks}")))
                else:
                    print(color_string((CR, f"set-config failed: status={resp.status}")))
                return
            blob = self.cmd.standalone_get_config(mode)
            if blob and len(blob) >= 2:
                ver, rb = struct.unpack('<BB', blob[:2])
                print(color_string((CG, "read-replay config:")))
                print(f"  version:      {ver}")
                print(f"  read-blocks:  {'on' if rb else 'off'}")
            else:
                print(color_string((CY, "no persisted config — default read-blocks on")))
            print(color_string((CY, "Clones scanned card into the active slot. Needs --opt-in to arm.")))
            return

        if mode == StandaloneMode.AUTOCLONE:
            if any(v is not None for v in (args.block, args.key_type, args.key, args.timeout)):
                print(color_string((CR,
                    "autoclone config uses only --also-slot")))
                return
            if args.also_slot is not None:
                als = 1 if args.also_slot == 'on' else 0
                cfg = struct.pack('<BB', 1, als) + b'\x00' * 2
                resp = self.cmd.standalone_set_config(mode, cfg)
                if resp.status == Status.SUCCESS:
                    print(color_string((CG, f"autoclone also-slot set to {args.also_slot}")))
                else:
                    print(color_string((CR, f"set-config failed: status={resp.status}")))
                return
            blob = self.cmd.standalone_get_config(mode)
            if blob and len(blob) >= 2:
                ver, als = struct.unpack('<BB', blob[:2])
                print(color_string((CG, "autoclone config:")))
                print(f"  version:    {ver}")
                print(f"  also-slot:  {'on' if als else 'off'}")
            else:
                print(color_string((CY, "no persisted config — default also-slot off")))
            print(color_string((CY, "Scan source (1st chord), present magic card (2nd chord). Needs --opt-in to arm.")))
            return

        if mode == StandaloneMode.DICT_CHECK:
            if any(v is not None for v in (args.block, args.key_type, args.key, args.timeout)):
                print(color_string((CR,
                    "dict-check config uses only --sectors")))
                return
            if args.sectors is not None:
                if not (1 <= args.sectors <= 16):
                    print(color_string((CR, "sectors must be 1..16")))
                    return
                cfg = struct.pack('<BB', 1, args.sectors) + b'\x00' * 2
                resp = self.cmd.standalone_set_config(mode, cfg)
                if resp.status == Status.SUCCESS:
                    print(color_string((CG, f"dict-check sectors set to {args.sectors}")))
                else:
                    print(color_string((CR, f"set-config failed: status={resp.status}")))
                return
            blob = self.cmd.standalone_get_config(mode)
            if blob and len(blob) >= 2:
                ver, sectors = struct.unpack('<BB', blob[:2])
                print(color_string((CG, "dict-check config:")))
                print(f"  version:  {ver}")
                print(f"  sectors:  {sectors}")
            else:
                print(color_string((CY, "no persisted config — default 16 sectors")))
            return

        if not any_setter:
            blob = self.cmd.standalone_get_config(mode)
            if not blob:
                print(color_string((CY, f"no persisted config for {mode.name}")))
                return
            if mode == StandaloneMode.AUTHTRACE and len(blob) >= 16:
                ver, typ, block, _r0, timeout = struct.unpack(
                    '<BBBBH', blob[:6])
                key = blob[6:12].hex()
                kname = {0x60: 'A', 0x61: 'B'}.get(typ, f'?(0x{typ:02x})')
                print(f"  version:  {ver}")
                print(f"  type:     {kname} (0x{typ:02x})")
                print(f"  block:    {block}")
                print(f"  timeout:  {timeout} ms")
                print(f"  key:      {key}")
            else:
                print(f"  raw ({len(blob)} bytes): {blob.hex()}")
            return

        if mode != StandaloneMode.AUTHTRACE:
            print(color_string((CR,
                f"config writes only implemented for authtrace; "
                f"raw set-config required for {mode.name}")))
            return

        existing = self.cmd.standalone_get_config(mode)
        if len(existing) >= 16:
            ver     = existing[0]
            typ     = existing[1]
            block   = existing[2]
            timeout = existing[4] | (existing[5] << 8)
            key     = bytes(existing[6:12])
        else:
            ver, typ, block, timeout = 1, 0x60, 4, 3000
            key = b'\xff' * 6

        if args.block    is not None: block   = args.block
        if args.timeout  is not None: timeout = args.timeout
        if args.key_type is not None:
            typ = 0x60 if args.key_type == 'A' else 0x61
        if args.key is not None:
            try:
                key = bytes.fromhex(args.key)
            except ValueError:
                print(color_string((CR, "key must be hex")))
                return
            if len(key) != 6:
                print(color_string((CR,
                    f"key must be 6 bytes; got {len(key)}")))
                return

        if not (100 <= timeout <= 30000):
            print(color_string((CR, "timeout must be 100..30000 ms")))
            return
        if not (0 <= block <= 255):
            print(color_string((CR, "block must be 0..255")))
            return

        cfg = struct.pack('<BBBBH', ver, typ, block, 0, timeout) \
              + key + b'\x00' * 4
        assert len(cfg) == 16

        resp = self.cmd.standalone_set_config(mode, cfg)
        if resp.status == Status.SUCCESS:
            kname = {0x60: 'A', 0x61: 'B'}[typ]
            print(color_string((CG,
                f"ok: type={kname} block={block} timeout={timeout}ms "
                f"key={key.hex()}")))
        else:
            print(color_string((CR,
                f"set-config failed: status={resp.status}")))

@hf_seos.command("eview")
class HFSeosEView(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "View data from emulator memory"
        self.add_slot_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        selected_slot = self.cmd.get_active_slot()
        slot_info = self.cmd.get_slot_info()
        tag_type = TagSpecificType(slot_info[selected_slot]["hf"])

        if tag_type != TagSpecificType.SEOS:
            raise Exception(
                "Card in current slot is not SEOS"
            )
        data = self.cmd.seos_read_emu_data()

        print("[=]        Data:", data["data"].hex().upper())
        print("[=]         OID:", data["oid"].hex().upper())
        print("[=]         Tag:", data["tag"].hex().upper())
        print("[=] Diversifier:", data["diversifier"].hex().upper())

@hf_seos.command("eload")
class HFSeosELoad(SlotIndexArgsAndGoUnit, HF14AAntiCollArgsUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Load data into emulator memory"
        self.add_slot_args(parser)
        self.add_hf14a_anticoll_args(parser)
        parser.add_argument("-d", "--data", type=str, default=None, metavar="<hex>",
                            help="Data to present to reader (2-255 bytes). Must be valid BER-TLV.")
        parser.add_argument("-o", "--oid", type=str, default=None, metavar="<hex>",
                            help=f"Target OID (1-32 bytes).")
        parser.add_argument("-t", "--tag", type=str, default=None, metavar="<hex>",
                            help=f"Tag of presented data (1-2 bytes).")
        parser.add_argument("--diversifier", type=str, default=None, metavar="<hex>",
                            help=f"Simulated card diversifier (1-16 bytes).")
        return parser

    def on_exec(self, args: argparse.Namespace):
        selected_slot = self.cmd.get_active_slot()
        slot_info = self.cmd.get_slot_info()
        tag_type = TagSpecificType(slot_info[selected_slot]["hf"])

        if tag_type != TagSpecificType.SEOS:
            raise Exception(
                "Card in current slot is not SEOS"
            )

        # Handle ISO14443-A anticollision changes
        anti_coll_data = self.cmd.hf14a_get_anti_coll_data()
        if anti_coll_data is None or len(anti_coll_data) == 0:
            print(
                f"{color_string((CR, f'Slot does not contain any HF 14A config'))}"
            )
            return
        uid = anti_coll_data["uid"]
        atqa = anti_coll_data["atqa"]
        sak = anti_coll_data["sak"]
        ats = anti_coll_data["ats"]
        
        change_requested, change_done, uid, atqa, sak, ats = self.update_hf14a_anticoll(
            args, uid, atqa, sak, ats
        )

        if (
            args.data is None and
            args.oid is None and
            args.tag is None and
            args.diversifier is None and
            change_requested is False
        ):
            print(color_string((CR, "Error: No changes were requested.")))


        seos_data = self.cmd.seos_read_emu_data()

        # Parse args
        data = bytes.fromhex(args.data) if args.data else seos_data["data"]
        oid = bytes.fromhex(args.oid) if args.oid else seos_data["oid"]
        tag = bytes.fromhex(args.tag) if args.tag else seos_data["tag"]
        diversifier = bytes.fromhex(args.diversifier) if args.diversifier else seos_data["diversifier"]

        # These are not currently configurable
        hash_alg = seos_data["hash_alg"]
        encr_alg = seos_data["encr_alg"]

        if len(data) < 2 or len(data) > 255:
            print(color_string((CR, "Error: invalid data length. Accepts 2-255 bytes.")))
            return
        if len(oid) < 1 or len(oid) > 32:
            print(color_string((CR, "Error: invalid OID length. Accepts 1-32 bytes.")))
            return
        if len(tag) < 1 or len(tag) > 2:
            print(color_string((CR, "Error: invalid tag length. Accepts 1-2 bytes.")))
            return
        if len(diversifier) < 1 or len(diversifier) > 16:
            print(color_string((CR, "Error: invalid diversifier length. Accepts 1-16 bytes.")))
            return

        self.cmd.seos_write_emu_data(
            data=data,
            oid=oid,
            tag=tag,
            diversifier=diversifier,
            hash_alg=hash_alg,
            encr_alg=encr_alg
        )

@hf_seos.command("keys")
class HFSeosKeys(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Load data into emulator memory"
        self.add_slot_args(parser)
        parser.add_argument("-a", "--auth", type=str, metavar="<hex>", required=True,
                            help="Auth key (16 bytes)")
        parser.add_argument("-e", "--privenc", type=str, metavar="<hex>", required=True,
                            help="PrivEnc key (16 bytes)")
        parser.add_argument("-m", "--privmac", type=str, metavar="<hex>", required=True,
                            help="PrivMac key (16 bytes)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        selected_slot = self.cmd.get_active_slot()
        slot_info = self.cmd.get_slot_info()
        tag_type = TagSpecificType(slot_info[selected_slot]["hf"])

        if tag_type != TagSpecificType.SEOS:
            raise Exception(
                "Card in current slot is not SEOS"
            )

        # Parse args
        auth = bytes.fromhex(args.auth)
        privenc = bytes.fromhex(args.privenc)
        privmac = bytes.fromhex(args.privmac)

        if len(auth) != 16:
            print(color_string((CR, "Error: invalid auth key length. Accepts 16 bytes.")))
            return
        if len(privenc) != 16:
            print(color_string((CR, "Error: invalid PrivEnc key length. Accepts 16 bytes.")))
            return
        if len(privmac) != 16:
            print(color_string((CR, "Error: invalid PrivMac key length. Accepts 16 bytes.")))
            return

        self.cmd.seos_write_emu_keys(
            auth=auth,
            privenc=privenc,
            privmac=privmac
        )
        print(f"\n {CR}No keys found{C0}")


# ---- Indala LF (read, T55xx clone, emulation) : ported from RRG #402 (kevihiiin) ----
def indala_decode_raw(raw: bytes):
    """Decode Indala 26-bit FC/CN from 8-byte raw frame (PM3-compatible bit mapping)."""
    bits = []
    for b in raw:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)

    fc = 0
    fc |= bits[57] << 7
    fc |= bits[49] << 6
    fc |= bits[44] << 5
    fc |= bits[47] << 4
    fc |= bits[48] << 3
    fc |= bits[53] << 2
    fc |= bits[39] << 1
    fc |= bits[58] << 0

    cn = 0
    cn |= bits[42] << 15
    cn |= bits[45] << 14
    cn |= bits[43] << 13
    cn |= bits[40] << 12
    cn |= bits[52] << 11
    cn |= bits[36] << 10
    cn |= bits[35] << 9
    cn |= bits[51] << 8
    cn |= bits[46] << 7
    cn |= bits[33] << 6
    cn |= bits[37] << 5
    cn |= bits[54] << 4
    cn |= bits[56] << 3
    cn |= bits[59] << 2
    cn |= bits[50] << 1
    cn |= bits[41] << 0

    return fc, cn

def indala_encode_raw(fc: int, cn: int) -> bytes:
    """Encode FC/CN into 8-byte Indala 26-bit raw frame (PM3-compatible bit mapping)."""
    bits = [0] * 64

    # preamble
    bits[0] = 1
    bits[2] = 1
    bits[32] = 1

    # fc
    bits[57] = (fc >> 7) & 1
    bits[49] = (fc >> 6) & 1
    bits[44] = (fc >> 5) & 1
    bits[47] = (fc >> 4) & 1
    bits[48] = (fc >> 3) & 1
    bits[53] = (fc >> 2) & 1
    bits[39] = (fc >> 1) & 1
    bits[58] = fc & 1

    # cn
    bits[42] = (cn >> 15) & 1
    bits[45] = (cn >> 14) & 1
    bits[43] = (cn >> 13) & 1
    bits[40] = (cn >> 12) & 1
    bits[52] = (cn >> 11) & 1
    bits[36] = (cn >> 10) & 1
    bits[35] = (cn >> 9) & 1
    bits[51] = (cn >> 8) & 1
    bits[46] = (cn >> 7) & 1
    bits[33] = (cn >> 6) & 1
    bits[37] = (cn >> 5) & 1
    bits[54] = (cn >> 4) & 1
    bits[56] = (cn >> 3) & 1
    bits[59] = (cn >> 2) & 1
    bits[50] = (cn >> 1) & 1
    bits[41] = cn & 1

    # checksum (sum of specific cn bits)
    chk = sum([
        (cn >> 14) & 1, (cn >> 12) & 1, (cn >> 9) & 1, (cn >> 8) & 1,
        (cn >> 6) & 1, (cn >> 5) & 1, (cn >> 2) & 1, cn & 1,
    ])
    if chk % 2 == 0:
        bits[62], bits[63] = 1, 0
    else:
        bits[62], bits[63] = 0, 1

    # parity
    p1, p2 = 1, 1
    for i in range(33, 64):
        if i % 2:
            p1 ^= bits[i]
        else:
            p2 ^= bits[i]
    bits[34] = p1
    bits[38] = p2

    raw = bytearray(8)
    for i in range(64):
        if bits[i]:
            raw[i // 8] |= 1 << (7 - (i % 8))
    return bytes(raw)

def indala_format_output(raw: bytes) -> str:
    """Format Indala raw bytes as PM3-style output string."""
    fc, cn = indala_decode_raw(raw)
    lines = [f"Indala (len 64)  Raw: {raw.hex().upper()}"]
    lines.append(f"   Fmt 26  FC: {fc}  Card: {cn}")
    return "\n".join(lines)
