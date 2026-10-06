"""cli_hf_mf — MIFARE Classic commands (hf mf ...).

Recovery (nested, darkside, hardnested, static-nested, autopwn, fchk), read/
write/dump/clone, value blocks, emulation slot load/save, and sim. Split out
of chameleon_cli_unit; foundation imported explicitly from cli_core."""

import re
import binascii
import sys
import math
import glob
import random
import datetime
import os
import time
import struct
import argparse
import tempfile
import json
from pathlib import Path
from multiprocessing import Pool, cpu_count

from cli_core import (
    _run_mfkey32v2,
    ArgsParserError,
    ArgumentParserNoExit,
    BaseCLIUnit,
    C0,
    CC,
    CG,
    CR,
    CY,
    Crypto1,
    DeviceRequiredUnit,
    HF14AAntiCollArgsUnit,
    MF1AuthArgsUnit,
    MfcKeyType,
    MfcValueBlockOperator,
    MifareClassicDarksideStatus,
    MifareClassicWriteMode,
    ReaderRequiredUnit,
    SlotIndexArgsAndGoUnit,
    SlotNumber,
    Status,
    TagSenseType,
    TagSpecificType,
    UnexpectedResponseError,
    Union,
    chameleon_com,
    chameleon_pm3,
    color_string,
    data,
    execute_tool,
    hardnested_utils,
    hf,
    hf_mf,
    load_dic_file,
    load_key_file,
    print_key_table,
    print_mem_dump,
    tqdm_if_exists,
)


@hf_mf.command("nested")
class HFMFNested(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Mifare Classic nested recover key"
        parser.add_argument(
            "--blk",
            "--known-block",
            type=int,
            required=True,
            metavar="<dec>",
            help="Known key block number",
        )
        srctype_group = parser.add_mutually_exclusive_group()
        srctype_group.add_argument(
            "-a", "-A", action="store_true", help="Known key is A key (default)"
        )
        srctype_group.add_argument(
            "-b", "-B", action="store_true", help="Known key is B key"
        )
        parser.add_argument(
            "-k", "--key", type=str, required=True, metavar="<hex>", help="Known key"
        )
        # tblk required because only single block mode is supported for now
        parser.add_argument(
            "--tblk",
            "--target-block",
            type=int,
            required=True,
            metavar="<dec>",
            help="Target key block number",
        )
        dsttype_group = parser.add_mutually_exclusive_group()
        dsttype_group.add_argument(
            "--ta", "--tA", action="store_true", help="Target A key (default)"
        )
        dsttype_group.add_argument(
            "--tb", "--tB", action="store_true", help="Target B key"
        )
        return parser

    def from_nt_level_code_to_str(self, nt_level):
        if nt_level == 0:
            return "StaticNested"
        if nt_level == 1:
            return "Nested"
        if nt_level == 2:
            return "HardNested"

    def recover_a_key(
        self, block_known, type_known, key_known, block_target, type_target
    ) -> Union[str, None]:
        """
            recover a key from key known.

        :param block_known:
        :param type_known:
        :param key_known:
        :param block_target:
        :param type_target:
        :return:
        """
        # check nt level, we can run static or nested auto...
        nt_level = self.cmd.mf1_detect_prng()
        print(
            f" - NT vulnerable: {color_string((CY, self.from_nt_level_code_to_str(nt_level)))}"
        )
        if nt_level == 2:
            print(" [!] Use hf mf hardnested")
            return None

        # acquire
        if nt_level == 0:  # It's a staticnested tag?
            nt_uid_obj = self.cmd.mf1_static_nested_acquire(
                block_known, type_known, key_known, block_target, type_target
            )
            cmd_param = f"{nt_uid_obj['uid']} {int(type_target)}"
            for nt_item in nt_uid_obj["nts"]:
                cmd_param += f" {nt_item['nt']} {nt_item['nt_enc']}"
            tool_name = "staticnested"
        else:
            dist_obj = self.cmd.mf1_detect_nt_dist(block_known, type_known, key_known)
            nt_obj = self.cmd.mf1_nested_acquire(
                block_known, type_known, key_known, block_target, type_target
            )
            # create cmd
            cmd_param = f"{dist_obj['uid']} {dist_obj['dist']}"
            for nt_item in nt_obj:
                cmd_param += f" {nt_item['nt']} {nt_item['nt_enc']} {nt_item['par']}"
            tool_name = "nested"

        # Cross-platform compatibility
        if sys.platform == "win32":
            cmd_recover = f"{tool_name}.exe {cmd_param}"
        else:
            cmd_recover = f"./{tool_name} {cmd_param}"

        print(f"   Executing {cmd_recover}")
        # start a decrypt process
        process = self.sub_process(cmd_recover)

        # wait end
        while process.is_running():
            msg = f"   [ Time elapsed {process.get_time_distance()/1000:#.1f}s ]\r"
            print(msg, end="")
            time.sleep(0.1)
        # clear \r
        print()

        if process.get_ret_code() == 0:
            output_str = process.get_output_sync()
            key_list = []
            for line in output_str.split("\n"):
                sea_obj = re.search(r"([a-fA-F0-9]{12})", line)
                if sea_obj is not None:
                    key_list.append(sea_obj[1])
            # Here you have to verify the password first, and then get the one that is successfully verified
            # If there is no verified password, it means that the recovery failed, you can try again
            print(f" - [{len(key_list)} candidate key(s) found ]")
            for key in key_list:
                key_bytes = bytearray.fromhex(key)
                if self.cmd.mf1_auth_one_key_block(
                    block_target, type_target, key_bytes
                ):
                    return key
        else:
            # No keys recover, and no errors.
            return None

    def on_exec(self, args: argparse.Namespace):
        block_known = args.blk
        # default to A
        type_known = MfcKeyType.B if args.b else MfcKeyType.A
        key_known: str = args.key
        if not re.match(r"^[a-fA-F0-9]{12}$", key_known):
            print("key must include 12 HEX symbols")
            return
        key_known_bytes = bytes.fromhex(key_known)
        block_target = args.tblk
        # default to A
        type_target = MfcKeyType.B if args.tb else MfcKeyType.A
        if block_known == block_target and type_known == type_target:
            print(color_string((CR, "Target key already known")))
            return
        print(" - Nested recover one key running...")
        key = self.recover_a_key(
            block_known, type_known, key_known_bytes, block_target, type_target
        )
        if key is None:
            print(color_string((CY, "\nNo key found, you can retry.")))
        else:
            print(
                f"\n - Block {block_target} Type {type_target.name} Key Found: {color_string((CG, key))}"
            )
        return


@hf_mf.command("darkside")
class HFMFDarkside(ReaderRequiredUnit):
    def __init__(self):
        super().__init__()
        self.darkside_list = []

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Mifare Classic darkside recover key"
        return parser

    def recover_key(self, block_target, type_target):
        """
            Execute darkside acquisition and decryption.

        :param block_target:
        :param type_target:
        :return:
        """
        first_recover = True
        retry_count = 0
        while retry_count < 0xFF:
            darkside_resp = self.cmd.mf1_darkside_acquire(
                block_target, type_target, first_recover, 30
            )
            first_recover = False  # not first run.
            if darkside_resp[0] != MifareClassicDarksideStatus.OK:
                print(
                    f"Darkside error: {MifareClassicDarksideStatus(darkside_resp[0])}"
                )
                break
            darkside_obj = darkside_resp[1]

            if darkside_obj["par"] != 0:  # NXP tag workaround.
                self.darkside_list.clear()

            self.darkside_list.append(darkside_obj)
            recover_params = f"{darkside_obj['uid']}"
            for darkside_item in self.darkside_list:
                recover_params += f" {darkside_item['nt1']} {darkside_item['ks1']} {darkside_item['par']}"
                recover_params += f" {darkside_item['nr']} {darkside_item['ar']}"
            if sys.platform == "win32":
                cmd_recover = f"darkside.exe {recover_params}"
            else:
                cmd_recover = f"./darkside {recover_params}"
            # subprocess.run(cmd_recover, cwd=os.path.abspath("../bin/"), shell=True)
            # print(f"   Executing {cmd_recover}")
            # start a decrypt process
            process = self.sub_process(cmd_recover)
            # wait end
            process.wait_process()
            # get output
            output_str = process.get_output_sync()
            if "key not found" in output_str:
                print(f" - No key found, retrying({retry_count})...")
                retry_count += 1
                continue  # retry
            else:
                key_list = []
                for line in output_str.split("\n"):
                    sea_obj = re.search(r"([a-fA-F0-9]{12})", line)
                    if sea_obj is not None:
                        key_list.append(sea_obj[1])
                # auth key
                for key in key_list:
                    key_bytes = bytearray.fromhex(key)
                    if self.cmd.mf1_auth_one_key_block(
                        block_target, type_target, key_bytes
                    ):
                        return key
        return None

    def on_exec(self, args: argparse.Namespace):
        key = self.recover_key(0x03, MfcKeyType.A)
        if key is not None:
            print(f" - Key Found: {key}")
        else:
            print(" - Key recover fail.")
        return


@hf_mf.command("hardnested")
class HFMFHardNested(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Mifare Classic hardnested recover key "
        parser.add_argument(
            "--blk",
            "--known-block",
            type=int,
            required=True,
            metavar="<dec>",
            help="Known key block number",
        )
        srctype_group = parser.add_mutually_exclusive_group()
        srctype_group.add_argument(
            "-a", "-A", action="store_true", help="Known key is A key (default)"
        )
        srctype_group.add_argument(
            "-b", "-B", action="store_true", help="Known key is B key"
        )
        parser.add_argument(
            "-k", "--key", type=str, required=True, metavar="<hex>", help="Known key"
        )
        parser.add_argument(
            "--tblk",
            "--target-block",
            type=int,
            required=True,
            metavar="<dec>",
            help="Target key block number",
        )
        dsttype_group = parser.add_mutually_exclusive_group()
        dsttype_group.add_argument(
            "--ta", "--tA", action="store_true", help="Target A key (default)"
        )
        dsttype_group.add_argument(
            "--tb", "--tB", action="store_true", help="Target B key"
        )
        parser.add_argument(
            "--slow",
            action="store_true",
            help="Use slower acquisition mode (more nonces)",
        )
        parser.add_argument(
            "--keep-nonce-file",
            action="store_true",
            help="Keep the generated nonce file (nonces.bin)",
        )
        parser.add_argument(
            "--max-runs",
            type=int,
            default=200,
            metavar="<dec>",
            help="Maximum acquisition runs per attempt before giving up (default: 200)",
        )
        # Add max acquisition attempts
        parser.add_argument(
            "--max-attempts",
            type=int,
            default=3,
            metavar="<dec>",
            help="Maximum acquisition attempts if MSB sum is invalid (default: 3)",
        )
        return parser

    def recover_key(
        self,
        slow_mode,
        block_known,
        type_known,
        key_known,
        block_target,
        type_target,
        keep_nonce_file,
        max_runs,
        max_attempts,
    ):
        """
        Recover a key using the HardNested attack via a nonce file, with dynamic MSB-based acquisition and restart on invalid sum.

        :param slow_mode: Boolean indicating if slow mode should be used.
        :param block_known: Known key block number.
        :param type_known: Known key type (A or B).
        :param key_known: Known key bytes.
        :param block_target: Target key block number.
        :param type_target: Target key type (A or B).
        :param keep_nonce_file: Boolean indicating whether to keep the nonce file.
        :param max_runs: Maximum number of acquisition runs per attempt.
        :param max_attempts: Maximum number of full acquisition attempts.
        :return: Recovered key as a hex string, or None if not found.
        """
        print(" - Starting HardNested attack...")
        nonces_buffer = bytearray()  # This will hold the final data for the file
        uid_bytes = b""  # To store UID from the successful attempt

        # --- Outer loop for acquisition attempts ---
        acquisition_success = False  # Flag to indicate if any attempt was successful
        for attempt in range(max_attempts):
            print(
                f"\n--- Starting Acquisition Attempt {attempt + 1}/{max_attempts} ---"
            )
            total_raw_nonces_bytes = (
                bytearray()
            )  # Accumulator for raw nonces for THIS attempt
            nonces_buffer.clear()  # Clear buffer for each new attempt

            # --- MSB Tracking Initialization (Reset for each attempt) ---
            seen_msbs = [False] * 256
            unique_msb_count = 0
            msb_parity_sum = 0
            # --- End MSB Tracking Initialization ---

            run_count = 0
            acquisition_goal_met = False

            # 1. Scan for the tag to get UID and prepare file header (Done ONCE per attempt)
            print("   Scanning for tag...")
            try:
                scan_resp = self.cmd.hf14a_scan()
            except Exception as e:
                print(color_string((CR, f"   Error scanning tag: {e}")))
                # Decide if we should retry or fail completely. Let's fail for now.
                print(
                    color_string((CR, "   Attack failed due to error during scanning."))
                )
                return None

            if scan_resp is None or len(scan_resp) == 0:
                print(color_string((CR, "Error: No tag found.")))
                if attempt + 1 < max_attempts:
                    print(color_string((CY, "   Retrying scan in 1 second...")))
                    time.sleep(1)
                    continue  # Retry the outer loop (next attempt)
                else:
                    print(
                        color_string(
                            (
                                CR,
                                "   Maximum attempts reached without finding tag. Attack failed.",
                            )
                        )
                    )
                    return None
            if len(scan_resp) > 1:
                print(
                    color_string(
                        (
                            CR,
                            "   Error: Multiple tags found. Please present only one tag.",
                        )
                    )
                )
                # Fail immediately if multiple tags are present
                return None

            tag_info = scan_resp[0]
            uid_bytes = tag_info["uid"]  # Store UID for later verification
            uid_len = len(uid_bytes)
            uid_for_file = b""
            if uid_len == 4:
                uid_for_file = uid_bytes[0:4]
            elif uid_len == 7:
                uid_for_file = uid_bytes[3:7]
            elif uid_len == 10:
                uid_for_file = uid_bytes[6:10]
            else:
                print(
                    color_string(
                        (
                            CR,
                            f"   Error: Unexpected UID length ({uid_len} bytes). Cannot create nonce file header.",
                        )
                    )
                )
                return None  # Fail if UID length is unexpected
            print(f"   Tag found with UID: {uid_bytes.hex().upper()}")
            # Prepare header in the main buffer for this attempt
            nonces_buffer.extend(uid_for_file)
            nonces_buffer.extend(
                struct.pack("!BB", block_target, type_target.value & 0x01)
            )
            print(f"   Nonce file header prepared: {nonces_buffer.hex().upper()}")

            # 2. Acquire nonces dynamically based on MSB criteria (Inner loop for runs)
            print(
                f"   Acquiring nonces (slow mode: {slow_mode}, max runs: {max_runs}). This may take a while..."
            )
            while run_count < max_runs:
                run_count += 1
                print(f"   Starting acquisition run {run_count}/{max_runs}...")
                try:
                    # Check if tag is still present before each run
                    current_scan = self.cmd.hf14a_scan()
                    if (
                        current_scan is None
                        or len(current_scan) == 0
                        or current_scan[0]["uid"] != uid_bytes
                    ):
                        print(
                            color_string(
                                (
                                    CY,
                                    f"   Error: Tag lost or changed before run {run_count}. Stopping acquisition attempt.",
                                )
                            )
                        )
                        acquisition_goal_met = False  # Mark as failed
                        break  # Exit inner run loop for this attempt

                    # Acquire nonces for this run
                    raw_nonces_bytes_this_run = self.cmd.mf1_hard_nested_acquire(
                        slow_mode,
                        block_known,
                        type_known,
                        key_known,
                        block_target,
                        type_target,
                    )

                    if not raw_nonces_bytes_this_run:
                        print(
                            color_string(
                                (
                                    CY,
                                    f"   Run {run_count}: No nonces acquired in this run. Continuing...",
                                )
                            )
                        )
                        time.sleep(0.1)  # Small delay before retrying
                        continue

                    # Append successfully acquired nonces to the total buffer for this attempt
                    total_raw_nonces_bytes.extend(raw_nonces_bytes_this_run)

                    # --- Process acquired nonces for MSB tracking ---
                    num_pairs_this_run = len(raw_nonces_bytes_this_run) // 9
                    print(
                        f"   Run {run_count}: Acquired {num_pairs_this_run * 2} nonces ({len(raw_nonces_bytes_this_run)} bytes raw). Processing MSBs..."
                    )

                    new_msbs_found_this_run = 0
                    for i in range(num_pairs_this_run):
                        offset = i * 9
                        try:
                            nt, nt_enc, par = struct.unpack_from(
                                "!IIB", raw_nonces_bytes_this_run, offset
                            )
                        except struct.error as unpack_err:
                            print(
                                color_string(
                                    (
                                        CR,
                                        f"   Error unpacking nonce data at offset {offset}: {unpack_err}. Skipping pair.",
                                    )
                                )
                            )
                            continue

                        msb = (nt_enc >> 24) & 0xFF

                        if not seen_msbs[msb]:
                            seen_msbs[msb] = True
                            unique_msb_count += 1
                            new_msbs_found_this_run += 1
                            parity_bit = hardnested_utils.evenparity32(
                                (nt_enc & 0xFF000000) | (par & 0x08)
                            )
                            msb_parity_sum += parity_bit
                            print(
                                f"\r   Unique MSBs: {unique_msb_count}/256 | Current Sum: {msb_parity_sum}   ",
                                end="",
                            )

                    if new_msbs_found_this_run > 0:
                        print()  # Print a newline after progress update

                    # --- Check termination condition ---
                    if unique_msb_count == 256:
                        print()
                        print(
                            f"{color_string((CG, '   All 256 unique MSBs found.'))} Final parity sum: {msb_parity_sum}"
                        )
                        if msb_parity_sum in hardnested_utils.hardnested_sums:
                            print(
                                color_string(
                                    (
                                        CG,
                                        f"   Parity sum {msb_parity_sum} is VALID. Stopping acquisition runs.",
                                    )
                                )
                            )
                            acquisition_goal_met = True
                            acquisition_success = True  # Mark attempt as successful
                            break  # Exit the inner run loop successfully
                        else:
                            print(
                                color_string(
                                    (
                                        CR,
                                        f"   Parity sum {msb_parity_sum} is INVALID (Expected one of {hardnested_utils.hardnested_sums}).",
                                    )
                                )
                            )
                            acquisition_goal_met = False  # Mark as failed
                            acquisition_success = False
                            break  # Exit the inner run loop to restart the attempt

                except chameleon_com.CMDInvalidException:
                    print(
                        color_string(
                            (
                                CR,
                                "   Error: Hardnested command not supported by this firmware version.",
                            )
                        )
                    )
                    return None  # Cannot proceed at all
                except UnexpectedResponseError as e:
                    print(
                        color_string(
                            (
                                CR,
                                f"   Error acquiring nonces during run {run_count}: {e}",
                            )
                        )
                    )
                    print(
                        color_string(
                            (CY, "   Stopping acquisition runs for this attempt...")
                        )
                    )
                    acquisition_goal_met = False
                    break  # Exit inner run loop
                except TimeoutError:
                    print(
                        color_string(
                            (
                                CR,
                                f"   Error: Timeout during nonce acquisition run {run_count}.",
                            )
                        )
                    )
                    print(
                        color_string(
                            (CY, "   Stopping acquisition runs for this attempt...")
                        )
                    )
                    acquisition_goal_met = False
                    break  # Exit inner run loop
                except Exception as e:
                    print(
                        color_string(
                            (
                                CR,
                                f"   Unexpected error during acquisition run {run_count}: {e}",
                            )
                        )
                    )
                    print(
                        color_string(
                            (CY, "   Stopping acquisition runs for this attempt...")
                        )
                    )
                    acquisition_goal_met = False
                    break  # Exit inner run loop
            # --- End of inner run loop (while run_count < max_runs) ---

            # --- Post-Acquisition Summary for this attempt ---
            print(f"\n   Finished acquisition phase for attempt {attempt + 1}.")
            if acquisition_success:
                print(
                    color_string(
                        (
                            CG,
                            f"   Successfully acquired nonces meeting the MSB sum criteria in {run_count} runs.",
                        )
                    )
                )
                # Append collected raw nonces to the main buffer for the file
                nonces_buffer.extend(total_raw_nonces_bytes)
                break  # Exit the outer attempt loop successfully
            elif unique_msb_count == 256 and not acquisition_goal_met:
                print(
                    color_string(
                        (CR, "   Found all 256 MSBs, but the parity sum was invalid.")
                    )
                )
                if attempt + 1 < max_attempts:
                    print(color_string((CY, "   Restarting acquisition process...")))
                    time.sleep(1)  # Small delay before restarting
                    continue  # Continue to the next iteration of the outer attempt loop
                else:
                    print(
                        color_string(
                            (
                                CR,
                                f"   Maximum attempts ({max_attempts}) reached with invalid sum. Attack failed.",
                            )
                        )
                    )
                    return None  # Failed after max attempts
            elif run_count >= max_runs:
                print(
                    color_string(
                        (
                            CY,
                            f"   Warning: Reached max runs ({max_runs}) for attempt {attempt + 1}. Found {unique_msb_count}/256 unique MSBs.",
                        )
                    )
                )
                if attempt + 1 < max_attempts:
                    print(color_string((CY, "   Restarting acquisition process...")))
                    time.sleep(1)
                    continue  # Continue to the next iteration of the outer attempt loop
                else:
                    print(
                        color_string(
                            (
                                CR,
                                f"   Maximum attempts ({max_attempts}) reached without meeting criteria. Attack failed.",
                            )
                        )
                    )
                    return None  # Failed after max attempts
            else:  # Acquisition stopped due to error or tag loss
                print(
                    color_string(
                        (
                            CR,
                            f"Acquisition attempt {attempt + 1} stopped prematurely due to an error after {run_count} runs.",
                        )
                    )
                )
                # Decide if we should retry or fail completely. Let's fail for now.
                print(
                    color_string((CR, "Attack failed due to error during acquisition."))
                )
                return None  # Failed due to error

        # --- End of outer attempt loop ---

        # If we exited the loop successfully (acquisition_success is True)
        if not acquisition_success:
            # This case should ideally be caught within the loop, but as a safeguard:
            print(
                color_string(
                    (CR, f"   Error: Acquisition failed after {max_attempts} attempts.")
                )
            )
            return None

        # --- Proceed with the rest of the attack using the successfully collected nonces ---
        total_nonce_pairs = (
            len(total_raw_nonces_bytes) // 9
        )  # Use data from the successful attempt
        print(
            f"\n   Proceeding with attack using {total_nonce_pairs * 2} nonces ({len(total_raw_nonces_bytes)} bytes raw)."
        )
        print(f"   Total nonce file size will be {len(nonces_buffer)} bytes.")

        if total_nonce_pairs == 0:
            print(
                color_string(
                    (
                        CR,
                        "   Error: No nonces were successfully acquired in the final attempt.",
                    )
                )
            )
            return None

        # 3. Save nonces to a temporary file
        nonce_file_path = None
        temp_nonce_file = None
        output_str = ""  # To store the output read from the file

        try:
            # --- Nonce File Handling ---
            delete_nonce_on_close = not keep_nonce_file
            # Use delete_on_close=False to manage deletion manually in finally block
            temp_nonce_file = tempfile.NamedTemporaryFile(
                suffix=".bin",
                prefix="hardnested_nonces_",
                delete=False,
                mode="wb",
                dir=".",
            )
            temp_nonce_file.write(
                nonces_buffer
            )  # Write the buffer from the successful attempt
            temp_nonce_file.flush()
            nonce_file_path = temp_nonce_file.name
            temp_nonce_file.close()  # Close it so hardnested can access it
            temp_nonce_file = None  # Clear variable after closing
            print(
                f"   Nonces saved to {'temporary ' if delete_nonce_on_close else ''}file: {os.path.abspath(nonce_file_path)}"
            )

            # 4. Prepare and run the external hardnested tool, redirecting output
            print(
                color_string(
                    (CC, "--- Running Hardnested Tool (Output redirected) ---")
                )
            )

            output_str = execute_tool("hardnested", [os.path.abspath(nonce_file_path)])

            print(color_string((CC, "--- Hardnested Tool Finished ---")))

            # 5. Read the output from the temporary log file
            # 6. Process the result (using output_str read from the file)
            key_list = []
            key_prefix = "Key found: "  # Define the specific prefix to look for
            for line in output_str.splitlines():
                line_stripped = line.strip()  # Remove leading/trailing whitespace
                if line_stripped.startswith(key_prefix):
                    # Found the target line, now extract the key using regex
                    # Regex now looks for 12 hex chars specifically after the prefix
                    sea_obj = re.search(
                        r"([a-fA-F0-9]{12})", line_stripped[len(key_prefix) :]
                    )
                    if sea_obj:
                        key_list.append(sea_obj.group(1))
                        # Optional: Break if you only expect one "Key found:" line
                        # break

            if not key_list:
                print(
                    color_string(
                        (
                            CY,
                            f"   No line starting with '{key_prefix}' found in the output file.",
                        )
                    )
                )
                return None

            # 7. Verify Keys (Same as before)
            print(
                f"   [{len(key_list)} candidate key(s) found in output. Verifying...]"
            )
            # Use the UID from the successful acquisition attempt
            uid_bytes_for_verify = (
                uid_bytes  # From the last successful scan in the outer loop
            )

            for key_hex in key_list:
                key_bytes = bytes.fromhex(key_hex)
                print(f"   Trying key: {key_hex.upper()}...", end="")
                try:
                    # Check tag presence before auth attempt
                    scan_check = self.cmd.hf14a_scan()
                    if (
                        scan_check is None
                        or len(scan_check) == 0
                        or scan_check[0]["uid"] != uid_bytes_for_verify
                    ):
                        print(
                            color_string(
                                (
                                    CR,
                                    " Tag lost or changed during verification. Cannot verify.",
                                )
                            )
                        )
                        return None  # Stop verification if tag is gone

                    if self.cmd.mf1_auth_one_key_block(
                        block_target, type_target, key_bytes
                    ):
                        print(color_string((CG, " Success!")))
                        return key_hex  # Return the verified key
                    else:
                        print(color_string((CR, "Auth failed.")))
                except UnexpectedResponseError as e:
                    print(color_string((CR, f" Verification error: {e}")))
                    # Consider if we should continue trying other keys or stop
                except Exception as e:
                    print(
                        color_string(
                            (CR, f" Unexpected error during verification: {e}")
                        )
                    )
                    # Consider stopping here

            print(color_string((CY, "   Verification failed for all candidate keys.")))
            return None

        finally:
            # 8. Clean up nonce file
            if nonce_file_path and os.path.exists(nonce_file_path):
                if keep_nonce_file:
                    final_nonce_filename = "nonces.bin"
                    try:
                        if os.path.exists(final_nonce_filename):
                            os.remove(final_nonce_filename)
                        # Use replace for atomicity if possible
                        os.replace(nonce_file_path, final_nonce_filename)
                        print(
                            f"   Nonce file kept as: {os.path.abspath(final_nonce_filename)}"
                        )
                    except OSError as e:
                        print(
                            color_string(
                                (
                                    CR,
                                    f"   Error renaming/replacing temporary nonce file to {final_nonce_filename}: {e}",
                                )
                            )
                        )
                        print(f"   Temporary file might remain: {nonce_file_path}")
                else:
                    try:
                        os.remove(nonce_file_path)
                        # print(f"   Temporary nonce file deleted: {nonce_file_path}") # Optional confirmation
                    except OSError as e:
                        print(
                            color_string(
                                (
                                    CR,
                                    f"   Error deleting temporary nonce file {nonce_file_path}: {e}",
                                )
                            )
                        )

    def on_exec(self, args: argparse.Namespace):
        block_known = args.blk
        type_known = MfcKeyType.B if args.b else MfcKeyType.A
        key_known_str: str = args.key
        if not re.match(r"^[a-fA-F0-9]{12}$", key_known_str):
            raise ArgsParserError("Known key must include 12 HEX symbols")
        key_known_bytes = bytes.fromhex(key_known_str)

        block_target = args.tblk
        type_target = MfcKeyType.B if args.tb else MfcKeyType.A

        if block_known == block_target and type_known == type_target:
            print(color_string((CR, "Target key is the same as the known key.")))
            return

        # Pass the max_runs and max_attempts arguments
        recovered_key = self.recover_key(
            args.slow,
            block_known,
            type_known,
            key_known_bytes,
            block_target,
            type_target,
            args.keep_nonce_file,
            args.max_runs,
            args.max_attempts,
        )

        if recovered_key:
            print(
                f" - Key Found: Block {block_target} Type {type_target.name} Key = {color_string((CG, recovered_key.upper()))}"
            )
        else:
            print(color_string((CR, " - HardNested attack failed to recover the key.")))


@hf_mf.command("senested")
class HFMFStaticEncryptedNested(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Mifare Classic static encrypted recover key via backdoor"
        parser.add_argument(
            "--key",
            "-k",
            help="Backdoor key (as hex[12] format), currently known: A396EFA4E24F (default), A31667A8CEC1, 518B3354E760. See https://eprint.iacr.org/2024/1275",
            metavar="<hex>",
            type=str,
        )
        parser.add_argument(
            "--sectors", "-s", type=int, metavar="<dec>", help="Sector count"
        )
        parser.add_argument(
            "--starting-sector",
            type=int,
            metavar="<dec>",
            help="Start recovery from this sector",
        )
        parser.set_defaults(sectors=16)
        parser.set_defaults(starting_sector=0)
        parser.set_defaults(key="A396EFA4E24F")
        return parser

    def on_exec(self, args: argparse.Namespace):
        key_map = self.senested(
            args.key, args.starting_sector, args.sectors, args.sectors
        )
        print_key_table(key_map)

    def senested(self, key, starting_sector, stopping_sector, sectors):
        acquire_datas = self.cmd.mf1_static_encrypted_nested_acquire(
            bytes.fromhex(key), sectors, starting_sector
        )

        if not acquire_datas:
            print("Failed to collect nonces, is card present and has backdoor?")

        uid = format(acquire_datas["uid"], "x")

        key_map = {"A": {}, "B": {}}

        check_speed = 1.95  # sec per 64 keys

        for sector in range(starting_sector, stopping_sector):
            sector_name = str(sector).zfill(2)
            print("Recovering", sector, "sector...")
            execute_tool(
                "staticnested_1nt",
                [
                    uid,
                    sector_name,
                    format(acquire_datas["nts"]["a"][sector]["nt"], "x").zfill(8),
                    format(acquire_datas["nts"]["a"][sector]["nt_enc"], "x").zfill(8),
                    str(acquire_datas["nts"]["a"][sector]["parity"]).zfill(4),
                ],
            )
            execute_tool(
                "staticnested_1nt",
                [
                    uid,
                    sector_name,
                    format(acquire_datas["nts"]["b"][sector]["nt"], "x").zfill(8),
                    format(acquire_datas["nts"]["b"][sector]["nt_enc"], "x").zfill(8),
                    str(acquire_datas["nts"]["b"][sector]["parity"]).zfill(4),
                ],
            )
            a_key_dic = f"keys_{uid}_{sector_name}_{format(acquire_datas['nts']['a'][sector]['nt'], 'x').zfill(8)}.dic"
            b_key_dic = f"keys_{uid}_{sector_name}_{format(acquire_datas['nts']['b'][sector]['nt'], 'x').zfill(8)}.dic"
            execute_tool("staticnested_2x1nt_rf08s", [a_key_dic, b_key_dic])

            keys = open(
                os.path.join(
                    tempfile.gettempdir(), b_key_dic.replace(".dic", "_filtered.dic")
                )
            ).readlines()
            keys_bytes = []
            for key in keys:
                keys_bytes.append(bytes.fromhex(key.strip()))

            key = None

            print(
                "Start checking possible B keys, will take up to",
                math.floor(len(keys_bytes) / 64 * check_speed),
                "seconds for",
                len(keys_bytes),
                "keys",
            )
            for i in tqdm_if_exists(range(0, len(keys_bytes), 64)):
                data = self.cmd.mf1_check_keys_on_block(
                    sector * 4 + 3, 0x61, keys_bytes[i : i + 64]
                )
                if data:
                    key = data.hex().zfill(12)
                    key_map["B"][sector] = key
                    print("Found B key", key)
                    break

            if key:
                a_key = execute_tool(
                    "staticnested_2x1nt_rf08s_1key",
                    [
                        format(acquire_datas["nts"]["b"][sector]["nt"], "x").zfill(8),
                        key,
                        a_key_dic,
                    ],
                )
                keys_bytes = []
                for key in a_key.split("\n"):
                    keys_bytes.append(bytes.fromhex(key.strip()))
                data = self.cmd.mf1_check_keys_on_block(
                    sector * 4 + 3, 0x60, keys_bytes
                )
                if data:
                    key = data.hex().zfill(12)
                    print("Found A key", key)
                    key_map["A"][sector] = key
                    continue
                else:
                    print(
                        "Failed to find A key by fast method, trying all possible keys"
                    )
                    keys = open(
                        os.path.join(
                            tempfile.gettempdir(),
                            a_key_dic.replace(".dic", "_filtered.dic"),
                        )
                    ).readlines()
                    keys_bytes = []
                    for key in keys:
                        keys_bytes.append(bytes.fromhex(key.strip()))

                    print(
                        "Start checking possible A keys, will take up to",
                        math.floor(len(keys_bytes) / 64 * check_speed),
                        "seconds for",
                        len(keys_bytes),
                        "keys",
                    )
                    for i in tqdm_if_exists(range(0, len(keys_bytes), 64)):
                        data = self.cmd.mf1_check_keys_on_block(
                            sector * 4 + 3, 0x60, keys_bytes[i : i + 64]
                        )
                        if data:
                            key = data.hex().zfill(12)
                            print("Found A key", key)
                            key_map["A"][sector] = key
                            break
            else:
                print("Failed to find key")

        for file in glob.glob(tempfile.gettempdir() + "/keys_*.dic"):
            os.remove(file)

        return key_map


@hf_mf.command("autopwn")
class HFMFAutopwn(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "MIFARE Classic auto recovery (PM3-style): detect PRNG, check known "
            "keys, then escalate darkside -> nested -> hardnested -> staticnested, "
            "propagating each recovered key. Flags follow Proxmark3: -f is the key "
            "dictionary, -o is the output suffix (hf-mf-<uid>-dump[-suffix].json). "
            "-s/--slot additionally loads the card into an emulation slot."
        )
        parser.add_argument(
            "-k",
            "--key",
            type=str,
            required=False,
            metavar="<hex>",
            help="Known key (12 hex)",
        )
        # Proxmark3-compatible: -f is the DICTIONARY (was output before; matches
        # `hf mf autopwn -f <dict>` muscle memory). --dict/--dic are aliases.
        parser.add_argument(
            "-f",
            "--file",
            "--dict",
            "--dic",
            dest="dict",
            type=str,
            default=None,
            metavar="<fn>",
            help="Filename of key dictionary to try first (PM3 -f).",
        )
        # Proxmark3-compatible: -o is a SUFFIX; outputs auto-name as
        # hf-mf-<uid>-dump[-suffix].json and hf-mf-<uid>-key[-suffix].(dic|bin).
        parser.add_argument(
            "-o",
            "--output",
            dest="output",
            type=str,
            nargs="?",
            const="",
            default=None,
            metavar="<suffix>",
            help="Dump the card + keys to hf-mf-<uid>-dump[-<suffix>].json and "
            "hf-mf-<uid>-key[-<suffix>].(dic|bin). Bare -o uses no suffix.",
        )
        parser.add_argument(
            "--bin",
            action="store_true",
            help="With -o, also write the raw .bin dump next to the JSON.",
        )
        parser.add_argument(
            "-s",
            "--slot",
            type=int,
            choices=range(1, 9),
            default=None,
            help="Also load the recovered card into this emulation slot (1-8).",
        )
        parser.add_argument(
            "--slow",
            action="store_true",
            help="Slower acquisition for non-standard cards (PM3 -s/--slow).",
        )
        parser.add_argument(
            "--keyfile",
            type=str,
            default=None,
            help="Resume: seed known keys from a Proxmark3 .key (A||B per sector) or "
            ".dic file, so already-recovered sectors are skipped.",
        )
        parser.add_argument(
            "--no-dump",
            action="store_true",
            help="Recover keys only; skip the card dump.",
        )
        return parser

    def get_mf_size(self, sak):
        sizes = {
            b"\x18": ("4k", 40),
            b"\x08": ("1k", 16),
            b"\x09": ("mini", 5),
            b"\x10": ("2k", 32),
            b"\x01": ("1k", 16),
        }
        if sak not in sizes:
            print("Unknown SAK, defaulting to 16 sectors")
        return sizes.get(sak, ("1k", 16))

    def getsak(self, deep=False):
        return self.scan(deep, "sak")

    def getuid(self, deep=False):
        return self.scan(deep, "uid")

    def from_nt_level_code_to_str(self, nt_level):
        return {0: "StaticNested", 1: "Nested", 2: "HardNested"}.get(
            nt_level, "Unknown"
        )

    def scan(self, deep=False, scanitem="uid"):
        resp = self.cmd.hf14a_scan()
        if resp is None:
            print("ISO14443-A tag not found")
            return None
        for data_tag in resp:
            if deep:
                self.sak_info(data_tag)
                if len(resp) == 1:
                    self.check_mf1_nt()
                else:
                    print("Multiple tags detected, skipping deep tests...")
            return data_tag[scanitem].hex().upper()

    def bits_to_10byte_mask(self, bits=0):
        return bytes.fromhex(f"{(1 << (80 - bits)) - 1:020X}")

    def try_key(self, key: bytes, mask: bytes):
        return self.cmd.mf1_check_keys_of_sectors(mask, [key])

    def neg_bytes(self, data: bytes) -> bytes:
        return (~int.from_bytes(data, "big") & ((1 << (len(data) * 8)) - 1)).to_bytes(
            len(data), "big"
        )

    def merge_found_sector_keys(self, existing, response, overwrite=False):
        for idx, key in response.get("sectorKeys", {}).items():
            if overwrite or idx not in existing:
                existing[idx] = key
        return existing

    def print_key_table(self, keymap, max_sectors):
        def fmt(k):
            text = (
                k.hex().upper().ljust(12)
                if isinstance(k, (bytes, bytearray))
                else "------------"
            )
            color = CG if isinstance(k, (bytes, bytearray)) else CR
            return f"{color}{text}{C0}"

        sep = "╠══════╬══════════════╬══════════════╣"
        print("╔══════╦══════════════╦══════════════╗")
        print("║ Sec  ║ key A        ║ key B        ║")
        for sector in range(max_sectors):
            print(sep)
            print(
                f"║ {sector:03d}  ║ {fmt(keymap.get(sector * 2))} ║ {fmt(keymap.get(sector * 2 + 1))} ║"
            )
        print("╚══════╩══════════════╩══════════════╝")

    def find_missing_keys(self, existing_keys: dict, max_num: int):
        return {
            i: (MfcKeyType.A if i % 2 == 0 else MfcKeyType.B)
            for i in range(max_num)
            if i not in existing_keys
        }

    def choose_random_known_key(self, keys_dict):
        index = random.choice(list(keys_dict.keys()))
        return (
            (index // 2) * 4,
            keys_dict[index],
            MfcKeyType.B if index % 2 else MfcKeyType.A,
        )

    def mask_from_keys(
        self, pos_container, total_bits=80, one_indexed=False, msb_left=True
    ):
        positions = (
            pos_container.keys() if isinstance(pos_container, dict) else pos_container
        )
        field = ["0"] * total_bits
        for p in positions:
            try:
                p = int(p)
            except Exception:
                continue
            idx = p - 1 if one_indexed else p
            if 0 <= idx < total_bits:
                field[idx if msb_left else total_bits - 1 - idx] = "1"
        bstr = "".join(field)
        return bstr, bytes(int(bstr[i : i + 8], 2) for i in range(0, total_bits, 8))

    def run_senested(self, current_keys_found, max_sectors_num):
        print(
            f" {CY}[+]{C0}  This card could be cracked using static nested attack (May take a few minutes)"
        )
        if input(f" {C0}[+]{C0}  Would you like to proceed? [y/n]: ").lower() != "y":
            return current_keys_found
        backdoor_key = "A396EFA4E24F"
        if (
            input(
                f" {C0}[+]{C0}  Would you like to use default backdoor key? [y/n]: "
            ).lower()
            == "n"
        ):
            while True:
                backdoor_key = input(
                    f" {C0}[+]{C0}  Backdoor key (known: A396EFA4E24F, A31667A8CEC1, 518B3354E760): "
                ).upper()
                if re.fullmatch(r"[A-F0-9]{12}", backdoor_key):
                    print(f" {CG}[+]{C0}  Valid key")
                    break
                print(f" {CR}[!]{C0}  Invalid format for key")
        else:
            print(f" {CY}[+]{C0}  Using default key A396EFA4E24F")
        print(f" {CG}[+]{C0}  Running static nested..")
        snested = HFMFStaticEncryptedNested.__new__(HFMFStaticEncryptedNested)
        snested._device_cmd = self.cmd
        missing_keys = self.find_missing_keys(current_keys_found, max_sectors_num * 2)
        keys = list(missing_keys.items())
        for i, (key_num, key_type) in enumerate(keys):
            if current_keys_found.get(key_num) is not None:
                print(f" {CG}[+]{C0}  Key {key_num} found by reuse")
                continue
            sector_num = key_num // 2
            found_keymap = snested.senested(
                backdoor_key, sector_num, sector_num + 1, max_sectors_num
            )
            next_key_num = keys[i + 1][0] if i + 1 < len(keys) else -1
            if next_key_num == key_num + 1 and key_type == MfcKeyType.A:
                current_keys_found[key_num] = bytes.fromhex(
                    found_keymap["A"][sector_num]
                )
                current_keys_found[key_num + 1] = bytes.fromhex(
                    found_keymap["B"][sector_num]
                )
            elif key_type == MfcKeyType.A:
                current_keys_found[key_num] = bytes.fromhex(
                    found_keymap["A"][sector_num]
                )
            else:
                current_keys_found[key_num] = bytes.fromhex(
                    found_keymap["B"][sector_num]
                )
            current_keys_found = dict(sorted(current_keys_found.items()))
            _, mask_bytes = self.mask_from_keys(missing_keys)
            neg = self.neg_bytes(mask_bytes)
            current_keys_found = self.merge_found_sector_keys(
                current_keys_found,
                self.try_key(bytes.fromhex(found_keymap["A"][sector_num]), neg),
            )
            current_keys_found = self.merge_found_sector_keys(
                current_keys_found,
                self.try_key(bytes.fromhex(found_keymap["B"][sector_num]), neg),
            )
        return current_keys_found

    def _load_keyfile(self, path, max_sectors_num):
        """Seed keys from a PM3 .key (positional A||B per sector) or .dic (list)."""
        seeded = {}
        try:
            data = open(path, "rb").read()
        except Exception as e:
            print(f" {CR}[!]{C0}  Could not read keyfile {path}: {e}")
            return seeded
        text = data.decode("utf-8", "ignore")
        hexlines = [
            l.strip()
            for l in text.splitlines()
            if re.fullmatch(r"[A-Fa-f0-9]{12}", l.strip())
        ]
        if path.lower().endswith(".dic") or (
            hexlines and len(hexlines) != max_sectors_num * 2 and b"\n" in data
        ):
            # dictionary: caller will try these across sectors
            self._extra_dict = (getattr(self, "_extra_dict", None) or []) + hexlines
            print(f" {CG}[+]{C0}  Seeded {len(hexlines)} dictionary keys from {path}")
            return seeded
        # positional .key: 6 bytes A + 6 bytes B per sector, sectors in order
        if len(data) == max_sectors_num * 12:
            blank = bytes(6)
            for sec in range(max_sectors_num):
                a = data[sec * 12 : sec * 12 + 6]
                b = data[sec * 12 + 6 : sec * 12 + 12]
                if a != blank:
                    seeded[sec * 2] = a
                if b != blank:
                    seeded[sec * 2 + 1] = b
            print(f" {CG}[+]{C0}  Seeded {len(seeded)} keys from {path} (resume)")
        elif hexlines:
            self._extra_dict = (getattr(self, "_extra_dict", None) or []) + hexlines
            print(f" {CG}[+]{C0}  Seeded {len(hexlines)} dictionary keys from {path}")
        else:
            print(f" {CR}[!]{C0}  Keyfile {path}: unrecognized size/format, ignored")
        return seeded

    def autopwn(self, key_known):
        uid = self.getuid()
        sak = self.getsak()
        mf_size, max_sectors_num = self.get_mf_size(bytes.fromhex(sak))
        print(f" {CG}[+]{C0}  Type: MIFARE Classic {CY}{mf_size}{C0}")
        print(f" {CG}[+]{C0}  UID: {uid}")
        print(f" {CG}[+]{C0}  SAK: {sak}")
        nt_level = self.cmd.mf1_detect_prng()
        print(
            f" {CG}[+]{C0}  NT vulnerable: {CY}{self.from_nt_level_code_to_str(nt_level)}{C0}"
        )

        current_keys_found = {}
        full_mask = self.bits_to_10byte_mask(max_sectors_num * 2)

        keyfile = getattr(self, "_keyfile_path", None)
        if keyfile:
            for idx, k in self._load_keyfile(keyfile, max_sectors_num).items():
                current_keys_found[idx] = k
            # verify/extend seeded keys by reuse across sectors
            for k in list(dict.fromkeys(current_keys_found.values())):
                current_keys_found = self.merge_found_sector_keys(
                    current_keys_found, self.try_key(k, full_mask)
                )

        if key_known is not None:
            current_keys_found = self.merge_found_sector_keys(
                current_keys_found, self.try_key(bytes.fromhex(key_known), full_mask)
            )
        current_keys_found = self.merge_found_sector_keys(
            current_keys_found, self.try_key(bytes.fromhex("FFFFFFFFFFFF"), bytes(10))
        )
        # user-supplied dictionary (--dict): try each key across all still-unknown sectors
        for dk in getattr(self, "_extra_dict", None) or []:
            if len(current_keys_found) >= max_sectors_num * 2:
                break
            current_keys_found = self.merge_found_sector_keys(
                current_keys_found, self.try_key(bytes.fromhex(dk), full_mask)
            )

        if not current_keys_found:
            print(f" {CR}[!]{C0}  No keys found yet, trying darkside..")
            darkside = HFMFDarkside.__new__(HFMFDarkside)
            HFMFDarkside.__init__(darkside)
            darkside._device_cmd = self.cmd
            darkside_key = darkside.recover_key(0x03, MfcKeyType.A)
            if darkside_key is not None:
                print(f" {CG}[+]{C0}  Darkside key found: {darkside_key}")
                current_keys_found[0] = bytes.fromhex(darkside_key)
                current_keys_found = dict(sorted(current_keys_found.items()))
                print(f" {CG}[+]{C0}  Reuse key check..")
                current_keys_found = self.merge_found_sector_keys(
                    current_keys_found,
                    self.try_key(bytes.fromhex(darkside_key), full_mask),
                )
            else:
                print(f" {CR}[!]{C0}  Darkside failed!")

        total = max_sectors_num * 2
        if len(current_keys_found) == total:
            print(f" {CG}[+]{C0}  All keys found")
            return current_keys_found, max_sectors_num

        if not current_keys_found:
            return (
                self.run_senested(current_keys_found, max_sectors_num),
                max_sectors_num,
            )

        print(f" {CG}[+]{C0}  Some keys found, recovering remaining..")
        if nt_level == 2:
            missing_keys = self.find_missing_keys(current_keys_found, total)
            hardnested = HFMFHardNested.__new__(HFMFHardNested)
            BaseCLIUnit.__init__(hardnested)
            hardnested._device_cmd = self.cmd
            for missing_key_num, key_type_target in missing_keys.items():
                if current_keys_found.get(missing_key_num) is not None:
                    print(f" {CG}[+]{C0}  Key {missing_key_num} found by reuse")
                    continue
                block_known, key_known_bytes, type_known = self.choose_random_known_key(
                    current_keys_found
                )
                block_target = (missing_key_num // 2) * 4
                hn_key = hardnested.recover_key(
                    False,
                    block_known,
                    type_known,
                    key_known_bytes,
                    block_target,
                    key_type_target,
                    False,
                    200,
                    3,
                )
                if hn_key is None:
                    continue
                print(f" {CG}[+]{C0}  Found key {missing_key_num}: {hn_key.upper()}")
                current_keys_found[missing_key_num] = bytes.fromhex(hn_key)
                current_keys_found = dict(sorted(current_keys_found.items()))
                _, mask_bytes = self.mask_from_keys(missing_keys)
                current_keys_found = self.merge_found_sector_keys(
                    current_keys_found,
                    self.try_key(bytes.fromhex(hn_key), self.neg_bytes(mask_bytes)),
                )
            if len(current_keys_found) < total:
                current_keys_found = self.run_senested(
                    current_keys_found, max_sectors_num
                )
        elif nt_level == 0:
            current_keys_found = self.run_senested(current_keys_found, max_sectors_num)
        else:
            block_known, key_known_bytes, type_known = self.choose_random_known_key(
                current_keys_found
            )
            missing_keys = self.find_missing_keys(current_keys_found, total)
            nested = HFMFNested.__new__(HFMFNested)
            BaseCLIUnit.__init__(nested)
            nested._device_cmd = self.cmd
            hardnested = None
            for missing_key_num, key_type_target in missing_keys.items():
                if current_keys_found.get(missing_key_num) is not None:
                    print(f" {CG}[+]{C0}  Key {missing_key_num} found by reuse")
                    continue
                nested_key = nested.recover_a_key(
                    block_known,
                    type_known,
                    key_known_bytes,
                    (missing_key_num // 2) * 4,
                    key_type_target,
                )
                if nested_key is None:
                    if hardnested is None:
                        hardnested = HFMFHardNested.__new__(HFMFHardNested)
                        BaseCLIUnit.__init__(hardnested)
                        hardnested._device_cmd = self.cmd
                    hn_key = hardnested.recover_key(
                        False,
                        block_known,
                        type_known,
                        key_known_bytes,
                        (missing_key_num // 2) * 4,
                        key_type_target,
                        False,
                        200,
                        3,
                    )
                    if hn_key is None:
                        continue
                    current_keys_found[missing_key_num] = bytes.fromhex(hn_key)
                    print(
                        f" {CG}[+]{C0}  Found key {missing_key_num}: {hn_key.upper()}"
                    )
                else:
                    print(
                        f" {CG}[+]{C0}  Found key {missing_key_num}: {nested_key.upper()}"
                    )
                    current_keys_found[missing_key_num] = bytes.fromhex(nested_key)
                current_keys_found = dict(sorted(current_keys_found.items()))
                _, mask_bytes = self.mask_from_keys(missing_keys)
                new_key = current_keys_found[missing_key_num]
                current_keys_found = self.merge_found_sector_keys(
                    current_keys_found,
                    self.try_key(new_key, self.neg_bytes(mask_bytes)),
                )
            if len(current_keys_found) < total:
                current_keys_found = self.run_senested(
                    current_keys_found, max_sectors_num
                )

        if len(current_keys_found) == total:
            print(f" {CG}[+]{C0}  All keys found")
        return current_keys_found, max_sectors_num

    def save_keys_to_file(self, extracted_keys, max_sectors_num):
        if input(f" {CY}[?]{C0}  Save keys to file? [y/n]: ").lower() != "y":
            return
        filename = input(
            f" {C0}[+]{C0}  Enter base filename (without extension): "
        ).strip()
        if not filename:
            print(f" {CR}[!]{C0}  No filename provided, skipping.")
            return
        dic_path = filename + ".dic"
        uniq_keys = set(
            v for v in extracted_keys.values() if isinstance(v, (bytes, bytearray))
        )
        with open(dic_path, "w") as f:
            for key in uniq_keys:
                f.write(key.hex().upper() + "\n")
        print(f" {CG}[+]{C0}  Keys saved to {dic_path} (as .dic format)")
        key_path = filename + ".key"
        unknownkey = bytes(6)
        with open(key_path, "wb") as f:
            for sector_no in range(max_sectors_num):
                f.write(extracted_keys.get(sector_no * 2, unknownkey))
                f.write(extracted_keys.get(sector_no * 2 + 1, unknownkey))
        print(f" {CG}[+]{C0}  Keys saved to {key_path} (as .key format)")

    def read_all_blocks(self, extracted_keys, max_sectors_num):
        """Read every block with the recovered keys -> {block_num: 16 bytes}."""
        blocks = {}
        buffer = bytearray()
        for s in range(max_sectors_num):
            key_a = extracted_keys.get(s * 2)
            key_b = extracted_keys.get(s * 2 + 1)
            num_blocks, first_block = (
                (4, s * 4) if s < 32 else (16, 128 + (s - 32) * 16)
            )
            for b in range(num_blocks):
                block_num = first_block + b
                block_data = None
                if key_b is not None:
                    try:
                        block_data = self.cmd.mf1_read_one_block(
                            block_num, MfcKeyType.B, key_b
                        )
                    except Exception:
                        pass
                if block_data is None and key_a is not None:
                    try:
                        block_data = self.cmd.mf1_read_one_block(
                            block_num, MfcKeyType.A, key_a
                        )
                    except Exception:
                        pass
                if block_data is None:
                    print(
                        f" {CR}[!]{C0}  Block {block_num} unreadable, filling with zeros"
                    )
                    block_data = bytes(16)
                blocks[block_num] = bytes(block_data)
                buffer.extend(block_data)
        return blocks, bytes(buffer)

    def _card_meta(self):
        """UID / ATQA / SAK from a fresh scan, for the mfc v2 Card block."""
        resp = self.cmd.hf14a_scan()
        if resp:
            t = resp[0]
            return t["uid"], t["atqa"], t["sak"][0]
        return b"", b"", 0

    def write_dump(self, blocks, raw, path):
        if path.lower().endswith(".json"):
            import json

            uid, atqa, sak = self._card_meta()
            obj = chameleon_pm3.mfc_blocks_to_json(uid, atqa, sak, blocks)
            with open(path, "w") as fh:
                fh.write(json.dumps(obj, indent=4))
            print(f" {CG}[+]{C0}  Card dumped to {path} (Proxmark3 'mfc v2')")
        else:
            with open(path, "wb") as fh:
                fh.write(raw)
            print(f" {CG}[+]{C0}  Card dumped to {path} (raw .bin)")

    def load_into_slot(self, raw, slot):
        """Push the recovered dump straight into an MF1 emulation slot (like eload)."""
        try:
            fwslot = SlotNumber(slot)
            block_count = len(raw) // 16
            tag = (
                TagSpecificType.MIFARE_4096
                if block_count > 64
                else TagSpecificType.MIFARE_1024
            )
            self.cmd.set_slot_tag_type(fwslot, tag)
            self.cmd.set_slot_enable(fwslot, TagSenseType.HF, True)
            self.cmd.set_active_slot(fwslot)
            # chunked write, same as hf mf eload
            max_blocks = (self.device_com.data_max_length - 1) // 16
            index = block = 0
            while index < len(raw):
                chunk = raw[index : index + 16 * max_blocks]
                self.cmd.mf1_write_emu_block_data(block, chunk)
                n = len(chunk) // 16
                index += 16 * n
                block += n
            self.cmd.slot_data_config_save()
            print(
                f" {CG}[+]{C0}  Loaded recovered card into slot {slot} "
                f"({block_count} blocks) — ready to emulate"
            )
        except Exception as e:
            print(f" {CR}[!]{C0}  Slot load failed: {e}")

    def _save_keys(self, extracted_keys, max_sectors_num, base):
        uniq = set(
            v for v in extracted_keys.values() if isinstance(v, (bytes, bytearray))
        )
        with open(base + ".dic", "w") as fh:
            for k in sorted(uniq):
                fh.write(k.hex().upper() + "\n")
        with open(base + ".key", "wb") as fh:
            for s in range(max_sectors_num):
                fh.write(extracted_keys.get(s * 2, bytes(6)))
                fh.write(extracted_keys.get(s * 2 + 1, bytes(6)))
        print(f" {CG}[+]{C0}  Keys saved to {base}.dic and {base}.key")

    def dump_card_to_file(self, extracted_keys, max_sectors_num):
        # interactive path (bare `autopwn`, no -f/-s)
        if input(f" {CY}[?]{C0}  Dump card to file? [y/n]: ").lower() != "y":
            return
        filename = input(
            f" {C0}[+]{C0}  Enter dump filename (base, or name.json / name.bin): "
        ).strip()
        if not filename:
            print(f" {CR}[!]{C0}  No filename provided, skipping.")
            return
        path = (
            filename
            if filename.lower().endswith((".json", ".bin"))
            else filename + ".bin"
        )
        blocks, raw = self.read_all_blocks(extracted_keys, max_sectors_num)
        self.write_dump(blocks, raw, path)

    def on_exec(self, args: argparse.Namespace):
        key_known: str = args.key
        if key_known is not None and not re.match(r"^[a-fA-F0-9]{12}$", key_known):
            print("key must include 12 HEX symbols")
            return
        self._extra_dict = None
        self._keyfile_path = getattr(args, "keyfile", None)
        self._slow = bool(getattr(args, "slow", False))
        if args.dict:
            try:
                with open(args.dict) as fh:
                    self._extra_dict = [
                        k.strip()
                        for k in fh
                        if re.fullmatch(r"[A-Fa-f0-9]{12}", k.strip())
                    ]
                print(
                    f" {CG}[+]{C0}  Loaded {len(self._extra_dict)} keys from {args.dict}"
                )
            except Exception as e:
                print(f" {CR}[!]{C0}  Could not read dict {args.dict}: {e}")

        extracted_keys, max_sectors_num = self.autopwn(key_known)
        self.print_key_table(extracted_keys, max_sectors_num)

        non_interactive = args.output is not None or args.slot
        if non_interactive:
            if args.output is not None:
                # PM3-style auto-naming: hf-mf-<uid>-{dump,key}[-suffix].*
                uid = self.getuid()
                uid_hex = (
                    uid.hex().upper()
                    if isinstance(uid, (bytes, bytearray))
                    else "UNKNOWN"
                )
                suffix = f"-{args.output}" if args.output else ""
                key_base = f"hf-mf-{uid_hex}-key{suffix}"
                dump_json = f"hf-mf-{uid_hex}-dump{suffix}.json"
                dump_bin = f"hf-mf-{uid_hex}-dump{suffix}.bin"
                self._save_keys(extracted_keys, max_sectors_num, key_base)
                if not args.no_dump:
                    blocks, raw = self.read_all_blocks(extracted_keys, max_sectors_num)
                    self.write_dump(blocks, raw, dump_json)
                    if args.bin:
                        self.write_dump(blocks, raw, dump_bin)
                    if args.slot:
                        self.load_into_slot(raw, args.slot)
            elif args.slot:
                if not args.no_dump:
                    blocks, raw = self.read_all_blocks(extracted_keys, max_sectors_num)
                    self.load_into_slot(raw, args.slot)
        else:
            self.save_keys_to_file(extracted_keys, max_sectors_num)
            if not args.no_dump:
                self.dump_card_to_file(extracted_keys, max_sectors_num)


@hf_mf.command("sim")
class HFMFSim(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Emulate a MIFARE Classic dump: load a Proxmark3 'mfc v2' .json, raw "
            ".bin, or .eml into a slot and leave that slot active. One-shot "
            "crack-file -> live tag."
        )
        parser.add_argument(
            "-f",
            "--file",
            type=str,
            required=True,
            help="Dump file: .json (PM3 mfc v2), .bin, or .eml",
        )
        parser.add_argument(
            "-s",
            "--slot",
            type=int,
            choices=range(1, 9),
            default=None,
            help="Target slot 1-8 (default: active slot)",
        )
        parser.add_argument(
            "-t",
            "--type",
            choices=["bin", "hex"],
            default=None,
            help="Force content type for non-.json files",
        )
        return parser

    def _read_dump(self, path, forced):
        with open(path, "rb") as fh:
            raw = fh.read()
        low = path.lower()
        if low.endswith(".json") or (forced is None and raw[:1] == b"{"):
            import json

            _card, blocks = chameleon_pm3.mfc_json_to_blocks(json.loads(raw.decode()))
            buf = bytearray()
            for n in range((max(blocks) + 1) if blocks else 0):
                buf.extend(blocks.get(n, bytes(16)))
            return bytes(buf)
        if low.endswith(".eml") or forced == "hex":
            return bytes.fromhex("".join(raw.decode().split()))  # eml: hex per line
        if low.endswith(".bin") or forced == "bin":
            return raw
        raise Exception("Unknown dump format; pass -t bin|hex")

    def on_exec(self, args: argparse.Namespace):
        raw = self._read_dump(args.file, args.type)
        if len(raw) % 16 != 0:
            raise Exception("Dump not a multiple of 16 bytes")
        slot = (
            SlotNumber(args.slot)
            if args.slot
            else SlotNumber.from_fw(self.cmd.get_active_slot())
        )
        block_count = len(raw) // 16
        tag = (
            TagSpecificType.MIFARE_4096
            if block_count > 64
            else TagSpecificType.MIFARE_1024
        )
        self.cmd.set_slot_tag_type(slot, tag)
        self.cmd.set_slot_enable(slot, TagSenseType.HF, True)
        self.cmd.set_active_slot(slot)
        max_blocks = (self.device_com.data_max_length - 1) // 16
        index = block = 0
        while index < len(raw):
            chunk = raw[index : index + 16 * max_blocks]
            self.cmd.mf1_write_emu_block_data(block, chunk)
            n = len(chunk) // 16
            index += 16 * n
            block += n
        self.cmd.slot_data_config_save()
        print(
            f" {CG}[+]{C0}  Emulating {block_count}-block MIFARE Classic in slot "
            f"{int(slot)} — leave CU on the reader"
        )


@hf_mf.command("fchk")
class HFMFFCHK(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Mifare Classic fast key check on sectors"

        mifare_type_group = parser.add_mutually_exclusive_group()
        mifare_type_group.add_argument(
            "--mini",
            help="MIFARE Classic Mini / S20",
            action="store_const",
            dest="maxSectors",
            const=5,
        )
        mifare_type_group.add_argument(
            "--1k",
            help="MIFARE Classic 1k / S50 (default)",
            action="store_const",
            dest="maxSectors",
            const=16,
        )
        mifare_type_group.add_argument(
            "--2k",
            help="MIFARE Classic/Plus 2k",
            action="store_const",
            dest="maxSectors",
            const=32,
        )
        mifare_type_group.add_argument(
            "--4k",
            help="MIFARE Classic 4k / S70",
            action="store_const",
            dest="maxSectors",
            const=40,
        )

        parser.add_argument(
            dest="keys",
            help="Key (as hex[12] format)",
            metavar="<hex>",
            type=str,
            nargs="*",
        )
        parser.add_argument(
            "--key",
            dest="import_key",
            type=argparse.FileType("rb"),
            help="Read keys from .key format file",
        )
        parser.add_argument(
            "--dic",
            dest="import_dic",
            type=argparse.FileType("r", encoding="utf8"),
            help="Read keys from .dic format file",
        )

        parser.add_argument(
            "--export-key",
            type=argparse.FileType("wb"),
            help=f'Export result as .key format, file will be {color_string((CR, "OVERWRITTEN"))} if exists',
        )
        parser.add_argument(
            "--export-dic",
            type=argparse.FileType("w", encoding="utf8"),
            help=f'Export result as .dic format, file will be {color_string((CR, "OVERWRITTEN"))} if exists',
        )

        parser.add_argument(
            "-m",
            "--mask",
            help="Which sectorKey to be skip, 1 bit per sectorKey. `0b1` represent to skip to check. (in hex[20] format)",
            type=str,
            default="00000000000000000000",
            metavar="<hex>",
        )

        parser.set_defaults(maxSectors=16)
        return parser

    def check_keys(self, mask: bytearray, keys: list[bytes], chunkSize=20):
        sectorKeys = dict()

        for i in range(0, len(keys), chunkSize):
            # print("mask = {}".format(mask.hex(sep=' ', bytes_per_sep=1)))
            chunkKeys = keys[i : i + chunkSize]
            print(
                f' - progress of checking keys... {color_string((CY, i))} / {len(keys)} ({color_string((CY, f"{100 * i / len(keys):.1f}"))} %)'
            )
            resp = self.cmd.mf1_check_keys_of_sectors(mask, chunkKeys)
            # print(resp)

            if resp["status"] != Status.HF_TAG_OK:
                print(
                    f' - check interrupted, reason: {color_string((CR, Status(resp["status"])))}'
                )
                break
            elif "sectorKeys" not in resp:
                print(
                    f' - check interrupted, reason: {color_string((CG, "All sectorKey is found or masked"))}'
                )
                break

            for j in range(10):
                mask[j] |= resp["found"][j]
            sectorKeys.update(resp["sectorKeys"])

        return sectorKeys

    def on_exec(self, args: argparse.Namespace):
        # print(args)

        keys = set()

        # keys from args
        for key in args.keys:
            if not re.match(r"^[a-fA-F0-9]{12}$", key):
                print(
                    f' - {color_string((CR, "Key should in hex[12] format, invalid key is ignored"))}, key = "{key}"'
                )
                continue
            keys.add(bytes.fromhex(key))

        # read keys from key format file
        if args.import_key is not None:
            if not load_key_file(args.import_key, keys):
                return

        if args.import_dic is not None:
            if not load_dic_file(args.import_dic, keys):
                return

        if len(keys) == 0:
            print(f' - {color_string((CR, "No keys"))}')
            return

        print(f" - loaded {color_string((CG, len(keys)))} keys")

        # mask
        if not re.match(r"^[a-fA-F0-9]{1,20}$", args.mask):
            print(
                f' - {color_string((CR, "mask should in hex[20] format"))}, mask = "{args.mask}"'
            )
            return
        mask = bytearray.fromhex(f"{args.mask:0<20}")
        for i in range(args.maxSectors, 40):
            mask[i // 4] |= 3 << (6 - i % 4 * 2)

        # check keys
        startedAt = datetime.now()
        sectorKeys = self.check_keys(mask, list(keys))
        endedAt = datetime.now()
        duration = endedAt - startedAt
        print(
            f" - elapsed time: {color_string((CY, f'{duration.total_seconds():.3f}s'))}"
        )

        if args.export_key is not None:
            unknownkey = bytes(6)
            for sectorNo in range(args.maxSectors):
                args.export_key.write(sectorKeys.get(2 * sectorNo, unknownkey))
                args.export_key.write(sectorKeys.get(2 * sectorNo + 1, unknownkey))
            print(
                f" - result exported to: {color_string((CG, args.export_key.name))} (as .key format)"
            )

        if args.export_dic is not None:
            uniq_result = set(sectorKeys.values())
            for key in uniq_result:
                args.export_dic.write(key.hex().upper() + "\n")
            print(
                f" - result exported to: {color_string((CG, args.export_dic.name))} (as .dic format)"
            )

        # print sectorKeys
        print(f"\n - {color_string((CG, 'result of key checking:'))}\n")
        print("-----+-----+--------------+---+--------------+----")
        print(" Sec | Blk | key A        |res| key B        |res ")
        print("-----+-----+--------------+---+--------------+----")
        for sectorNo in range(args.maxSectors):
            blk = (sectorNo * 4 + 3) if sectorNo < 32 else (sectorNo * 16 - 369)
            keyA = sectorKeys.get(2 * sectorNo, None)
            if keyA:
                keyA = f"{color_string((CG, keyA.hex().upper()))} | {color_string((CG, '1'))}"
            else:
                keyA = (
                    f"{color_string((CR, '------------'))} | {color_string((CR, '0'))}"
                )
            keyB = sectorKeys.get(2 * sectorNo + 1, None)
            if keyB:
                keyB = f"{color_string((CG, keyB.hex().upper()))} | {color_string((CG, '1'))}"
            else:
                keyB = (
                    f"{color_string((CR, '------------'))} | {color_string((CR, '0'))}"
                )
            print(
                f" {color_string((CY, f'{sectorNo:03d}'))} | {blk:03d} | {keyA} | {keyB} "
            )
        print("-----+-----+--------------+---+--------------+----")
        print(
            f"( {color_string((CR, '0'))}: Failed, {color_string((CG, '1'))}: Success )\n\n"
        )


@hf_mf.command("rdbl")
class HFMFRDBL(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = "Mifare Classic read one block"
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)
        resp = self.cmd.mf1_read_one_block(param.block, param.type, param.key)
        print(f" - Data: {resp.hex()}")


@hf_mf.command("wrbl")
class HFMFWRBL(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = "Mifare Classic write one block"
        parser.add_argument(
            "-d",
            "--data",
            type=str,
            required=True,
            metavar="<hex>",
            help="Your block data, as hex string.",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)
        if not re.match(r"^[a-fA-F0-9]{32}$", args.data):
            raise ArgsParserError("Data must include 32 HEX symbols")
        data = bytearray.fromhex(args.data)
        resp = self.cmd.mf1_write_one_block(param.block, param.type, param.key, data)
        if resp:
            print(f" - {color_string((CG, 'Write done.'))}")
        else:
            print(f" - {color_string((CR, 'Write fail.'))}")


@hf_mf.command("view")
class HFMFView(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Display content from tag memory or dump file"
        mifare_type_group = parser.add_mutually_exclusive_group()
        mifare_type_group.add_argument(
            "--mini",
            help="MIFARE Classic Mini / S20",
            action="store_const",
            dest="maxSectors",
            const=5,
        )
        mifare_type_group.add_argument(
            "--1k",
            help="MIFARE Classic 1k / S50 (default)",
            action="store_const",
            dest="maxSectors",
            const=16,
        )
        mifare_type_group.add_argument(
            "--2k",
            help="MIFARE Classic/Plus 2k",
            action="store_const",
            dest="maxSectors",
            const=32,
        )
        mifare_type_group.add_argument(
            "--4k",
            help="MIFARE Classic 4k / S70",
            action="store_const",
            dest="maxSectors",
            const=40,
        )
        parser.add_argument(
            "-d",
            "--dump-file",
            required=False,
            type=argparse.FileType("rb"),
            help="Dump file to read",
        )
        parser.add_argument(
            "-k",
            "--key-file",
            required=False,
            type=argparse.FileType("r"),
            help="File containing keys of tag to write (exported with fchk --export)",
        )
        parser.set_defaults(maxSectors=16)
        return parser

    def on_exec(self, args: argparse.Namespace):
        data = bytearray(0)
        if args.dump_file is not None:
            print("Reading dump file")
            data = args.dump_file.read()
        elif args.key_file is not None:
            print("Reading tag memory")
            # read keys from file
            keys = list()
            for line in args.key_file.readlines():
                a, b = [bytes.fromhex(h) for h in line[:-1].split(":")]
                keys.append((a, b))
            if len(keys) != args.maxSectors:
                raise ArgsParserError(
                    f"Invalid key file. Found {len(keys)}, expected {args.maxSectors}"
                )
            # iterate over blocks
            for blk in range(0, args.maxSectors * 4):
                resp = None
                try:
                    # first try with key B
                    resp = self.cmd.mf1_read_one_block(
                        blk, MfcKeyType.B, keys[blk // 4][1]
                    )
                except UnexpectedResponseError:
                    # ignore read errors at this stage as we want to try key A
                    pass
                if not resp:
                    # try with key A if B was unsuccessful
                    # this will raise an exception if key A fails too
                    resp = self.cmd.mf1_read_one_block(
                        blk, MfcKeyType.A, keys[blk // 4][0]
                    )
                data.extend(resp)
        else:
            raise ArgsParserError(
                "Missing args. Specify --dump-file (-d) or --key-file (-k)"
            )
        print_mem_dump(data, 16)


@hf_mf.command("dump")
class HFMFDump(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Mifare Classic dump tag"
        parser.add_argument(
            "-t",
            "--dump-file-type",
            type=str,
            required=False,
            help="Dump file content type",
            choices=["bin", "hex"],
        )
        parser.add_argument(
            "-f",
            "--dump-file",
            type=argparse.FileType("wb"),
            required=True,
            help="Dump file to write data from tag",
        )
        parser.add_argument(
            "-d",
            "--dic",
            type=argparse.FileType("r"),
            required=True,
            help="Read keys (to communicate with tag to dump) from .dic format file",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        # check dump type
        if args.dump_file_type is None:
            if args.dump_file.name.endswith(".bin"):
                content_type = "bin"
            elif args.dump_file.name.endswith(".eml"):
                content_type = "hex"
            else:
                raise Exception(
                    "Unknown file format, Specify content type with -t option"
                )
        else:
            content_type = args.dump_file_type

        # read keys from file
        keys = [bytes.fromhex(line[:-1]) for line in args.dic.readlines()]

        # data to write from dump file
        buffer = bytearray()

        # iterate over sectors
        for s in range(16):
            # find working keys for this sector (both A and B)
            type_a = type_b = None
            key_a = key_b = None
            for key in keys:
                if type_b is None:
                    try:
                        self.cmd.mf1_read_one_block(4 * s, MfcKeyType.B, key)
                        type_b = MfcKeyType.B
                        key_b = key
                    except UnexpectedResponseError:
                        pass
                if type_a is None:
                    try:
                        self.cmd.mf1_read_one_block(4 * s, MfcKeyType.A, key)
                        type_a = MfcKeyType.A
                        key_a = key
                    except UnexpectedResponseError:
                        pass
                if type_a is not None and type_b is not None:
                    break
            if type_a is None and type_b is None:
                raise Exception(f"No key found for sector {s}")

            typ = type_a if type_a is not None else type_b
            key = key_a if type_a is not None else key_b
            # iterate over blocks
            for b in range(3):
                block_data = self.cmd.mf1_read_one_block(4 * s + b, typ, key)
                if content_type == "bin":
                    buffer.extend(block_data)
                elif content_type == "hex":
                    buffer.extend(block_data.hex().encode("utf-8"))

            # sector trailer: fill key bytes from known keys
            trailer = bytearray(self.cmd.mf1_read_one_block(4 * s + 3, typ, key))
            if key_a is not None:
                trailer[0:6] = key_a
            if key_b is not None:
                trailer[10:16] = key_b
            trailer = bytes(trailer)
            if content_type == "bin":
                buffer.extend(trailer)
            elif content_type == "hex":
                buffer.extend(trailer.hex().encode("utf-8"))
        # write buffer to file
        args.dump_file.write(buffer)


def _gen3_raw(cmd, apdu: bytes):
    """Send a Gen3 magic APDU. Returns (ok, raw_response_bytes).

    hf14a_raw() returns the raw response bytes (not a Response object), so
    success is judged from the card's reply: Gen3 cards answer with SW 90 00.
    """
    opt = {'activate_rf_field': 0, 'wait_response': 1, 'append_crc': 1,
           'auto_select': 1, 'keep_rf_field': 0, 'check_response_crc': 1}
    try:
        resp = cmd.hf14a_raw(options=opt, resp_timeout_ms=1000, data=list(apdu))
    except (UnexpectedResponseError, TimeoutError):
        return False, b""
    resp = bytes(resp)
    return resp[-2:] == b"\x90\x00", resp


# Gen4 "Ultimate Magic" (GTU) prefix command. After select, frames are
# CF <4-byte pwd> <op> [args], CRC appended by the card side like a normal
# 14A frame. Default password is 00000000. Returns (ok, response_bytes).
GEN4_DEFAULT_PWD = bytes.fromhex("00000000")


def _gen4_raw(cmd, pwd: bytes, op: int, args: bytes = b""):
    opt = {'activate_rf_field': 0, 'wait_response': 1, 'append_crc': 1,
           'auto_select': 1, 'keep_rf_field': 0, 'check_response_crc': 1}
    frame = b"\xcf" + pwd + bytes([op]) + args
    try:
        resp = cmd.hf14a_raw(options=opt, resp_timeout_ms=1000, data=list(frame))
    except (UnexpectedResponseError, TimeoutError):
        return False, b""
    resp = bytes(resp)
    # TODO: tighten the write-ack check once the real success byte is confirmed
    # on hardware. GTU clones vary by vendor (commonly 0x00 ack on success);
    # for now any reply is treated as sent.
    return len(resp) > 0, resp


def _gen4_pwd(args):
    return bytes.fromhex(args.pwd) if getattr(args, "pwd", None) else GEN4_DEFAULT_PWD


# Most Gen4/GTU clones ack a successful write with a single 0x00 byte and
# something else on failure - that convention varies by vendor/firmware
# though, so this is the one place to adjust if your card acks differently.
GEN4_ACK_OK = 0x00


def _gen4_write_ok(resp: bytes) -> bool:
    return len(resp) >= 1 and resp[0] == GEN4_ACK_OK


def _gen4_read_blk(cmd, pwd, block):
    ok, resp = _gen4_raw(cmd, pwd, 0xCE, bytes([block]))
    return resp[:16] if ok and len(resp) >= 16 else None


def _gen4_read_config(cmd, pwd):
    ok, resp = _gen4_raw(cmd, pwd, 0xC6)
    return resp if ok and resp else None


def _gen4_verify_write(label, readback, expected):
    # Some Gen4-GTU clones (and GDM-adjacent ones) are known to ack a write
    # as successful without actually applying it - especially on trailer
    # blocks - so this is a cheap read-back sanity check, not just trust
    # in the ack byte. readback=None means the verify read itself failed,
    # which is reported separately from a genuine data mismatch.
    if readback is None:
        print(f"   (could not verify: {label} read-back failed)")
    elif readback != expected:
        print(f"   (!) ack said success but read-back doesn't match - "
              f"{label} may not have actually been written")


def identify_magic_gen(cmd):
    """Best-effort, read-only probe for the common MIFARE Classic magic-card
    backdoors. Call with a card already selectable on the antenna.

    Returns "gen1a", "gen3", "gen4-gtu", "gen4-gdm", or None.

    No gen2/CUID probe: documented gen2 behavior is that it does NOT answer
    unauthenticated commands at all - its only tell is that block 0 accepts
    a normal authenticated write (commonly key A FFFFFFFFFFFF), which isn't
    something a passive identify scan can observe without attempting that
    write. A gen2 card reads as None here and gets picked up by the normal
    autopwn/dump path instead, same as a genuine card.

    GDM ("USCUID") is probed read-only below via its raw-wakeup backdoor
    (0x20(7) "GDM alt" stage 1 only, same non-destructive single-ACK check as
    the gen1a probe). A card that only answers the WUPA-magic-auth flavour
    (no raw-wakeup backdoor enabled) is not caught here and reads as None --
    distinguishing that from a genuine card would mean attempting an auth
    with a guessed key, which this read-only probe deliberately does not do.

    Every probe below only reads, or attempts a single-step wakeup/auth
    handshake; nothing writes a block.
    """
    # Gen1a: the 7-bit 0x40 "unlock stage 1" command. A real card ignores
    # or NAKs it; a gen1a magic card answers with the 4-bit ACK (0x0a).
    # We stop right after this single read of the ACK - never send the
    # stage-2 0x43 or any write, so the card's state isn't changed.
    opt_raw = {"activate_rf_field": 1, "wait_response": 1, "append_crc": 0,
               "auto_select": 0, "keep_rf_field": 1, "check_response_crc": 0}
    try:
        r = cmd.hf14a_raw(options=opt_raw, resp_timeout_ms=500, data=[0x40], bitlen=7)
        if r and bytes(r)[:1] == b"\x0a":
            return "gen1a"
    except (UnexpectedResponseError, TimeoutError):
        pass
    finally:
        try:
            cmd.hf14a_raw(options={**opt_raw, "keep_rf_field": 0, "wait_response": 0},
                          resp_timeout_ms=200, data=[])  # drop the field
        except Exception:
            pass

    # GDM alt: same non-destructive shape as the gen1a probe above, just the
    # 0x20(7) stage-1 byte instead of 0x40 -- stop right after the single ACK
    # read, never send stage-2 0x23 or any write.
    try:
        r = cmd.hf14a_raw(options=opt_raw, resp_timeout_ms=500, data=[0x20], bitlen=7)
        if r and bytes(r)[:1] == b"\x0a":
            return "gen4-gdm"
    except (UnexpectedResponseError, TimeoutError):
        pass
    finally:
        try:
            cmd.hf14a_raw(options={**opt_raw, "keep_rf_field": 0, "wait_response": 0},
                          resp_timeout_ms=200, data=[])  # drop the field
        except Exception:
            pass

    # Gen3: the same APDU family as gen3uid/gen3blk/gen3freeze, but with
    # Lc=0 so there is no UID payload to write - a malformed/empty write
    # is rejected rather than applied. Only a Gen3 card understands this
    # APDU framing at all, so any status-word reply is the tell.
    ok, resp = _gen3_raw(cmd, bytes([0x90, 0xFB, 0xCC, 0xCC, 0x00]))
    if resp:
        return "gen3"

    # Gen4 GTU ("Ultimate Magic"): reading the GTU config block (0xC6) with
    # the default password is read-only and only a Gen4-GTU card understands
    # this CF-prefixed framing at all, so any reply is the tell. A card with
    # a non-default password, or a Gen4-GDM card (different protocol), won't
    # be caught here - see the docstring above.
    ok, resp = _gen4_raw(cmd, GEN4_DEFAULT_PWD, 0xC6)
    if resp:
        return "gen4-gtu"

    return None


def _gen1a_raw(cmd, opt, data, bitlen=None, timeout_ms=200):
    # hf14a_raw, tolerant of NAK/no-response (returns b"")
    try:
        return cmd.hf14a_raw(options=opt, resp_timeout_ms=timeout_ms, data=data, bitlen=bitlen)
    except UnexpectedResponseError:
        return b""


def _gen1a_unlock(cmd, opt):
    """Backdoor stage1 (0x40) + stage2 (0x43) unlock. opt must already have
    activate_rf_field=1, auto_select=0, keep_rf_field=1, append_crc=0 - this
    mutates opt['append_crc']=1 on success, ready for 0x30/0xA0 commands on
    the same (still-open) RF session. Raises on failure."""
    r = _gen1a_raw(cmd, opt, [0x40], bitlen=7, timeout_ms=1000)
    if not r or r[0] != 0x0a:
        raise Exception("gen1a unlock failed (not a gen1a magic card?)")
    r = _gen1a_raw(cmd, opt, [0x43], timeout_ms=1000)
    if not r or r[0] != 0x0a:
        raise Exception("gen1a unlock failed (stage 2)")
    opt["append_crc"] = 1


def _gen1a_drop_field(cmd, opt):
    opt["keep_rf_field"] = 0
    opt["wait_response"] = 0
    try:
        cmd.hf14a_raw(options=opt, resp_timeout_ms=200, data=[])
    except Exception:
        pass


def _gen1a_new_session():
    return {"activate_rf_field": 1, "wait_response": 1, "append_crc": 0,
            "auto_select": 0, "keep_rf_field": 1, "check_response_crc": 0}


def _gen1a_read_blk(cmd, opt, blk):
    r = _gen1a_raw(cmd, opt, [0x30, blk])
    r = bytes(r) if r else b""
    if len(r) < 16:
        raise Exception(f"backdoor read NAK at block {blk}")
    return r[:16]


def _gen1a_write_blk(cmd, opt, blk, data16):
    r = _gen1a_raw(cmd, opt, [0xA0, blk])
    if not r or r[0] != 0x0a:
        raise Exception(f"write command NAK at block {blk}")
    r = _gen1a_raw(cmd, opt, list(data16))
    if not r or r[0] != 0x0a:
        raise Exception(f"write data NAK at block {blk}")


def _gen1a_write_dump(cmd, buffer):
    # Write the dump to a gen1a magic card through the backdoor: unlock, then
    # raw-write (0xA0) every block including block 0. 4-bit ACK is 0x0a.
    nblocks = len(buffer) // 16
    opt = _gen1a_new_session()
    try:
        _gen1a_unlock(cmd, opt)
        for blk in range(nblocks):
            _gen1a_write_blk(cmd, opt, blk, buffer[blk * 16:blk * 16 + 16])
            print(color_string((CG, f"block {blk:2d} written")))
        print(color_string((CG, f"gen1a clone done: {nblocks} blocks")))
    finally:
        _gen1a_drop_field(cmd, opt)


def _gen1a_read_dump(cmd, nblocks):
    # Read every block through the gen1a backdoor; no keys needed/used.
    opt = _gen1a_new_session()
    buf = bytearray()
    try:
        _gen1a_unlock(cmd, opt)
        for blk in range(nblocks):
            buf.extend(_gen1a_read_blk(cmd, opt, blk))
    finally:
        _gen1a_drop_field(cmd, opt)
    return bytes(buf)


# --- Gen4 GDM ("USCUID") magic card backdoor -------------------------------
# v1 scope: config get/set (raw hex only -- see note below) and public block
# get/set, with auto-detecting wakeup across the three known styles. Hidden
# blocks, signature, UID-set, and wipe are deferred: those touch areas where
# even PM3's own current implementation has open, unresolved bugs on some
# card variants, and config field-level semantics (shadow mode, CUID bit,
# etc, as opposed to the wakeup-style byte) vary by vendor batch in ways not
# independently verified here -- see gdmsetcfg's docstring.
#
# Wakeup bytes and opcodes verified against RRG proxmark3 (GPLv3): client-side
# structure from client/src/cmdhfmf.c's gdm_* helpers, wire-level wakeup
# sequences and command framing from armsrc/mifarecmd.c's mifare_wakeup_auth()
# and the gen4gdm* raw-frame examples (whose literal CRC-A bytes independently
# confirm the opcode values 0xE0/0x38/0x80, cross-checked by computing CRC-A
# myself rather than trusting the symbol names alone). GDM-alt's 0x20(7)/0x23
# wakeup bytes come from a debug string literal in that same cmdhfmf.c
# (parse_gdm_cfg's "GDM 20(7)/23" vs "Gen1a 40(7)/43" message).
GDM_WUPC1       = 0x20
GDM_WUPC2       = 0x23
GDM_AUTH_KEY    = 0x80
GDM_READ_CFG    = 0xE0
GDM_WRITE_CFG   = 0xE1
GDM_READBLOCK   = 0x30  # public block: the standard MIFARE read/write opcodes
GDM_WRITEBLOCK  = 0xA0  # work once ANY backdoor wakeup has unlocked the card
GDM_DEFAULT_KEY = bytes(6)  # 00 00 00 00 00 00, PM3's own default magic-auth key


def _gdm_unlock_altwake(cmd, opt):
    """Backdoor stage1 (0x20) + stage2 (0x23): GDM-alt wakeup. Identical framing
    to _gen1a_unlock's 0x40/0x43, different bytes -- same card family of trick,
    different command set."""
    r = _gen1a_raw(cmd, opt, [GDM_WUPC1], bitlen=7, timeout_ms=1000)
    if not r or r[0] != 0x0a:
        raise Exception("gdm-alt unlock failed (not a GDM-alt magic card?)")
    r = _gen1a_raw(cmd, opt, [GDM_WUPC2], timeout_ms=1000)
    if not r or r[0] != 0x0a:
        raise Exception("gdm-alt unlock failed (stage 2)")
    opt["append_crc"] = 1


GDM_WAKEUP_RETRIES = 3
GDM_WAKEUP_RETRY_DELAY_S = 0.06


def _gdm_wakeup_once(cmd, style, key, auth_block):
    if style == 'gen1a':
        opt = _gen1a_new_session()
        _gen1a_unlock(cmd, opt)
        return opt
    if style == 'gdm':
        opt = _gen1a_new_session()
        _gdm_unlock_altwake(cmd, opt)
        return opt
    if style == 'wupa':
        resp = cmd.mf1_magic_auth(GDM_AUTH_KEY, auth_block, key, keep_field=True)
        if not resp.parsed:
            raise Exception("WUPA magic auth failed (wrong key, or not a GDM card)")
        # Field is already on, card already selected+authed by mf1_magic_auth;
        # a follow-up hf14a_raw must not reactivate the field or reselect.
        return {"activate_rf_field": 0, "wait_response": 1, "append_crc": 1,
                "auto_select": 0, "keep_rf_field": 1, "check_response_crc": 0}
    raise ValueError(f"unknown GDM wakeup style {style!r}")


def _gdm_wakeup(cmd, style, key, auth_block=0):
    """Perform one wakeup style; return an hf14a_raw opt dict ready for a
    follow-up raw backdoor command on the SAME RF session (field held open --
    dropping it between wakeup and backdoor command loses the unlock on a
    real card, matching how PM3's own mifare_wakeup_auth() never drops the
    field between the two steps either).
    style: 'gen1a' | 'gdm' | 'wupa'. key only used for 'wupa'.

    Retries GDM_WAKEUP_RETRIES times, each with a fresh RF session (field
    cycled off/on) -- a magic unlock handshake failing once and succeeding
    on an immediate identical retry is a known characteristic of these
    backdoor sequences, not specific to any one card. A single miss here
    used to fall straight through to styles that could never work on that
    card, producing a worse error than the situation warranted.
    """
    last_err = None
    for attempt in range(GDM_WAKEUP_RETRIES):
        if attempt > 0:
            time.sleep(GDM_WAKEUP_RETRY_DELAY_S)
        try:
            return _gdm_wakeup_once(cmd, style, key, auth_block)
        except Exception as e:
            last_err = e
    raise last_err


def _gdm_read_with_wakeup(cmd, opt, read_cmd, block):
    r = _gen1a_raw(cmd, opt, [read_cmd, block])
    r = bytes(r) if r else b""
    if len(r) < 16:
        raise Exception(f"backdoor read NAK at block {block}")
    return r[:16]


def _gdm_write_with_wakeup(cmd, opt, write_cmd, block, data16):
    r = _gen1a_raw(cmd, opt, [write_cmd, block])
    if not r or r[0] != 0x0a:
        raise Exception(f"write command NAK at block {block}")
    r = _gen1a_raw(cmd, opt, list(data16))
    if not r or r[0] != 0x0a:
        raise Exception(f"write data NAK at block {block}")


def _gdm_resolve_wakeup(cmd, read_cmd, block, gen1a, gdm, wupa, key, prefer_auth=False):
    """Explicit --gen1a/--gdm/--wupa (or a key, which implies --wupa): single
    attempt, no probing. Otherwise auto-detect by probing `block` with
    `read_cmd` across all three styles in turn (config reads try WUPA auth
    first since that path is the one most likely to work read-only even on a
    sealed/custom card; block reads try the two raw-wakeup backdoors first).
    Returns (opt, data16, style_name). Raises if nothing works.
    """
    explicit = [s for s, f in (('gen1a', gen1a), ('gdm', gdm), ('wupa', wupa)) if f]
    if len(explicit) > 1:
        raise ValueError("specify only one of --gen1a / --gdm / --wupa")

    if explicit or key:
        style = explicit[0] if explicit else 'wupa'
        if style != 'wupa' and key:
            raise ValueError("cannot use a key in combination with --gen1a or --gdm wakeup")
        opt = _gdm_wakeup(cmd, style, key or GDM_DEFAULT_KEY, block)
        try:
            data = _gdm_read_with_wakeup(cmd, opt, read_cmd, block)
        except Exception:
            _gen1a_drop_field(cmd, opt)
            raise
        return opt, data, style

    order = ('wupa', 'gen1a', 'gdm') if prefer_auth else ('gen1a', 'gdm', 'wupa')
    for style in order:
        try:
            opt = _gdm_wakeup(cmd, style, GDM_DEFAULT_KEY, block)
        except Exception:
            continue
        try:
            data = _gdm_read_with_wakeup(cmd, opt, read_cmd, block)
            return opt, data, style
        except Exception:
            _gen1a_drop_field(cmd, opt)
    raise Exception("Could not find a working wakeup (tried gen1a/gdm-alt/WUPA default "
                     "key); card may be sealed or use a non-default magic auth key")


def _gdm_print_cfg(data: bytes):
    print(f" Raw config: {color_string((CY, data.hex().upper()))}")
    # Verified against cmdhfmf.c's own parse_gdm_cfg(): byte[2] literally
    # selects which raw-wakeup backdoor the card answers to (0x85=GDM-alt,
    # anything else=gen1a); this does not affect the WUPA magic-auth path.
    style = "GDM 20(7)/23" if len(data) > 2 and data[2] == 0x85 else "Gen1a 40(7)/43"
    print(f" Raw-wakeup backdoor style: {color_string((CY, style))}")
    print(color_string((CY,
        "Other config bits (shadow mode, CUID, signature sector, etc.) vary by "
        "vendor batch and are not decoded here -- use the raw hex above.")))


@hf_mf.command("gdmgetcfg")
class HFMFGdmGetCfg(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Get configuration data from a GDM ('USCUID') card. "
                              "With no wakeup flag, auto-detects (tries WUPA magic "
                              "auth, then gen1a, then gdm alt).")
        parser.add_argument("--gen1a", action="store_true", help="force gen1a (40/43) magic wakeup")
        parser.add_argument("--gdm", action="store_true", help="force gdm alt (20/23) magic wakeup")
        parser.add_argument("--wupa", action="store_true", help="force WUPA + magic auth wakeup")
        parser.add_argument("-k", "--key", type=str, default=None, metavar="<hex12>",
                            help="6-byte magic auth key for --wupa (default 000000000000)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        key = bytes.fromhex(args.key) if args.key else None
        if key is not None and len(key) != 6:
            print(color_string((CR, "key must be 6 bytes (12 hex chars)")))
            return
        try:
            opt, data, style = _gdm_resolve_wakeup(
                self.cmd, GDM_READ_CFG, 0, args.gen1a, args.gdm, args.wupa, key, prefer_auth=True)
        except Exception as e:
            print(color_string((CR, f"gdmgetcfg failed: {e}")))
            return
        _gen1a_drop_field(self.cmd, opt)
        if not (args.gen1a or args.gdm or args.wupa or key):
            print(color_string((CY, f"Auto-detected wakeup: {style}")))
        _gdm_print_cfg(data)


@hf_mf.command("gdmsetcfg")
class HFMFGdmSetCfg(ReaderRequiredUnit):
    """v1: raw hex only, no field-level flags (--cuid/--shadow/etc. from PM3's
    own gdmsetcfg). Those toggle specific bits at specific byte offsets whose
    exact positions genuinely vary by vendor batch per an open PM3 issue
    (RfidResearchGroup/proxmark3#2073) -- getting one wrong is a write, not a
    read, so this stays at raw-hex-in/raw-hex-out until that's verified
    independently rather than taken on faith from one vendor's sample."""

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set configuration data on a GDM ('USCUID') card (raw hex)"
        parser.add_argument("-d", "--data", type=str, required=True, metavar="<hex32>",
                            help="16-byte config block (32 hex chars)")
        parser.add_argument("--gen1a", action="store_true", help="force gen1a (40/43) magic wakeup")
        parser.add_argument("--gdm", action="store_true", help="force gdm alt (20/23) magic wakeup")
        parser.add_argument("--wupa", action="store_true", help="force WUPA + magic auth wakeup")
        parser.add_argument("-k", "--key", type=str, default=None, metavar="<hex12>",
                            help="6-byte magic auth key for --wupa (default 000000000000)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        cfg = bytes.fromhex(args.data)
        if len(cfg) != 16:
            print(color_string((CR, "config data must be 16 bytes (32 hex chars)")))
            return
        key = bytes.fromhex(args.key) if args.key else None
        if key is not None and len(key) != 6:
            print(color_string((CR, "key must be 6 bytes (12 hex chars)")))
            return
        try:
            opt, _old, style = _gdm_resolve_wakeup(
                self.cmd, GDM_READ_CFG, 0, args.gen1a, args.gdm, args.wupa, key, prefer_auth=True)
        except Exception as e:
            print(color_string((CR, f"gdmsetcfg failed: {e}")))
            return
        if not (args.gen1a or args.gdm or args.wupa or key):
            print(color_string((CY, f"Auto-detected wakeup: {style}")))
        try:
            _gdm_write_with_wakeup(self.cmd, opt, GDM_WRITE_CFG, 0, cfg)
        except Exception as e:
            print(color_string((CR, f"gdmsetcfg failed: {e}")))
            return
        finally:
            _gen1a_drop_field(self.cmd, opt)
        print(color_string((CG, "GDM config written")))
        print(color_string((CY, "Hint: run `hf mf gdmgetcfg` to verify")))


@hf_mf.command("gdmgetblk")
class HFMFGdmGetBlk(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Read a public block from a GDM ('USCUID') card. "
                              "With no wakeup flag, auto-detects (tries gen1a, "
                              "then gdm alt, then WUPA default-key auth).")
        parser.add_argument("--blk", type=int, required=True, help="Block number")
        parser.add_argument("--gen1a", action="store_true", help="force gen1a (40/43) magic wakeup")
        parser.add_argument("--gdm", action="store_true", help="force gdm alt (20/23) magic wakeup")
        parser.add_argument("--wupa", action="store_true", help="force WUPA + magic auth wakeup")
        parser.add_argument("-k", "--key", type=str, default=None, metavar="<hex12>",
                            help="6-byte magic auth key for --wupa (default 000000000000)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        key = bytes.fromhex(args.key) if args.key else None
        if key is not None and len(key) != 6:
            print(color_string((CR, "key must be 6 bytes (12 hex chars)")))
            return
        try:
            opt, data, style = _gdm_resolve_wakeup(
                self.cmd, GDM_READBLOCK, args.blk, args.gen1a, args.gdm, args.wupa, key)
        except Exception as e:
            print(color_string((CR, f"gdmgetblk failed: {e}")))
            return
        _gen1a_drop_field(self.cmd, opt)
        if not (args.gen1a or args.gdm or args.wupa or key):
            print(color_string((CY, f"Auto-detected wakeup: {style}")))
        print(f" block {args.blk:3d}: {color_string((CY, data.hex().upper()))}")


@hf_mf.command("gdmsetblk")
class HFMFGdmSetBlk(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = ("Write a public block on a GDM ('USCUID') card. "
                              "With no wakeup flag, auto-detects (tries gen1a, "
                              "then gdm alt, then WUPA default-key auth).")
        parser.add_argument("--blk", type=int, required=True, help="Block number")
        parser.add_argument("-d", "--data", type=str, required=True, metavar="<hex32>",
                            help="16 bytes of block data (32 hex chars)")
        parser.add_argument("--gen1a", action="store_true", help="force gen1a (40/43) magic wakeup")
        parser.add_argument("--gdm", action="store_true", help="force gdm alt (20/23) magic wakeup")
        parser.add_argument("--wupa", action="store_true", help="force WUPA + magic auth wakeup")
        parser.add_argument("-k", "--key", type=str, default=None, metavar="<hex12>",
                            help="6-byte magic auth key for --wupa (default 000000000000)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        data16 = bytes.fromhex(args.data)
        if len(data16) != 16:
            print(color_string((CR, "data must be 16 bytes (32 hex chars)")))
            return
        key = bytes.fromhex(args.key) if args.key else None
        if key is not None and len(key) != 6:
            print(color_string((CR, "key must be 6 bytes (12 hex chars)")))
            return
        try:
            opt, _old, style = _gdm_resolve_wakeup(
                self.cmd, GDM_READBLOCK, args.blk, args.gen1a, args.gdm, args.wupa, key)
        except Exception as e:
            print(color_string((CR, f"gdmsetblk failed: {e}")))
            return
        if not (args.gen1a or args.gdm or args.wupa or key):
            print(color_string((CY, f"Auto-detected wakeup: {style}")))
        try:
            _gdm_write_with_wakeup(self.cmd, opt, GDM_WRITEBLOCK, args.blk, data16)
        except Exception as e:
            print(color_string((CR, f"gdmsetblk failed: {e}")))
            return
        finally:
            _gen1a_drop_field(self.cmd, opt)
        print(color_string((CG, f"block {args.blk} written")))


@hf_mf.command("cgetblk")
class HFMFCGetBlk(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read one block via the gen1a backdoor (no keys needed)"
        parser.add_argument("-b", "--block", type=int, required=True, metavar="<dec>",
                            help="Block number")
        return parser

    def on_exec(self, args: argparse.Namespace):
        opt = _gen1a_new_session()
        try:
            _gen1a_unlock(self.cmd, opt)
            data = _gen1a_read_blk(self.cmd, opt, args.block)
            print(f" - Block {args.block}: {data.hex().upper()}")
        except Exception as e:
            print(f" - cgetblk failed: {e}")
        finally:
            _gen1a_drop_field(self.cmd, opt)


@hf_mf.command("csetblk")
class HFMFCSetBlk(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write one block via the gen1a backdoor (no keys needed)"
        parser.add_argument("-b", "--block", type=int, required=True, metavar="<dec>",
                            help="Block number")
        parser.add_argument("-d", "--data", type=str, required=True, metavar="<hex32>",
                            help="16-byte block data")
        return parser

    def on_exec(self, args: argparse.Namespace):
        block_data = bytes.fromhex(args.data)
        if len(block_data) != 16:
            print("block data must be 16 bytes"); return
        opt = _gen1a_new_session()
        try:
            _gen1a_unlock(self.cmd, opt)
            _gen1a_write_blk(self.cmd, opt, args.block, block_data)
            print(f" - Block {args.block} written: {block_data.hex().upper()}")
        except Exception as e:
            print(f" - csetblk failed: {e}")
        finally:
            _gen1a_drop_field(self.cmd, opt)


@hf_mf.command("csetuid")
class HFMFCSetUID(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Set the UID on a gen1a magic card via the backdoor (no keys needed). "
            "4-byte UID only - keeps the rest of block 0 (SAK/ATQA/manufacturer "
            "bytes) as read from the card and recomputes BCC."
        )
        parser.add_argument("-u", "--uid", type=str, required=True, metavar="<hex8>",
                            help="New 4-byte UID")
        return parser

    def on_exec(self, args: argparse.Namespace):
        uid = bytes.fromhex(args.uid)
        if len(uid) != 4:
            print("UID must be 4 bytes (7-byte gen1a UIDs are not supported by this command)")
            return
        bcc = 0
        for b in uid:
            bcc ^= b
        opt = _gen1a_new_session()
        try:
            _gen1a_unlock(self.cmd, opt)
            blk0 = bytearray(_gen1a_read_blk(self.cmd, opt, 0))
            blk0[0:4] = uid
            blk0[4] = bcc
            _gen1a_write_blk(self.cmd, opt, 0, bytes(blk0))
            print(f" - Gen1a UID set to {uid.hex().upper()} (block 0: {blk0.hex().upper()})")
        except Exception as e:
            print(f" - csetuid failed: {e}")
        finally:
            _gen1a_drop_field(self.cmd, opt)


@hf_mf.command("cview")
class HFMFCView(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Dump a gen1a magic card via the backdoor (no keys needed)"
        parser.add_argument("--4k", dest="is4k", action="store_true",
                            help="256 blocks (4K) instead of the default 64 blocks (1K)")
        parser.add_argument("-f", "--file", type=str, default=None, metavar="<fn>",
                            help="Save to file (.bin raw, or .json Proxmark3 'mfc v2')")
        return parser

    def on_exec(self, args: argparse.Namespace):
        nblocks = 256 if args.is4k else 64
        try:
            raw = _gen1a_read_dump(self.cmd, nblocks)
        except Exception as e:
            print(f" - cview failed: {e}")
            return
        print_mem_dump(raw, 16)
        if args.file:
            if args.file.lower().endswith(".json"):
                blocks = {i: raw[i * 16:i * 16 + 16] for i in range(nblocks)}
                # ATQA/SAK come from the reader-level anticollision response,
                # not from block 0, so do a normal (non-backdoor) scan for them.
                scan = self.cmd.hf14a_scan()
                uid, atqa, sak = (scan[0]["uid"], scan[0]["atqa"], scan[0]["sak"][0]) \
                    if scan else (raw[0:4], b"\x00\x00", 0)
                obj = chameleon_pm3.mfc_blocks_to_json(uid, atqa, sak, blocks)
                with open(args.file, "w") as fh:
                    json.dump(obj, fh, indent=4)
            else:
                with open(args.file, "wb") as fh:
                    fh.write(raw)
            print(f" - Saved to {args.file}")


@hf_mf.command("cload")
class HFMFCLoad(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = (
            "Write a dump to a gen1a magic card via the backdoor (no keys needed). "
            "Equivalent to `hf mf clone --gen1a`, named to match Proxmark3's `hf mf cload`."
        )
        parser.add_argument("-f", "--dump-file", type=argparse.FileType("rb"), required=True,
                            help="Dump file (raw .bin)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        buffer = args.dump_file.read()
        if len(buffer) % 16 != 0:
            print("Data block not aligned to 16 bytes"); return
        if len(buffer) // 16 > 256:
            print("Data block memory overflow"); return
        _gen1a_write_dump(self.cmd, buffer)


@hf_mf.command("ggetblk")
class HFMFG4GetBlk(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read one block from a Gen4-GTU ('Ultimate Magic') card - not Gen4-GDM, a different protocol"
        parser.add_argument("-b", "--block", type=int, required=True, help="Block number")
        parser.add_argument("-p", "--pwd", type=str, default=None, metavar="<hex8>",
                            help="Gen4 password, 4 bytes (default 00000000)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not 0 <= args.block <= 255:
            print("block must be 0-255"); return
        ok, resp = _gen4_raw(self.cmd, _gen4_pwd(args), 0xCE, bytes([args.block]))
        if ok and len(resp) >= 16:
            print(f" - Block {args.block}: {resp[:16].hex().upper()}")
        else:
            print(f" - Gen4 read failed (is this a Gen4 card? wrong password?)")


@hf_mf.command("gsetblk")
class HFMFG4SetBlk(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write one block to a Gen4-GTU ('Ultimate Magic') card - not Gen4-GDM, a different protocol"
        parser.add_argument("-b", "--block", type=int, required=True, help="Block number")
        parser.add_argument("-d", "--data", type=str, required=True, metavar="<hex32>",
                            help="16-byte block data")
        parser.add_argument("-p", "--pwd", type=str, default=None, metavar="<hex8>",
                            help="Gen4 password, 4 bytes (default 00000000)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        data = bytes.fromhex(args.data)
        if len(data) != 16:
            print("block data must be 16 bytes"); return
        if not 0 <= args.block <= 255:
            print("block must be 0-255"); return
        pwd = _gen4_pwd(args)
        _, resp = _gen4_raw(self.cmd, pwd, 0xCD, bytes([args.block]) + data)
        ok = _gen4_write_ok(resp)
        print(f" - Block {args.block} {'written' if ok else 'write failed'}")
        if ok:
            _gen4_verify_write(f"block {args.block}", _gen4_read_blk(self.cmd, pwd, args.block), data)


@hf_mf.command("gsetuid")
class HFMFG4SetUID(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set the UID on a Gen4-GTU ('Ultimate Magic') card"
        parser.add_argument("-u", "--uid", type=str, required=True, metavar="<hex>",
                            help="New UID, 4 or 7 bytes")
        parser.add_argument("-p", "--pwd", type=str, default=None, metavar="<hex8>",
                            help="Gen4 password, 4 bytes (default 00000000)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        uid = bytes.fromhex(args.uid)
        if len(uid) not in (4, 7):
            print("UID must be 4 or 7 bytes"); return
        pwd = _gen4_pwd(args)
        _, resp = _gen4_raw(self.cmd, pwd, 0xFE, uid)
        ok = _gen4_write_ok(resp)
        print(f" - Gen4 UID {'set to ' + uid.hex().upper() if ok else 'set failed'}")
        if ok:
            blk0 = _gen4_read_blk(self.cmd, pwd, 0)
            _gen4_verify_write("UID", blk0[:len(uid)] if blk0 else None, uid)


@hf_mf.command("gsetpwd")
class HFMFG4SetPwd(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Change the Gen4-GTU ('Ultimate Magic') password"
        parser.add_argument("-p", "--pwd", type=str, default=None, metavar="<hex8>",
                            help="Current password, 4 bytes (default 00000000)")
        parser.add_argument("-n", "--new", type=str, required=True, metavar="<hex8>",
                            help="New password, 4 bytes")
        return parser

    def on_exec(self, args: argparse.Namespace):
        new = bytes.fromhex(args.new)
        if len(new) != 4:
            print("new password must be 4 bytes"); return
        confirm = input(f" [!] Changing the Gen4 password to {new.hex().upper()}. "
                        f"A wrong value locks the password-gated commands. Type 'yes': ")
        if confirm.strip().lower() != "yes":
            print(" - aborted"); return
        _, resp = _gen4_raw(self.cmd, _gen4_pwd(args), 0xFD, new)
        ok = _gen4_write_ok(resp)
        print(f" - Gen4 password {'changed' if ok else 'change failed'}")
        if ok:
            # Can't read a password back, so verify indirectly: a config
            # read using the NEW password should now succeed.
            if _gen4_read_config(self.cmd, new) is None:
                print("   (!) ack said success but the new password doesn't "
                      "unlock the card - change may not have actually applied")


@hf_mf.command("gconfig")
class HFMFG4Config(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read or write the Gen4-GTU ('Ultimate Magic') config block"
        parser.add_argument("-d", "--data", type=str, default=None, metavar="<hex>",
                            help="Config bytes to write; omit to read current config")
        parser.add_argument("-p", "--pwd", type=str, default=None, metavar="<hex8>",
                            help="Gen4 password, 4 bytes (default 00000000)")
        return parser

    def on_exec(self, args: argparse.Namespace):
        pwd = _gen4_pwd(args)
        if args.data:
            cfg = bytes.fromhex(args.data)
            _, resp = _gen4_raw(self.cmd, pwd, 0xF0, cfg)
            ok = _gen4_write_ok(resp)
            print(f" - Gen4 config {'written' if ok else 'write failed'}")
            if ok:
                _gen4_verify_write("config", _gen4_read_config(self.cmd, pwd), cfg)
        else:
            ok, resp = _gen4_raw(self.cmd, pwd, 0xC6)
            if ok:
                print(f" - Gen4 config: {resp.hex().upper()}")
            else:
                print(" - Gen4 config read failed (is this a Gen4 card? wrong password?)")


@hf_mf.command("gen3uid")
class HFMFGen3UID(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Set UID on a Gen3 magic card (block 0 manufacturer bytes kept)"
        parser.add_argument("-u", "--uid", type=str, required=True, metavar="<hex>",
                            help="New UID, 4 or 7 bytes")
        return parser

    def on_exec(self, args: argparse.Namespace):
        uid = bytes.fromhex(args.uid)
        if len(uid) not in (4, 7):
            print("UID must be 4 or 7 bytes"); return
        apdu = bytes([0x90, 0xFB, 0xCC, 0xCC, len(uid)]) + uid
        ok, resp = _gen3_raw(self.cmd, apdu)
        if ok:
            print(f" - Gen3 UID set to {uid.hex().upper()}")
        else:
            print(f" - Gen3 UID set failed (is this a Gen3 card?) resp={resp.hex() or 'none'}")


@hf_mf.command("gen3blk")
class HFMFGen3Blk(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Write full block 0 on a Gen3 magic card"
        parser.add_argument("-d", "--data", type=str, required=True, metavar="<hex>",
                            help="16-byte block 0")
        return parser

    def on_exec(self, args: argparse.Namespace):
        blk0 = bytes.fromhex(args.data)
        if len(blk0) != 16:
            print("block 0 must be 16 bytes"); return
        apdu = bytes([0x90, 0xF0, 0xCC, 0xCC, 0x10]) + blk0
        ok, resp = _gen3_raw(self.cmd, apdu)
        if ok:
            print(f" - Gen3 block 0 written: {blk0.hex().upper()}")
        else:
            print(f" - Gen3 block 0 write failed (is this a Gen3 card?) resp={resp.hex() or 'none'}")


@hf_mf.command("gen3freeze")
class HFMFGen3Freeze(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Permanently lock the UID of a Gen3 magic card (IRREVERSIBLE)"
        return parser

    def on_exec(self, args: argparse.Namespace):
        confirm = input(" [!] This permanently locks the UID and cannot be undone. Type 'yes': ")
        if confirm.strip().lower() != "yes":
            print(" - aborted"); return
        apdu = bytes([0x90, 0xFD, 0x11, 0x11, 0x00])
        ok, resp = _gen3_raw(self.cmd, apdu)
        if ok:
            print(" - Gen3 UID permanently locked")
        else:
            print(f" - Gen3 freeze failed (is this a Gen3 card?) resp={resp.hex() or 'none'}")


@hf_mf.command("clone")
class HFMFClone(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Mifare Classic clone tag from dump"
        parser.add_argument(
            "-t",
            "--dump-file-type",
            type=str,
            required=False,
            help="Dump file content type",
            choices=["bin", "hex"],
        )
        parser.add_argument(
            "-a",
            "--clone-access",
            type=bool,
            default=False,
            help="Write ACL from original dump too (! could brick your tag)",
        )
        parser.add_argument(
            "--gen1a",
            action="store_true",
            help="Write via the gen1a backdoor (magic card); no keys needed, clones block 0",
        )
        parser.add_argument(
            "-f",
            "--dump-file",
            type=argparse.FileType("rb"),
            required=True,
            help="Dump file containing data to write on new tag",
        )
        parser.add_argument(
            "-d",
            "--dic",
            type=argparse.FileType("r"),
            required=False,
            help="Read keys (to communicate with tag to write) from .dic format file",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.dump_file_type is None:
            if args.dump_file.name.endswith(".bin"):
                content_type = "bin"
            elif args.dump_file.name.endswith(".eml"):
                content_type = "hex"
            else:
                raise Exception(
                    "Unknown file format, Specify content type with -t option"
                )
        else:
            content_type = args.dump_file_type

        # data to write from dump file
        buffer = bytearray()
        if content_type == "bin":
            buffer.extend(args.dump_file.read())
        if content_type == "hex":
            buffer.extend(bytearray.fromhex(args.dump_file.read().decode()))
        if len(buffer) % 16 != 0:
            raise Exception("Data block not align for 16 bytes")
        if len(buffer) / 16 > 256:
            raise Exception("Data block memory overflow")

        if args.gen1a:
            self._clone_gen1a(buffer)
            return

        if args.dic is None:
            raise Exception("keyed clone needs -d <dict>; use --gen1a for a gen1a magic card")

        # keys to use from file
        keys = [bytes.fromhex(line[:-1]) for line in args.dic.readlines()]

        # iterate over sectors
        for s in range(16):
            # try all keys for this sector
            keyA, keyB = None, None
            for key in keys:
                # first try key B
                try:
                    self.cmd.mf1_read_one_block(4 * s, MfcKeyType.B, key)
                    keyB = key
                except UnexpectedResponseError:
                    # ignore read errors at this stage as we want to try key A
                    pass
                # try with key A if B was unsuccessful
                try:
                    self.cmd.mf1_read_one_block(4 * s, MfcKeyType.A, key)
                    keyA = key
                except UnexpectedResponseError:
                    pass
                # both keys were found, no need to continue iterating
                if keyA and keyB:
                    break
            # neither A or B key was found
            if not keyA and not keyB:
                raise Exception(f"No key found for sector {s}")
            # iterate over blocks
            for b in range(4):
                block_data = buffer[(4 * s + b) * 16 : (4 * s + b + 1) * 16]
                # special case for last block of each sector
                if b == 3:
                    # check ACL option
                    if not args.clone_access:
                        # if option is not specified, use generic ACL to be able to write again
                        block_data = (
                            block_data[:6] + bytes.fromhex("ff0780") + block_data[9:]
                        )
                try:
                    # try B key first
                    self.cmd.mf1_write_one_block(
                        4 * s + b, MfcKeyType.B, keyB, block_data
                    )
                    continue
                except UnexpectedResponseError:
                    pass
                self.cmd.mf1_write_one_block(4 * s + b, MfcKeyType.A, keyA, block_data)


    def _clone_gen1a(self, buffer):
        # Kept for `clone --gen1a` backward compatibility; the real logic now
        # lives in _gen1a_write_dump (shared with the `cload` command) so
        # there's one implementation of the backdoor write sequence.
        _gen1a_write_dump(self.cmd, buffer)


@hf_mf.command("value")
class HFMFVALUE(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "MIFARE Classic value block commands"

        operator_group = parser.add_mutually_exclusive_group()
        operator_group.add_argument(
            "--get", action="store_true", help="get value from src block"
        )
        operator_group.add_argument(
            "--set",
            type=int,
            required=False,
            metavar="<dec>",
            help="set value X (-2147483647 ~ 2147483647) to src block",
        )
        operator_group.add_argument(
            "--inc",
            type=int,
            required=False,
            metavar="<dec>",
            help="increment value by X (0 ~ 2147483647) from src to dst",
        )
        operator_group.add_argument(
            "--dec",
            type=int,
            required=False,
            metavar="<dec>",
            help="decrement value by X (0 ~ 2147483647) from src to dst",
        )
        operator_group.add_argument(
            "--res",
            "--cp",
            action="store_true",
            help="copy value from src to dst (Restore and Transfer)",
        )

        parser.add_argument(
            "--blk",
            "--src-block",
            type=int,
            required=True,
            metavar="<dec>",
            help="block number of src",
        )
        srctype_group = parser.add_mutually_exclusive_group()
        srctype_group.add_argument(
            "-a", "-A", action="store_true", help="key of src is A key (default)"
        )
        srctype_group.add_argument(
            "-b", "-B", action="store_true", help="key of src is B key"
        )
        parser.add_argument(
            "-k",
            "--src-key",
            type=str,
            required=True,
            metavar="<hex>",
            help="key of src",
        )

        parser.add_argument(
            "--tblk",
            "--dst-block",
            type=int,
            metavar="<dec>",
            help="block number of dst (default to src)",
        )
        dsttype_group = parser.add_mutually_exclusive_group()
        dsttype_group.add_argument(
            "--ta",
            "--tA",
            action="store_true",
            help="key of dst is A key (default to src)",
        )
        dsttype_group.add_argument(
            "--tb",
            "--tB",
            action="store_true",
            help="key of dst is B key (default to src)",
        )
        parser.add_argument(
            "--tkey",
            "--dst-key",
            type=str,
            metavar="<hex>",
            help="key of dst (default to src)",
        )

        return parser

    def on_exec(self, args: argparse.Namespace):
        # print(args)
        # src
        src_blk = args.blk
        src_type = MfcKeyType.B if args.b is not False else MfcKeyType.A
        src_key = args.src_key
        if not re.match(r"^[a-fA-F0-9]{12}$", src_key):
            print("src_key must include 12 HEX symbols")
            return
        src_key = bytearray.fromhex(src_key)
        # print(src_blk, src_type, src_key)

        if args.get is not False:
            self.get_value(src_blk, src_type, src_key)
            return
        elif args.set is not None:
            self.set_value(src_blk, src_type, src_key, args.set)
            return

        # dst
        dst_blk = args.tblk if args.tblk is not None else src_blk
        dst_type = (
            MfcKeyType.A
            if args.ta is not False
            else (MfcKeyType.B if args.tb is not False else src_type)
        )
        dst_key = args.tkey if args.tkey is not None else args.src_key
        if not re.match(r"^[a-fA-F0-9]{12}$", dst_key):
            print("dst_key must include 12 HEX symbols")
            return
        dst_key = bytearray.fromhex(dst_key)
        # print(dst_blk, dst_type, dst_key)

        if args.inc is not None:
            self.inc_value(
                src_blk, src_type, src_key, args.inc, dst_blk, dst_type, dst_key
            )
            return
        elif args.dec is not None:
            self.dec_value(
                src_blk, src_type, src_key, args.dec, dst_blk, dst_type, dst_key
            )
            return
        elif args.res is not False:
            self.res_value(src_blk, src_type, src_key, dst_blk, dst_type, dst_key)
            return
        else:
            raise ArgsParserError("Please specify a value command")

    def get_value(self, block, type, key):
        resp = self.cmd.mf1_read_one_block(block, type, key)
        val1, val2, val3, adr1, adr2, adr3, adr4 = struct.unpack("<iiiBBBB", resp)
        # print(f"{val1}, {val2}, {val3}, {adr1}, {adr2}, {adr3}, {adr4}")
        if (val1 != val3) or (val1 + val2 != -1):
            print(
                f" - {color_string((CR, f'Invalid value of value block: {resp.hex()}'))}"
            )
            return
        if (adr1 != adr3) or (adr2 != adr4) or (adr1 + adr2 != 0xFF):
            print(
                f" - {color_string((CR, f'Invalid address of value block: {resp.hex()}'))}"
            )
            return
        print(
            f" - block[{block}] = {color_string((CG, f'{{ value: {val1}, adr: {adr1} }}'))}"
        )

    def set_value(self, block, type, key, value):
        if value < -2147483647 or value > 2147483647:
            raise ArgsParserError(
                f"Set value must be between -2147483647 and 2147483647. Got {value}"
            )
        adr_inverted = 0xFF - block
        data = struct.pack(
            "<iiiBBBB",
            value,
            -value - 1,
            value,
            block,
            adr_inverted,
            block,
            adr_inverted,
        )
        resp = self.cmd.mf1_write_one_block(block, type, key, data)
        if resp:
            print(f" - {color_string((CG, 'Set done.'))}")
            self.get_value(block, type, key)
        else:
            print(f" - {color_string((CR, 'Set fail.'))}")

    def inc_value(self, src_blk, src_type, src_key, value, dst_blk, dst_type, dst_key):
        if value < 0 or value > 2147483647:
            raise ArgsParserError(
                f"Increment value must be between 0 and 2147483647. Got {value}"
            )
        resp = self.cmd.mf1_manipulate_value_block(
            src_blk,
            src_type,
            src_key,
            MfcValueBlockOperator.INCREMENT,
            value,
            dst_blk,
            dst_type,
            dst_key,
        )
        if resp:
            print(f" - {color_string((CG, 'Increment done.'))}")
            self.get_value(dst_blk, dst_type, dst_key)
        else:
            print(f" - {color_string((CR, 'Increment fail.'))}")

    def dec_value(self, src_blk, src_type, src_key, value, dst_blk, dst_type, dst_key):
        if value < 0 or value > 2147483647:
            raise ArgsParserError(
                f"Decrement value must be between 0 and 2147483647. Got {value}"
            )
        resp = self.cmd.mf1_manipulate_value_block(
            src_blk,
            src_type,
            src_key,
            MfcValueBlockOperator.DECREMENT,
            value,
            dst_blk,
            dst_type,
            dst_key,
        )
        if resp:
            print(f" - {color_string((CG, 'Decrement done.'))}")
            self.get_value(dst_blk, dst_type, dst_key)
        else:
            print(f" - {color_string((CR, 'Decrement fail.'))}")

    def res_value(self, src_blk, src_type, src_key, dst_blk, dst_type, dst_key):
        resp = self.cmd.mf1_manipulate_value_block(
            src_blk,
            src_type,
            src_key,
            MfcValueBlockOperator.RESTORE,
            0,
            dst_blk,
            dst_type,
            dst_key,
        )
        if resp:
            print(f" - {color_string((CG, 'Restore done.'))}")
            self.get_value(dst_blk, dst_type, dst_key)
        else:
            print(f" - {color_string((CR, 'Restore fail.'))}")


class ItemGenerator:
    def __init__(self, rs, uid_found_keys=set()):
        self.rs: list = rs
        self.progress = 0
        self.i = 0
        self.j = 1
        self.found = set()
        self.keys = set()
        for known_key in uid_found_keys:
            self.test_key(known_key)

    def __iter__(self):
        return self

    def __next__(self):
        size = len(self.rs)
        if self.j >= size:
            self.i += 1
            if self.i >= size - 1:
                raise StopIteration
            self.j = self.i + 1
        item_i, item_j = self.rs[self.i], self.rs[self.j]
        self.progress += 1
        self.j += 1
        if self.key_from_item(item_i) in self.found:
            self.progress += max(0, size - self.j)
            self.i += 1
            self.j = self.i + 1
            return next(self)
        if self.key_from_item(item_j) in self.found:
            return next(self)
        return item_i, item_j

    @staticmethod
    def key_from_item(item):
        return "{uid}-{nt}-{nr}-{ar}".format(**item)

    def test_key(self, key, items=list()):
        for item in self.rs:
            item_key = self.key_from_item(item)
            if item_key in self.found:
                continue
            if (item in items) or (
                Crypto1.mfkey32_is_reader_has_key(
                    int(item["uid"], 16),
                    int(item["nt"], 16),
                    int(item["nr"], 16),
                    int(item["ar"], 16),
                    key,
                )
            ):
                self.keys.add(key)
                self.found.add(item_key)


@hf_mf.command("elog")
class HFMFELog(DeviceRequiredUnit):
    detection_log_size = 18

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "MF1 Detection log count/decrypt"
        parser.add_argument(
            "--decrypt", action="store_true", help="Decrypt key from MF1 log list"
        )
        return parser

    def decrypt_by_list(self, rs: list, uid_found_keys: set = set()):
        """
            Decrypt key from reconnaissance log list

        :param rs:
        :return:
        """
        msg1 = f"  > {len(rs)} records => "
        msg2 = f"/{(len(rs)*(len(rs)-1))//2} combinations. "
        msg3 = " key(s) found"
        gen = ItemGenerator(rs, uid_found_keys)
        print(f"{msg1}{gen.progress}{msg2}{len(gen.keys)}{msg3}\r", end="")
        with Pool(cpu_count()) as pool:
            for result in pool.imap(_run_mfkey32v2, gen):
                if result is not None:
                    gen.test_key(*result)
                print(f"{msg1}{gen.progress}{msg2}{len(gen.keys)}{msg3}\r", end="")
        print(f"{msg1}{gen.progress}{msg2}{len(gen.keys)}{msg3}")
        return gen.keys

    def on_exec(self, args: argparse.Namespace):
        if not args.decrypt:
            count = self.cmd.mf1_get_detection_count()
            print(f" - MF1 detection log count = {count}")
            return
        index = 0
        count = self.cmd.mf1_get_detection_count()
        if count == 0:
            print(" - No detection log to download")
            return
        print(f" - MF1 detection log count = {count}, start download", end="")
        result_list = []
        while index < count:
            tmp = self.cmd.mf1_get_detection_log(index)
            recv_count = len(tmp)
            index += recv_count
            result_list.extend(tmp)
            print("." * recv_count, end="")
        print()
        print(f" - Download done ({len(result_list)} records), start parse and decrypt")
        # classify
        result_maps = {}
        for item in result_list:
            uid = item["uid"]
            if uid not in result_maps:
                result_maps[uid] = {}
            block = item["block"]
            if block not in result_maps[uid]:
                result_maps[uid][block] = {}
            type = item["type"]
            if type not in result_maps[uid][block]:
                result_maps[uid][block][type] = []

            result_maps[uid][block][type].append(item)

        for uid in result_maps.keys():
            print(f" - Detection log for uid [{uid.upper()}]")
            result_maps_for_uid = result_maps[uid]
            uid_found_keys = set()
            for block in result_maps_for_uid:
                for keyType in "AB":
                    records = (
                        result_maps_for_uid[block][keyType]
                        if keyType in result_maps_for_uid[block]
                        else []
                    )
                    if len(records) < 1:
                        continue
                    print(f"  > Decrypting block {block} key {keyType} detect log...")
                    result_maps[uid][block][keyType] = self.decrypt_by_list(
                        records, uid_found_keys
                    )
                    uid_found_keys.update(result_maps[uid][block][keyType])

            print("  > Result ---------------------------")
            for block in result_maps_for_uid.keys():
                if "A" in result_maps_for_uid[block]:
                    print(
                        f"  > Block {block}, A key result: {result_maps_for_uid[block]['A']}"
                    )
                if "B" in result_maps_for_uid[block]:
                    print(
                        f"  > Block {block}, B key result: {result_maps_for_uid[block]['B']}"
                    )
        return


@hf_mf.command("eload")
class HFMFELoad(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Load data to emulator memory"
        self.add_slot_args(parser)
        parser.add_argument("-f", "--file", type=str, required=True, help="file path")
        parser.add_argument(
            "-t",
            "--type",
            type=str,
            required=False,
            help="content type",
            choices=["bin", "hex"],
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        file = args.file
        if args.type is None:
            if file.endswith(".bin"):
                content_type = "bin"
            elif file.endswith(".eml"):
                content_type = "hex"
            elif file.endswith(".json"):
                content_type = "json"
            else:
                raise Exception(
                    "Unknown file format, Specify content type with -t option"
                )
        else:
            content_type = args.type
        buffer = bytearray()

        # Proxmark3 'mfc v2' dump JSON -> block buffer (sniffed by content)
        if content_type not in ("bin", "hex") or file.endswith(".json"):
            with open(file, "r") as fd:
                text = fd.read()
            if '"mfc' in text and '"blocks"' in text:
                import json

                _card, blocks = chameleon_pm3.mfc_json_to_blocks(json.loads(text))
                for n in range(max(blocks) + 1 if blocks else 0):
                    buffer.extend(blocks.get(n, bytes(16)))
                content_type = "bin"  # already materialized
            elif content_type not in ("bin", "hex"):
                raise Exception(
                    "Unknown file format, Specify content type with -t option"
                )

        if not buffer:
            with open(file, mode="rb") as fd:
                if content_type == "bin":
                    buffer.extend(fd.read())
                if content_type == "hex":
                    buffer.extend(bytearray.fromhex(fd.read().decode()))

        if len(buffer) % 16 != 0:
            raise Exception("Data block not align for 16 bytes")
        if len(buffer) / 16 > 256:
            raise Exception("Data block memory overflow")

        index = 0
        block = 0
        max_blocks = (self.device_com.data_max_length - 1) // 16
        while index + 16 < len(buffer):
            # split a block from buffer
            block_data = buffer[index : index + 16 * max_blocks]
            n_blocks = len(block_data) // 16
            index += 16 * n_blocks
            # load to device
            self.cmd.mf1_write_emu_block_data(block, block_data)
            print("." * n_blocks, end="")
            block += n_blocks
        print("\n - Load success")


@hf_mf.command("esave")
class HFMFESave(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Read data from emulator memory"
        self.add_slot_args(parser)
        parser.add_argument("-f", "--file", type=str, required=True, help="file path")
        parser.add_argument(
            "-t",
            "--type",
            type=str,
            required=False,
            help="content type",
            choices=["bin", "hex"],
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        file = args.file
        if args.type is None:
            if file.endswith(".bin"):
                content_type = "bin"
            elif file.endswith(".eml"):
                content_type = "hex"
            elif file.endswith(".json"):
                content_type = "json"
            else:
                raise Exception(
                    "Unknown file format, Specify content type with -t option"
                )
        else:
            content_type = args.type

        selected_slot = self.cmd.get_active_slot()
        slot_info = self.cmd.get_slot_info()
        tag_type = TagSpecificType(slot_info[selected_slot]["hf"])
        if tag_type == TagSpecificType.MIFARE_Mini:
            block_count = 20
        elif tag_type == TagSpecificType.MIFARE_1024:
            block_count = 64
        elif tag_type in (TagSpecificType.MIFARE_2048, TagSpecificType.MIFARE_PLUS_S2K):
            block_count = 128
        elif tag_type in (TagSpecificType.MIFARE_4096, TagSpecificType.MIFARE_PLUS_S4K):
            block_count = 256
        else:
            raise Exception(
                "Card in current slot is not Mifare Classic/Plus in SL1 mode"
            )

        index = 0
        data = bytearray(0)
        max_blocks = self.device_com.data_max_length // 16
        while block_count > 0:
            chunk_count = min(block_count, max_blocks, 32)
            data.extend(self.cmd.mf1_read_emu_block_data(index, chunk_count))
            index += chunk_count
            block_count -= chunk_count
            print("." * chunk_count, end="")

        if file.endswith(".json") or content_type == "json":
            import json

            uid = bytes(data[0:4])  # block 0: UID(4) BCC SAK ATQA...
            sak = bytes([data[5]])
            atqa = bytes(data[6:8])  # wire order in block 0
            blocks = {
                i: bytes(data[i * 16 : (i + 1) * 16]) for i in range(len(data) // 16)
            }
            obj = chameleon_pm3.mfc_blocks_to_json(uid, atqa, data[5], blocks)
            with open(file, "w") as fd:
                fd.write(json.dumps(obj, indent=4))
            print(
                f"\n - Wrote Proxmark3 'mfc v2' dump ({len(blocks)} blocks) to {file}"
            )
        else:
            with open(file, "wb") as fd:
                if content_type == "hex":
                    for i in range(len(data) // 16):
                        fd.write(binascii.hexlify(data[i * 16 : (i + 1) * 16]) + b"\n")
                else:
                    fd.write(data)
            print("\n - Read success")


@hf_mf.command("eview")
class HFMFEView(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "View data from emulator memory"
        self.add_slot_args(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        selected_slot = self.cmd.get_active_slot()
        slot_info = self.cmd.get_slot_info()
        tag_type = TagSpecificType(slot_info[selected_slot]["hf"])

        if tag_type == TagSpecificType.MIFARE_Mini:
            block_count = 20
        elif tag_type == TagSpecificType.MIFARE_1024:
            block_count = 64
        elif tag_type in (TagSpecificType.MIFARE_2048, TagSpecificType.MIFARE_PLUS_S2K):
            block_count = 128
        elif tag_type in (TagSpecificType.MIFARE_4096, TagSpecificType.MIFARE_PLUS_S4K):
            block_count = 256
        else:
            raise Exception(
                "Card in current slot is not Mifare Classic/Plus in SL1 mode"
            )
        index = 0
        data = bytearray(0)
        max_blocks = self.device_com.data_max_length // 16
        while block_count > 0:
            # read all the blocks
            chunk_count = min(block_count, max_blocks, 32)
            data.extend(self.cmd.mf1_read_emu_block_data(index, chunk_count))
            index += chunk_count
            block_count -= chunk_count
        print_mem_dump(data, 16)


@hf_mf.command("econfig")
class HFMFEConfig(SlotIndexArgsAndGoUnit, HF14AAntiCollArgsUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = "Settings of Mifare Classic emulator"
        self.add_slot_args(parser)
        self.add_hf14a_anticoll_args(parser)
        gen1a_group = parser.add_mutually_exclusive_group()
        gen1a_group.add_argument(
            "--enable-gen1a", action="store_true", help="Enable Gen1a magic mode"
        )
        gen1a_group.add_argument(
            "--disable-gen1a", action="store_true", help="Disable Gen1a magic mode"
        )
        gen2_group = parser.add_mutually_exclusive_group()
        gen2_group.add_argument(
            "--enable-gen2", action="store_true", help="Enable Gen2 magic mode"
        )
        gen2_group.add_argument(
            "--disable-gen2", action="store_true", help="Disable Gen2 magic mode"
        )
        block0_group = parser.add_mutually_exclusive_group()
        block0_group.add_argument(
            "--enable-block0",
            action="store_true",
            help="Use anti-collision data from block 0 for 4 byte UID tags",
        )
        block0_group.add_argument(
            "--disable-block0",
            action="store_true",
            help="Use anti-collision data from settings",
        )
        write_names = [w.name for w in MifareClassicWriteMode.list()]
        help_str = "Write Mode: " + ", ".join(write_names)
        parser.add_argument(
            "--write", type=str, help=help_str, metavar="MODE", choices=write_names
        )
        log_group = parser.add_mutually_exclusive_group()
        log_group.add_argument(
            "--enable-log",
            action="store_true",
            help="Enable logging of MFC authentication data",
        )
        log_group.add_argument(
            "--disable-log",
            action="store_true",
            help="Disable logging of MFC authentication data",
        )
        field_off_reset_group = parser.add_mutually_exclusive_group()
        field_off_reset_group.add_argument(
            "--enable_field_off_do_reset",
            action="store_true",
            help="Enable FIELD_OFF_DO_RESET",
        )
        field_off_reset_group.add_argument(
            "--disable_field_off_do_reset",
            action="store_true",
            help="Disable FIELD_OFF_DO_RESET",
        )
        return parser

    def on_exec(self, args: argparse.Namespace):
        # collect current settings
        anti_coll_data = self.cmd.hf14a_get_anti_coll_data()
        if anti_coll_data is None or len(anti_coll_data) == 0:
            print(
                f"{color_string((CR, f'Slot {self.slot_num} does not contain any HF 14A config'))}"
            )
            return
        uid = anti_coll_data["uid"]
        atqa = anti_coll_data["atqa"]
        sak = anti_coll_data["sak"]
        ats = anti_coll_data["ats"]
        slotinfo = self.cmd.get_slot_info()
        fwslot = SlotNumber.to_fw(self.slot_num)
        hf_tag_type = TagSpecificType(slotinfo[fwslot]["hf"])
        if hf_tag_type not in [
            TagSpecificType.MIFARE_Mini,
            TagSpecificType.MIFARE_1024,
            TagSpecificType.MIFARE_2048,
            TagSpecificType.MIFARE_4096,
            TagSpecificType.MIFARE_PLUS_S2K,
            TagSpecificType.MIFARE_PLUS_S4K,
        ]:
            print(
                f"{color_string((CR, f'Slot {self.slot_num} not configured as MIFARE Classic'))}"
            )
            return
        mfc_config = self.cmd.mf1_get_emulator_config()
        gen1a_mode = mfc_config["gen1a_mode"]
        gen2_mode = mfc_config["gen2_mode"]
        block_anti_coll_mode = mfc_config["block_anti_coll_mode"]
        write_mode = MifareClassicWriteMode(mfc_config["write_mode"])
        detection = mfc_config["detection"]
        change_requested, change_done, uid, atqa, sak, ats = self.update_hf14a_anticoll(
            args, uid, atqa, sak, ats
        )
        field_off_do_reset = self.cmd.mf1_get_field_off_do_reset()

        if args.enable_gen1a:
            change_requested = True
            if not gen1a_mode:
                gen1a_mode = True
                self.cmd.mf1_set_gen1a_mode(gen1a_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested gen1a already enabled"))}')
        elif args.disable_gen1a:
            change_requested = True
            if gen1a_mode:
                gen1a_mode = False
                self.cmd.mf1_set_gen1a_mode(gen1a_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested gen1a already disabled"))}')
        if args.enable_gen2:
            change_requested = True
            if not gen2_mode:
                gen2_mode = True
                self.cmd.mf1_set_gen2_mode(gen2_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested gen2 already enabled"))}')
        elif args.disable_gen2:
            change_requested = True
            if gen2_mode:
                gen2_mode = False
                self.cmd.mf1_set_gen2_mode(gen2_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested gen2 already disabled"))}')
        if args.enable_block0:
            change_requested = True
            if not block_anti_coll_mode:
                block_anti_coll_mode = True
                self.cmd.mf1_set_block_anti_coll_mode(block_anti_coll_mode)
                change_done = True
            else:
                print(
                    f'{color_string((CY, "Requested block0 anti-coll mode already enabled"))}'
                )
        elif args.disable_block0:
            change_requested = True
            if block_anti_coll_mode:
                block_anti_coll_mode = False
                self.cmd.mf1_set_block_anti_coll_mode(block_anti_coll_mode)
                change_done = True
            else:
                print(
                    f'{color_string((CY, "Requested block0 anti-coll mode already disabled"))}'
                )
        if args.write is not None:
            change_requested = True
            new_write_mode = MifareClassicWriteMode[args.write]
            if new_write_mode != write_mode:
                write_mode = new_write_mode
                self.cmd.mf1_set_write_mode(write_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested write mode already set"))}')
        if args.enable_log:
            change_requested = True
            if not detection:
                detection = True
                self.cmd.mf1_set_detection_enable(detection)
                change_done = True
            else:
                print(
                    f'{color_string((CY, "Requested logging of MFC authentication data already enabled"))}'
                )
        elif args.disable_log:
            change_requested = True
            if detection:
                detection = False
                self.cmd.mf1_set_detection_enable(detection)
                change_done = True
            else:
                print(
                    f'{color_string((CY, "Requested logging of MFC authentication data already disabled"))}'
                )
        if args.enable_field_off_do_reset:
            change_requested = True
            if not field_off_do_reset:
                field_off_do_reset = True
                self.cmd.mf1_set_field_off_do_reset(field_off_do_reset)
                change_done = True
            else:
                print(
                    f'{color_string((CY, "Requested FIELD_OFF_DO_RESET already enabled"))}'
                )
        elif args.disable_field_off_do_reset:
            change_requested = True
            if field_off_do_reset:
                field_off_do_reset = False
                self.cmd.mf1_set_field_off_do_reset(field_off_do_reset)
                change_done = True
            else:
                print(
                    f'{color_string((CY, "Requested FIELD_OFF_DO_RESET already disabled"))}'
                )

        if change_done:
            print(" - MF1 Emulator settings updated")
        if not change_requested:
            enabled_str = color_string((CG, "enabled"))
            disabled_str = color_string((CR, "disabled"))
            atqa_string = f"{atqa.hex().upper()} (0x{int.from_bytes(atqa, byteorder='little'):04x})"
            print(f'- {"Type:":40}{color_string((CY, hf_tag_type))}')
            print(f'- {"UID:":40}{color_string((CY, uid.hex().upper()))}')
            print(f'- {"ATQA:":40}{color_string((CY, atqa_string))}')
            print(f'- {"SAK:":40}{color_string((CY, sak.hex().upper()))}')
            if len(ats) > 0:
                print(f'- {"ATS:":40}{color_string((CY, ats.hex().upper()))}')
            print(
                f'- {"Gen1A magic mode:":40}{f"{enabled_str}" if gen1a_mode else f"{disabled_str}"}'
            )
            print(
                f'- {"Gen2 magic mode:":40}{f"{enabled_str}" if gen2_mode else f"{disabled_str}"}'
            )
            print(
                f'- {"Use anti-collision data from block 0:":40}'
                f'{f"{enabled_str}" if block_anti_coll_mode else f"{disabled_str}"}'
            )
            try:
                print(
                    f'- {"Write mode:":40}{color_string((CY, MifareClassicWriteMode(write_mode)))}'
                )
            except ValueError:
                print(f'- {"Write mode:":40}{color_string((CR, "invalid value!"))}')
            print(
                f'- {"Log (mfkey32) mode:":40}{f"{enabled_str}" if detection else f"{disabled_str}"}'
            )
            print(
                f'- {"FIELD_OFF_DO_RESET:":40}{f"{enabled_str}" if field_off_do_reset else f"{disabled_str}"}'
            )
