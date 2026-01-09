#!/usr/bin/env python3
"""Normalize messages using drain3 for pattern recognition."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, TypedDict

from drain3 import TemplateMiner
from drain3.masking import MaskingInstruction
from drain3.template_miner_config import TemplateMinerConfig

from utils import logger, save_json

# Sample short texts for testing
SAMPLE_TEXTS = [
    "[CampaignController][error] Distribution batch",
    "[CampaignController][error] Distripution batc",
    "[CampaignController][error] Disasicution batch",
]

def configure_template_miner() -> TemplateMiner:
    """
    Configure the drain3 template miner with custom masking instructions.

    Returns:
        Configured TemplateMiner instance
    """
    config = TemplateMinerConfig()
    config.mask_prefix = "<"
    config.mask_suffix = ">"

    # Clear default masking instructions and add custom ones
    config.masking_instructions = []

    # IP addresses
    config.masking_instructions.append(
        MaskingInstruction(pattern=r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", mask_with="IP")
    )

    # Timestamps in various formats
    config.masking_instructions.append(
        MaskingInstruction(
            pattern=r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+|-)\d{2}:\d{2}\]",
            mask_with="[TIMESTAMP]",
        )
    )
    config.masking_instructions.append(
        MaskingInstruction(pattern=r"\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?\]", mask_with="[TIMESTAMP]")
    )
    config.masking_instructions.append(
        MaskingInstruction(
            pattern=r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+|-)\d{2}:\d{2}",
            mask_with="TIMESTAMP",
        )
    )
    config.masking_instructions.append(
        MaskingInstruction(pattern=r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} (\+|-)\d{4}", mask_with="TIMESTAMP")
    )
    config.masking_instructions.append(
        MaskingInstruction(pattern=r"[A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}", mask_with="TIMESTAMP")
    )
    config.masking_instructions.append(MaskingInstruction(pattern=r"\d{4}-\d{2}-\d{2}", mask_with="DATE"))
    config.masking_instructions.append(MaskingInstruction(pattern=r"\d{2}:\d{2}:\d{2}(\.\d+)?", mask_with="TIME"))

    # UUIDs
    config.masking_instructions.append(
        MaskingInstruction(
            pattern=r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            mask_with="UUID",
        )
    )

    # Hexadecimal identifiers
    config.masking_instructions.append(MaskingInstruction(pattern=r"\b[0-9a-f]{16,}\b", mask_with="HEX"))

    # Process IDs
    config.masking_instructions.append(MaskingInstruction(pattern=r"\[\d+\]", mask_with="[PID]"))

    # Line numbers in stack traces
    config.masking_instructions.append(MaskingInstruction(pattern=r"line:? \d+", mask_with="line: NUM"))
    config.masking_instructions.append(MaskingInstruction(pattern=r":\d+\)", mask_with=":NUM)"))

    # Query parameters in URLs
    config.masking_instructions.append(MaskingInstruction(pattern=r'\?[^"\'<>\s]*', mask_with="?PARAMS"))

    return TemplateMiner(config=config)

def main() -> None:

    template_miner = configure_template_miner()

    for processed_message in SAMPLE_TEXTS:
        # Apply custom pre-processing to the message
        # processed_message = preprocess_log_line(message) + ((":" + stack_hash) if stack_hash else "")

        # Add to template miner
        result = template_miner.add_log_message(processed_message)

        # Store the document ID with its template
        template_id = result["cluster_id"]
        logger.info(f"DEBUG processed_message: {processed_message} template_id: {template_id}")


if __name__ == "__main__":
    main()
