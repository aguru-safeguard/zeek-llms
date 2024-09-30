# LLM Traffic Monitor for Zeek

## Overview

This Zeek script monitors network traffic for connections to known Large Language Model (LLM) providers. It logs detected LLM-related traffic, categorizing it based on predefined lists of providers, and applies basic allow/block logic using whitelists and blacklists.

For more information about our products, visit our website [aguru.com](https://aguru.com).

## Features

- Detects traffic to a wide range of LLM providers (e.g., OpenAI, Google AI, Anthropic, etc.)
- Logs detailed information about detected LLM traffic
- Supports whitelisting and blacklisting of specific providers
- Monitors both SSL and DNS traffic for LLM-related connections

## Requirements

- Zeek 3.0 or later
- Base protocols: SSL and DNS

## Installation

1. Copy the `llm_traffic_monitor.zeek` script to your Zeek scripts directory.
2. Add the following line to your `local.zeek` file:

   ```zeek
   @load path/to/llm_traffic_monitor.zeek
   ```

## Configuration

The script provides several configurable sets that can be modified:

- `llm_providers`: A set of known LLM provider domains
- `whitelist`: A set of allowed LLM provider domains
- `blacklist`: A set of blocked LLM provider domains

You can modify these sets by redefining them in your `local.zeek` file:
