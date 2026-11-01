# tia-IndicatorReputationScorer
Assigns a reputation score to indicators based on multiple public threat intelligence feeds, weighting scores based on source reliability and consensus across different sources. - Focused on Collects and normalizes threat intelligence feeds from various open-source and commercial providers (e.g., VirusTotal, AlienVault OTX, Twitter). Allows for searching, filtering, and correlating indicators of compromise (IOCs) across multiple sources.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-indicatorreputationscorer`

Set the VirusTotal key in the environment as `VIRUSTOTAL_API_KEY`. The AlienVault OTX key is optional and is read from `ALIENVAULT_OTX_API_KEY`. Both keys are sent in request headers only.

## Usage
`python main.py <indicator>`

The score is a reputation: 1.0 is fully benign and 0.0 is fully malicious. Each source score is the complement of its risk signal, so an indicator flagged malicious by most engines gets a low reputation and a low reputation verdict. If no source produces a valid score, the run prints no score and exits non-zero. A malformed response from a source counts as a lookup failure for that source, not as a benign result.

The indicator type is detected (IP address, domain, or file hash) and each source is queried on its matching endpoint for that type. The indicator is also sent as a public Twitter search query, URL encoded, so do not score indicators that must stay private.

## Parameters
- `indicator` (required, positional): The indicator of compromise to check (IP address, domain, or hash).
- `-h`: Show help message and exit
- `-t`: Consensus threshold between 0 and 1 for the high reputation label.
- `-v`: Enable verbose logging.
- `-o`: Output file to save the results (JSON format).

## License
Copyright (c) ShadowGuard-AI
