#!/usr/bin/env python3

import argparse
import ipaddress
import logging
import json
import re
import requests
from bs4 import BeautifulSoup
import os
import sys
from urllib.parse import quote, quote_plus

REQUEST_TIMEOUT = 15

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_THRESHOLD = 0.7  # Default consensus threshold
DEFAULT_WEIGHT = 1.0     # Default weight for sources

# Data structures (example - can be expanded)
SOURCE_WEIGHTS = {
    "VirusTotal": 0.8,
    "AlienVault OTX": 0.7,
    "Twitter": 0.5  # Be cautious with Twitter data
}

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Assigns a reputation score to indicators based on multiple public threat intelligence feeds.")
    parser.add_argument("indicator", help="The indicator of compromise (IOC) to check (e.g., IP address, domain, hash).")
    parser.add_argument("-t", "--threshold", type=float, default=DEFAULT_THRESHOLD,
                        help=f"Consensus threshold (default: {DEFAULT_THRESHOLD}).  A value between 0 and 1 representing the minimum agreement across sources required for a high reputation score.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-o", "--output", type=str, help="Output file to save the results (JSON format).")
    return parser.parse_args()


def detect_indicator_type(indicator):
    """Returns 'ip', 'hash', or 'domain' for the given indicator."""
    try:
        ipaddress.ip_address(indicator.strip())
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", indicator.strip()):
        return "hash"
    return "domain"


VT_ENDPOINTS = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
OTX_ENDPOINTS = {"ip": "ip", "domain": "domain", "hash": "file"}


def fetch_virustotal_reputation(indicator):
    """
    Fetches reputation data from VirusTotal for the given indicator.
    The score is a reputation: 1.0 is fully benign, 0.0 is fully
    malicious. It is the complement of the maliciousness ratio.
    """
    try:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")  # Get API key from environment variable
        if not api_key:
            raise ValueError("VirusTotal API key not found in environment variables.")

        indicator_type = detect_indicator_type(indicator)
        url = f"https://www.virustotal.com/api/v3/{VT_ENDPOINTS[indicator_type]}/{quote(indicator, safe='')}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if 'data' in data and 'attributes' in data['data'] and 'last_analysis_stats' in data['data']['attributes']:
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) #Number of engines/sources who have analyzed the indicator

            if total > 0: #prevent ZeroDivisionError
                malicious_ratio = (malicious + suspicious) / total
                reputation_score = 1.0 - malicious_ratio
            else:
                return {"source": "VirusTotal", "score": None, "error": "VirusTotal returned no analysis stats.", "raw_data": data}

            return {"source": "VirusTotal", "score": reputation_score, "raw_data": data} #Returning the raw data, for debugging
        else:
            logging.warning(f"Could not find reputational attributes for {indicator} in VirusTotal response. Treating the response as a lookup failure, not as a benign result.")
            return {"source": "VirusTotal", "score": None, "error": "Malformed VirusTotal response: no last_analysis_stats.", "raw_data": data}

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from VirusTotal: {e}")
        return {"source": "VirusTotal", "score": None, "error": str(e)}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response from VirusTotal: {e}")
        return {"source": "VirusTotal", "score": None, "error": str(e)}
    except ValueError as e:
        logging.error(f"Error: {e}")
        return {"source": "VirusTotal", "score": None, "error": str(e)}
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return {"source": "VirusTotal", "score": None, "error": str(e)}


def fetch_alienvault_otx_reputation(indicator):
    """
    Fetches reputation data from AlienVault OTX for the given indicator.
    The score is a reputation: more pulses naming the indicator means
    a lower score.
    """
    try:
        # Replace with actual AlienVault OTX API key and endpoint, if necessary
        #OTX does not require API key for basic pulls, but it is helpful for rate limiting and some advanced features.
        #API Key is optional and should be placed in environment variable if used.

        api_key = os.environ.get("ALIENVAULT_OTX_API_KEY")
        headers = {} #initialize headers
        if api_key:
             headers = {"X-OTX-API-KEY": api_key}

        indicator_type = detect_indicator_type(indicator)
        url = f"https://otx.alienvault.com/api/v1/indicator/{OTX_ENDPOINTS[indicator_type]}/{quote(indicator, safe='')}"

        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        data = response.json()
        if not isinstance(data, dict) or 'pulse_info' not in data:
            return {"source": "AlienVault OTX", "score": None, "error": "Malformed OTX response: no pulse_info.", "raw_data": data}
        # Reputation is the complement of the pulse based risk signal:
        # more pulses naming the indicator means lower reputation.
        pulse_count = data.get('pulse_info', {}).get('count', 0) #Get the count of pulses that have identified this indicator.
        reputation_score = 1.0 - min(pulse_count/100.0, 1.0) #Capping the risk signal at 1.0.

        return {"source": "AlienVault OTX", "score": reputation_score, "raw_data": data}

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from AlienVault OTX: {e}")
        return {"source": "AlienVault OTX", "score": None, "error": str(e)}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON response from AlienVault OTX: {e}")
        return {"source": "AlienVault OTX", "score": None, "error": str(e)}
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return {"source": "AlienVault OTX", "score": None, "error": str(e)}

def fetch_twitter_reputation(indicator):
    """
    Fetches reputation data from Twitter (using search) for the given indicator.
    Note: This is extremely unreliable and should be used with caution.
    It uses web scraping of the public search page. Use with caution due to rate limiting and potential HTML changes.
    """
    try:
        # Replace with actual Twitter API call and authentication if possible
        # Due to Twitter API changes, web scraping is used as a last resort (use with caution!)
        search_url = f"https://twitter.com/search?q={quote_plus(indicator)}&src=typed_query"
        response = requests.get(search_url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=REQUEST_TIMEOUT) #User-Agent to avoid blocking
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')
        # This is very basic and prone to breaking.  Improve if possible with API access.
        tweet_count = len(soup.find_all('div', class_='css-1dbjc4n r-1iusvr4 r-16y2uox r-1777f5m r-1xky4jy r-1mi0q7o r-1loqt21 r-o7ynqc r-6416eg r-1ny4l3l'))  #Attempt to extract tweet count
        #This will be very fragile!  Review output and adapt often!

        # More mentions are treated as a risk signal, so reputation is
        # the complement of the mention signal, capped for unreliability.
        reputation_score = 1.0 - min(tweet_count / 50.0, 0.6)

        return {"source": "Twitter", "score": reputation_score, "raw_data": f"Scraped HTML - count: {tweet_count}"}

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching data from Twitter: {e}")
        return {"source": "Twitter", "score": None, "error": str(e)}
    except Exception as e:
        logging.error(f"An unexpected error occurred while scraping Twitter: {e}")
        return {"source": "Twitter", "score": None, "error": str(e)}


def calculate_overall_reputation(source_reputations, threshold=DEFAULT_THRESHOLD):
    """
    Calculates the overall reputation score based on multiple sources,
    taking into account source reliability and consensus.
    """
    weighted_scores = []
    total_weight = 0

    for reputation in source_reputations:
        if reputation['score'] is not None:
            source = reputation['source']
            score = reputation['score']
            weight = SOURCE_WEIGHTS.get(source, DEFAULT_WEIGHT)  # Use default weight if source not in SOURCE_WEIGHTS

            weighted_scores.append(score * weight)
            total_weight += weight
        else:
            logging.warning(f"Skipping {reputation['source']} due to missing score.")

    if total_weight == 0:
        return None  # No valid scores: the lookup failed, there is no reputation to report.

    overall_score = sum(weighted_scores) / total_weight

    # Scores are reputation: high is benign, low is malicious.
    if overall_score > threshold:
        logging.info(f"Reputation score above threshold {threshold}. Considered high reputation.")
    else:
        logging.warning(f"Reputation score at or below threshold {threshold}. Considered low reputation: the indicator looks malicious and requires further investigation.")

    return overall_score


def main():
    """
    Main function to orchestrate the indicator reputation scoring.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    indicator = args.indicator

    # Input validation (basic)
    if not indicator:
        logging.error("Indicator cannot be empty.")
        sys.exit(1)

    logging.info(f"Checking reputation for indicator: {indicator}")

    # Fetch reputation from different sources
    source_reputations = [
        fetch_virustotal_reputation(indicator),
        fetch_alienvault_otx_reputation(indicator),
        fetch_twitter_reputation(indicator)
    ]

    # Calculate overall reputation
    overall_reputation = calculate_overall_reputation(source_reputations, args.threshold)

    if overall_reputation is None:
        logging.error("No source produced a valid score. The lookup failed, so no reputation score is reported.")
        results = {
            "indicator": indicator,
            "overall_reputation": None,
            "verdict": "lookup failed: no score",
            "source_reputations": source_reputations
        }
        print(json.dumps(results, indent=4))
        sys.exit(1)

    logging.info(f"Overall reputation score: {overall_reputation}")

    verdict = "high reputation" if overall_reputation > args.threshold else "low reputation: malicious"

    results = {
        "indicator": indicator,
        "overall_reputation": overall_reputation,
        "verdict": verdict,
        "source_reputations": source_reputations
    }


    # Output to console
    print(json.dumps(results, indent=4))

    # Output to file if specified
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
            logging.info(f"Results saved to {args.output}")
        except IOError as e:
            logging.error(f"Error writing to file {args.output}: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()


# Example Usage:
# 1.  Ensure API keys are set in environment variables (VIRUSTOTAL_API_KEY, ALIENVAULT_OTX_API_KEY - optional).
# 2.  Run the script:
#     python tia-IndicatorReputationScorer.py 8.8.8.8
#     python tia-IndicatorReputationScorer.py bad.domain.com -t 0.8 -o output.json
#     python tia-IndicatorReputationScorer.py 1234567890abcdef1234567890abcdef12345678 -v
#
# Offensive Tool Integration Notes:
# - This script can be integrated into offensive security tools to quickly assess the reputation of targets.
# - For example, during reconnaissance, you could use this script to check the reputation of identified IP addresses and domains.
# - Integrate the script output (JSON) into other offensive tools for automated decision-making.
# - Be mindful of API rate limits and usage policies of the threat intelligence providers.
# - Be extremely cautious using Twitter reputation data in automated decisioning due to its potential for inaccuracy and manipulation.