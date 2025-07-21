# -*- coding: utf-8 -*-
"""
Recursive Request Exploit (RRE) — Burp Extension
------------------------------------------------

Author: Farzan Karimi (@jumpycastle)
Talk:   "Paywall Optional: Stream for Free with a New Technique — RRE"
Event:  DEFCON 2025

Description:
    This Burp extension implements a recursive tracing technique to identify
    logic flaws across chained asynchronous APIs. It highlights cases where
    unauthenticated or loosely validated APIs can leak references to higher-privilege
    digital assets (like video streams, entitlements, or restricted data).

License:
    MIT
"""
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
import json
import traceback
import re
import math

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Recursive Request Exploit")
        callbacks.registerContextMenuFactory(self)
        # print("[DEBUG] Recursive Request Exploit Plugin loaded successfully.")

    def createMenuItems(self, invocation):
        return [
            JMenuItem("Trace Dependencies", actionPerformed=lambda x: self.trace_api(invocation)),
            JMenuItem("Full Chain Discovery", actionPerformed=lambda x: self.full_chain_discovery(invocation))
        ]

    def trace_api(self, invocation):
        try:
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages:
                # print("[DEBUG] No messages selected. Exiting trace.")
                return

            highlighted_value = self.extract_highlighted_value(invocation, selected_messages[0])
            if not highlighted_value:
                # print("[DEBUG] No highlighted value found. Exiting trace.")
                return

            # print("[DEBUG] Highlighted value: {}".format(highlighted_value))
            self.walkback_to_first_reference(highlighted_value)
        except Exception as e:
            # print("[DEBUG] Error in trace_api: {}".format(traceback.format_exc()))
            pass

    def full_chain_discovery(self, invocation):
        try:
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages:
                # print("[DEBUG] No messages selected. Exiting full chain.")
                return

            highlighted_value = self.extract_highlighted_value(invocation, selected_messages[0])
            if not highlighted_value:
                # print("[DEBUG] No highlighted value found. Exiting full chain.")
                return

            # print("[DEBUG] Starting full chain discovery from value: {}".format(highlighted_value))
            self.full_walkback_chain(highlighted_value)
        except Exception as e:
            # print("[DEBUG] Error in full_chain_discovery: {}".format(traceback.format_exc()))
            pass

    def extract_highlighted_value(self, invocation, selected_message):
        try:
            bounds = invocation.getSelectionBounds()
            if bounds and bounds[0] != bounds[1]:
                request = selected_message.getRequest()
                response = selected_message.getResponse()

                if request and bounds[0] < len(self._helpers.bytesToString(request)):
                    highlighted = self._helpers.bytesToString(request)[bounds[0]:bounds[1]]
                    # print("[DEBUG] Highlighted value extracted from request: {}".format(highlighted))
                    return highlighted.strip()

                elif response:
                    response_offset = bounds[0]
                    highlighted = self._helpers.bytesToString(response)[response_offset:response_offset + (bounds[1] - bounds[0])]
                    # print("[DEBUG] Highlighted value extracted from response: {}".format(highlighted))
                    return highlighted.strip()

            # print("[DEBUG] No valid highlight detected or empty selection.")
        except Exception as e:
            # print("[DEBUG] Error extracting highlighted value: {}".format(traceback.format_exc()))
            pass
        return None

    def walkback_to_first_reference(self, value):
        # print("[DEBUG] Starting walkback for value: {}".format(value))
        history = self._callbacks.getProxyHistory()
        # print("[DEBUG] Proxy history size: {}".format(len(history)))

        visited = set()

        def recursive_walk(current_value):
            if current_value in visited:
                # print("[DEBUG] Value '{}' already processed. Skipping.".format(current_value))
                return

            visited.add(current_value)

            for item in history:
                request = self._helpers.bytesToString(item.getRequest())
                response = self._helpers.bytesToString(item.getResponse())

                if not request or not response:
                    continue

                if current_value in response:
                    # print("[DEBUG] Found '{}' in response.".format(current_value))
                    top_line = request.splitlines()[0] if request else "[No Request Found]"
                    # print("[DEBUG] Associated request (top line): {}".format(top_line))

                    body = self.get_response_body(response)
                    # print("[DEBUG] Response body (truncated):\n{}".format(
                    #     body[:500].encode('ascii', 'ignore').decode('ascii') if body else "[No JSON Found]"
                    # ))

                    dependency = self.extract_dependency(response, current_value)
                    if dependency and isinstance(dependency, str):
                        # print("[DEBUG] Extracted dependency from response: {}".format(dependency))
                        recursive_walk(dependency)

                    return

            # print("[DEBUG] No further references found for value: {}".format(current_value))

        recursive_walk(value)

    def full_walkback_chain(self, value):
        history = self._callbacks.getProxyHistory()
        visited = set()

        def calculate_shannon_entropy(s):
            prob = [float(s.count(c)) / len(s) for c in set(s)]
            return -sum([p * math.log(p, 2) for p in prob])

        def recursive_chain(current_value, depth=0):
            indent = "    " * depth
            if current_value in visited:
                print(indent + "↺ Already visited: {}".format(current_value))
                return
            visited.add(current_value)

            for item in history:
                request = self._helpers.bytesToString(item.getRequest())
                response = self._helpers.bytesToString(item.getResponse())

                if not request or not response:
                    continue

                if current_value in response:
                    top_line = request.splitlines()[0] if request else "[No Request]"
                    print(indent + "→ Found in: {}".format(top_line))

                    matches = re.findall(r"/([a-zA-Z0-9]{10,})", top_line)
                    for match in matches:
                        entropy = calculate_shannon_entropy(match)
                        if entropy > 3.0 and match not in visited:
                            print(indent + "    ↑ High entropy match: {} (entropy: {:.2f})".format(match, entropy))
                            recursive_chain(match, depth + 1)

                    dependency = self.extract_dependency(response, current_value)
                    if dependency and isinstance(dependency, str):
                        if dependency not in visited:
                            print(indent + "    ↓ Dependency: {}".format(dependency))
                            recursive_chain(dependency, depth + 1)
                    return

            print(indent + "× No reference found for: {}".format(current_value))

        print("\n→ Starting Recursive Chain Discovery")
        print("Initial Target: {}\n".format(value))
        recursive_chain(value)

    def get_response_body(self, response):
        try:
            headers, body = response.split("\r\n\r\n", 1)
            if body.strip().startswith(("{", "[")):
                return body
            return None
        except ValueError:
            return None

    def extract_dependency(self, response, current_value):
        try:
            json_data = self.parse_json(response)
            if json_data:
                # print("[DEBUG] Parsing JSON response.")
                dependency = self.find_in_json(json_data, current_value)
                if dependency:
                    return dependency

            # print("[DEBUG] Searching response text for dependency.")
            return self.find_in_text(response, current_value)
        except Exception as e:
            # print("[DEBUG] Error extracting dependency: {}".format(traceback.format_exc()))
            return None

    def parse_json(self, response):
        try:
            headers, body = response.split("\r\n\r\n", 1)
            if not body.strip().startswith(("{", "[")):
                # print("[DEBUG] Response does not appear to be JSON. Skipping.")
                return None
            return json.loads(body)
        except ValueError:
            # print("[DEBUG] JSON parsing failed: {}".format(e))
            return None
        except Exception as e:
            # print("[DEBUG] Unexpected error during JSON parsing: {}".format(traceback.format_exc()))
            return None

    def find_in_json(self, json_data, current_value):
        def recursive_search(data):
            if isinstance(data, dict):
                for key, value in data.items():
                    if current_value in str(value):
                        return key if isinstance(value, str) else value
                    if isinstance(value, (dict, list)):
                        result = recursive_search(value)
                        if result:
                            return result
            elif isinstance(data, list):
                for item in data:
                    result = recursive_search(item)
                    if result:
                        return result
            return None

        return recursive_search(json_data)

    def find_in_text(self, response, current_value):
        try:
            lines = response.splitlines()
            for line in lines:
                if current_value in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith("key=") or part.startswith("id="):
                            return part.split("=")[-1].strip('"')
            return None
        except Exception as e:
            # print("[DEBUG] Error in find_in_text: {}".format(traceback.format_exc()))
            return None
