import requests, re, urllib.parse as urlparse
from bs4 import BeautifulSoup
import time
import argparse

import xss_payloads
from sqli import sqli_payloads


class Charlotte:
    def __init__(self, url):
        self.url = url
        self.session = requests.session()

    def discover(self, path_to_dict):
        print("INITIATING DISCOVERY FOR URL: " + self.url)
        with open(path_to_dict, 'r') as dictionary:
            for line in dictionary:
                response = self.session.head(self.url + line)
                if response.status_code == 200:
                    print("FOUND DIRECTORY: " + self.url + line)

    def extract_forms(self, url):
        response = self.session.get(url)
        parsed_html = BeautifulSoup(response.content, features='lxml')
        return parsed_html.findAll('form')

    def submit_forms(self, form, value, url):
        action = form.get("action")
        post_url = urlparse.urljoin(url, action)
        method = form.get("method")

        inputs_list = form.findAll("input")
        post_data = {}
        for input in inputs_list:
            input_name = input.get("name")
            input_value = input.get("value")
            if input_value == 'text':
                input_value = value
            post_data[input_name] = input_value
        if method == "post":
            return requests.post(post_url, data=post_data)
        return self.session.get(post_url, params=post_data)

    def extract_same_site_urls(self, page_url):
        response = self.session.get(page_url)

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            base_domain = self.url

            pattern = re.compile(r'^https?://' + re.escape(base_domain) + r'/\S*$')

            all_links = soup.find_all('a', href=True)

            same_site_urls = [urlparse.urljoin(page_url, link['href']) for link in all_links if
                              pattern.match(urlparse.urljoin(page_url, link['href']))]

            return same_site_urls

        else:
            print(f"Failed to retrieve page: {page_url}")
            return []

    def xss_in_form(self, path_to_payloads=None):
        urls = self.extract_same_site_urls(self.url)
        for url in urls:
            forms = self.extract_forms(url)
            if path_to_payloads:
                with open(path_to_payloads, 'r') as payloads_content:
                    for form in forms:
                        for payload in payloads_content:
                            alert_pattern = re.compile(r'alert\(([^)]+)\)')
                            response = self.submit_forms(form, payload, url)
                            matches = alert_pattern.findall(response.text)
                            if matches:
                                print("XSS SUCCESSFUL FOR PAYLOAD: " + payload)
            else:
                for form in forms:
                    for payload in xss_payloads.payloads:
                        alert_pattern = re.compile(r'alert\(([^)]+)\)')
                        response = self.submit_forms(form, payload, url)
                        matches = alert_pattern.findall(response.text)
                        if matches:
                            print("XSS SUCCESSFUL FOR PAYLOAD: " + payload)

    def time_based_sqli(self):
        urls = self.extract_same_site_urls(self.url)
        for url in urls:
            forms = self.extract_forms(url)
            for form in forms:
                for payloads in sqli_payloads:
                    # Timing the request with the payload with a true condition
                    start_time_true = time.time()
                    response_true = self.submit_forms(form, payloads[0], url)
                    end_time_true = time.time()

                    # Timing the request with the payload with a false condition
                    start_time_false = time.time()
                    response_false = self.submit_forms(form, payloads[1], url)
                    end_time_false = time.time()

                    # Timing the request with the payload with a generic payload
                    start_time_generic = time.time()
                    response_generic = self.submit_forms(form, payloads[3], url)
                    end_time_generic = time.time()

                    time_delta_true = start_time_true - end_time_true
                    time_delta_false = start_time_false - end_time_false
                    time_delta_generic = start_time_generic - end_time_generic

                    # Compare lengths
                    if not time_delta_generic == time_delta_false == time_delta_true:
                        print("TIME BASED SQL INJECTION DISCOVERED IN URL: " + url)

    def xss_in_link(self, url, path_to_payloads=None):
            if path_to_payloads:
                with open(path_to_payloads, 'r') as payloads:
                    for payload in payloads:
                        modified_url = url.replace("=", "=" + payload)
                        response = self.session.get(modified_url)
                        if response.status_code == 200 and payload in response.text:
                            print("FOUND XSS IN URL: ", modified_url)

    def sqli(self):
        urls = self.extract_same_site_urls(self.url)
        for url in urls:
            forms = self.extract_forms(url)
            for form in forms:
                for payloads in sqli_payloads:
                    response_true = self.submit_forms(form, payloads[0], url)
                    response_false = self.submit_forms(form, payloads[1], url)
                    response_test = self.submit_forms(form, "test", url)

                    # Calculate response lengths
                    length_true = len(response_true.text)
                    length_false = len(response_false.text)
                    length_test = len(response_test)

                    # Compare lengths
                    if not length_false == length_true == length_test:
                        print("POSSIBLE SQL INJECTION DISCOVERED IN URL: " + url)

    def run_interactive_menu(self):
        while True:
            print("\n=== Hello! I am Charlotte, a friendly spider who knows the web. Please enter a number to allow "
                  "me to show you around! ===")
            print("1. Discover Directories")
            print("2. Extract Forms")
            print("3. XSS Testing in Forms")
            print("4. Time-Based SQL Injection Testing")
            print("5. XSS Testing in Links")
            print("6. SQL Injection Testing")
            print("7. Exit")

            choice = input("Enter your choice (1-7): ")

            if choice == '1':
                path_to_dict = input("Enter the path to the directory dictionary: ")
                self.discover(path_to_dict)
            elif choice == '2':
                url = input("Enter the URL to extract forms from: ")
                forms = self.extract_forms(url)
                print("Extracted Forms:")
                for form in forms:
                    print(form)
            elif choice == '3':
                path_to_payloads = input("Enter the path to XSS payloads (leave empty for default): ")
                self.xss_in_form(path_to_payloads)
            elif choice == '4':
                self.time_based_sqli()
            elif choice == '5':
                url = input("Enter the URL to test for XSS in links: ")
                path_to_payloads = input("Enter the path to XSS payloads (leave empty for default): ")
                self.xss_in_link(url, path_to_payloads)
            elif choice == '6':
                self.sqli()
            elif choice == '7':
                print("Exiting Charlotte. Goodbye!")
                break
            else:
                print("Invalid choice. Please enter a number between 1 and 7.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Interactive Security Testing with Charlotte")
    parser.add_argument("url", help="URL to test")

    args = parser.parse_args()

    Charlotte = Charlotte(args.url)
    Charlotte.run_interactive_menu()
