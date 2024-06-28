# -*- coding: utf-8 -*-

from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from scrapy.http import FormRequest, Request
from scrapy.exceptions import IgnoreRequest, NotConfigured
from twisted.internet.error import DNSLookupError, TimeoutError, TCPTimedOutError, ConnectError
from scrapy.http.cookies import CookieJar
from urllib.parse import urlparse, parse_qsl, urljoin, unquote

from lxml.html import soupparser, fromstring
import lxml.etree
import lxml.html
import urllib
import re
import sys
import cgi
import requests
import string
import random

from xsscrapy.items import inj_resp
from xsscrapy.loginform import fill_login_form

try:
    from uro import find_patterns
except ImportError:
    pass


__author__ = 'Dan McInerney danhmcinerney@gmail.com'

class XSSspider(CrawlSpider):
    name = 'xsscrapy'
    handle_httpstatus_list = [x for x in range(0, 300)] + [x for x in range(400, 600)]  # Scrape 404 pages too
    rules = (Rule(LinkExtractor(), callback='parse_resp', follow=True),)

    def __init__(self, *args, **kwargs):
        super(XSSspider, self).__init__(*args, **kwargs)
        self.start_urls = [kwargs.get('url')]
        self.url = kwargs.get('url')  # Define self.url here
        hostname = urlparse(self.start_urls[0]).hostname

        # With subdomains
        self.allowed_domains = [hostname]
        self.delim = '1zqj'
        self.test_str = '\'"(){}<x>:/'

        # Login details
        self.login_user = kwargs.get('user')
        self.login_cookie_key = kwargs.get('cookie_key')
        self.login_cookie_value = kwargs.get('cookie_value')
        self.login_pass = kwargs.get('pw')

        # Handle None values from arguments
        if self.login_user == 'None':
            self.login_user = None
        if self.login_cookie_key == 'None':
            self.login_cookie_key = None
        if self.login_cookie_value == 'None':
            self.login_cookie_value = None
        if self.login_pass == 'None':
            self.login_pass = None 

        if self.login_user or (self.login_cookie_key and self.login_cookie_value):
            self.rules = (Rule(LinkExtractor(deny=('logout')), callback='parse_resp', follow=True),)

        if self.login_pass is None and self.login_user is not None:
            self.login_pass = input("Please enter the password: ")

        # HTTP Basic Auth
        self.basic_auth = kwargs.get('basic')
        if self.basic_auth == 'true':
            self.http_user = self.login_user
            self.http_pass = self.login_pass
        self.open_redirects_file = "open-redir.txt"
        self.redirected_urls = set() # Track source URLs that have caused redirects
        self.tested_params = set()  # Track unique (path, parameter) combinations

    def parse_start_url(self, response):
        ''' Creates the XSS tester requests for the start URL as well as the request for robots.txt '''
        parsed_url = urlparse(response.url)
        self.base_url = parsed_url.scheme + '://' + parsed_url.netloc
        robots_url = self.base_url + '/robots.txt'
        robot_req = Request(robots_url, callback=self.robot_parser)
        fourohfour_url = self.url + '/requestXaX404'  
        fourohfour_req = Request(fourohfour_url, callback=self.parse_resp)

        reqs = self.parse_resp(response)
        reqs.append(robot_req)
        reqs.append(fourohfour_req)
        return reqs
    
    def start_requests(self):
        """Generate the initial request to be sent."""
        for url in self.start_urls:
            yield Request(url, callback=self.parse_start_url)

    def login(self):
        """Generate the login request."""
        self.logger.info("Trying to log in.")
        if self.login_cookie_key and self.login_cookie_value:
            # Set cookies directly
            jar = CookieJar()
            jar.set_cookie(self.login_cookie_key, self.login_cookie_value, domain=urlparse(self.url).hostname)
            return [Request(self.url, cookies=jar)]
        else:
            # Fill in the login form
            return [FormRequest.from_response(
                response,
                formdata={self.login_user: self.login_pass},
                callback=self.confirm_login
            )]

    def confirm_login(self, response):
        """Check the response to confirm successful login."""
        if "logout" in response.body:
            self.logger.info("Successfully logged in.")
        else:
            self.logger.error("Failed to log in.")

    def robot_parser(self, response):
        """Parse the robots.txt file."""
        self.logger.info("Robots.txt content: %s" % response.body)
    
    def parse_resp(self, response):
        """The main response parsing function."""
        try:
            reqs = []
            orig_url = response.url
            body = response.body
            parsed_url = urlparse(orig_url)
            url_params = parse_qsl(parsed_url.query, keep_blank_values=True)
            doc = lxml.html.fromstring(body, base_url=orig_url)
            forms = doc.xpath('//form')
            payload = self.make_payload()

            # Check for 30x redirects
            if 300 <= response.status < 400:
                with open(self.open_redirects_file, 'a') as f:
                    f.write(response.url + '\n')
                self.logger.info(f"Found 30x redirect: {response.url}")

                # Add the source URL to the redirected_urls set
                self.redirected_urls.add(orig_url)
                # If the source URL has already been tested for XSS, skip further testing
                if orig_url in self.tested_params:
                    return  # Stop processing this response (redirect)
            elif orig_url in self.redirected_urls:
                # Skip the response if the original URL already caused a redirect
                return

            iframe_reqs = self.make_iframe_reqs(doc, orig_url)
            if iframe_reqs:
                reqs += iframe_reqs

            if forms:  # Corrected indentation
                form_reqs = self.make_form_reqs(orig_url, forms, payload)
                if form_reqs:
                    reqs += form_reqs

            payloaded_urls = self.make_URLs(orig_url, parsed_url, url_params)
            if payloaded_urls:
                try:
                    unique_urls = find_patterns(payloaded_urls)
                except NameError:  # uro is not installed
                    self.logger.warning("Uro not installed. Skipping URL decluttering.")
                    unique_urls = payloaded_urls
                filtered_urls = []
                for url, param, payload in unique_urls:
                    if (parsed_url.path, param) not in self.tested_params:
                        filtered_urls.append((url, param, payload))
                        self.tested_params.add((parsed_url.path, param))
                url_reqs = self.make_url_reqs(orig_url, filtered_urls)
                if url_reqs:
                    reqs += url_reqs

            # Add the original untampered response to each request for use by sqli_check()
            for r in reqs:
                r.meta['orig_body'] = body
            return reqs

        except (lxml.etree.ParserError, lxml.etree.XMLSyntaxError) as e:
            self.logger.error(f"Parsing Error: {e}")

        except (DNSLookupError, TimeoutError, TCPTimedOutError, ConnectError) as e:
            self.logger.error(f"Network Error: {e}")
            raise IgnoreRequest("Network Error") 

    def make_payload(self):
        """Generate a random payload for XSS testing."""
        return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))

    def make_iframe_reqs(self, doc, orig_url):
        """Create requests for iframe sources."""
        iframe_reqs = []
        iframes = doc.xpath('//iframe')
        for iframe in iframes:
            src = iframe.get('src')
            if src:
                iframe_url = urljoin(orig_url, src)
                iframe_reqs.append(Request(iframe_url, callback=self.parse_resp))
        return iframe_reqs

    def make_form_reqs(self, orig_url, forms, payload):
        """Create form submission requests with the XSS payload."""
        form_reqs = []
        for form in forms:
            form_action = form.get('action')
            form_method = form.get('method', 'GET').upper()
            form_data = {input_elem.get('name'): payload for input_elem in form.xpath('.//input[@name]')}
            if form_method == 'POST':
                form_reqs.append(FormRequest(urljoin(orig_url, form_action), formdata=form_data, callback=self.parse_resp))
            else:
                form_reqs.append(Request(urljoin(orig_url, form_action), method=form_method, callback=self.parse_resp, body=urllib.parse.urlencode(form_data)))
        return form_reqs

    def make_URLs(self, orig_url, parsed_url, url_params):
        """Generate URLs with XSS payloads."""
        payloaded_urls = []
        for param, value in url_params:
            payloaded_value = value + self.delim + self.make_payload() + self.delim
            payloaded_url = orig_url.replace(f"{param}={value}", f"{param}={payloaded_value}")
            payloaded_urls.append((payloaded_url, param, payloaded_value))
        return payloaded_urls

    def make_url_reqs(self, orig_url, filtered_urls):
        """Create requests for URLs with XSS payloads."""
        url_reqs = []
        for url, param, payload in filtered_urls:
            url_reqs.append(Request(url, callback=self.parse_resp))
        return url_reqs

    def sqli_check(self, request, response):
        """Check for SQL injection vulnerabilities."""
        pass
